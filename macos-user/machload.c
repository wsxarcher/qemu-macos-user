/*
 *  Mach-O binary loader for macOS user mode
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user/guest-base.h"
#include "qemu/path.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define MACHO_MAGIC_32 0xfeedface
#define MACHO_MAGIC_64 0xfeedfacf
#define MACHO_MAGIC_FAT 0xcafebabe

/* Load a Mach-O image into memory */
static int load_macho_image(const char *filename, int fd,
                            struct image_info *info,
                            char **pinterp_name)
{
    struct mach_header_64 hdr;
    struct load_command *cmds = NULL;
    uint8_t *cmdptr;
    int i;
    abi_ulong load_addr = 0;
    abi_ulong load_bias = 0;
    int retval = -1;

    /* Read Mach-O header */
    if (read(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
        goto exit_read;
    }

    /* Check magic number */
    if (hdr.magic != MACHO_MAGIC_64) {
        fprintf(stderr, "Invalid Mach-O magic: 0x%x (expected 0x%x)\n",
                hdr.magic, MACHO_MAGIC_64);
        goto exit_read;
    }

    /* Verify it's an executable */
    if (hdr.filetype != MH_EXECUTE) {
        fprintf(stderr, "Not an executable Mach-O file (type %d)\n", hdr.filetype);
        goto exit_read;
    }

    /* Check CPU type - ARM64 only */
    if (hdr.cputype != CPU_TYPE_ARM64) {
        fprintf(stderr, "Unsupported CPU type: %d (expected ARM64)\n", hdr.cputype);
        goto exit_read;
    }

    /* Allocate space for load commands */
    cmds = g_malloc(hdr.sizeofcmds);
    if (read(fd, cmds, hdr.sizeofcmds) != hdr.sizeofcmds) {
        goto exit_read;
    }

    /* Process load commands */
    cmdptr = (uint8_t *)cmds;
    info->start_code = UINTPTR_MAX;
    info->end_code = 0;
    info->start_data = UINTPTR_MAX;
    info->end_data = 0;
    info->entry = 0;

    for (i = 0; i < hdr.ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmdptr;

        switch (lc->cmd) {
        case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                abi_ulong map_start = seg->vmaddr;
                abi_ulong map_end = seg->vmaddr + seg->vmsize;
                off_t file_offset = seg->fileoff;
                size_t file_size = seg->filesize;
                int prot = 0;

                if (seg->maxprot & VM_PROT_READ) prot |= PROT_READ;
                if (seg->maxprot & VM_PROT_WRITE) prot |= PROT_WRITE;
                if (seg->maxprot & VM_PROT_EXECUTE) prot |= PROT_EXEC;

                /* Skip __PAGEZERO segment */
                if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                    cmdptr += lc->cmdsize;
                    continue;
                }

                /* Map segment into memory */
                if (file_size > 0) {
                    abi_ulong map_page_start = TARGET_PAGE_ALIGN(map_start);
                    abi_ulong map_page_end = TARGET_PAGE_ALIGN(map_end);

                    void *mapped = mmap((void *)(uintptr_t)map_page_start,
                                       map_page_end - map_page_start,
                                       prot | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                       -1, 0);

                    if (mapped == MAP_FAILED) {
                        perror("mmap segment");
                        goto exit_read;
                    }

                    /* Read segment data from file */
                    if (pread(fd, (void *)(uintptr_t)map_start,
                             file_size, file_offset) != file_size) {
                        perror("pread segment");
                        goto exit_read;
                    }

                    /* Remove write permission if not needed */
                    if (!(prot & PROT_WRITE)) {
                        mprotect((void *)(uintptr_t)map_page_start,
                                map_page_end - map_page_start, prot);
                    }
                }

                /* Track code and data segments */
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    if (map_start < info->start_code) {
                        info->start_code = map_start;
                    }
                    if (map_end > info->end_code) {
                        info->end_code = map_end;
                    }
                }
                if (strcmp(seg->segname, "__DATA") == 0) {
                    if (map_start < info->start_data) {
                        info->start_data = map_start;
                    }
                    if (map_end > info->end_data) {
                        info->end_data = map_end;
                    }
                    /* Set brk to end of data segment */
                    info->brk = map_end;
                    info->start_brk = map_end;
                }
            }
            break;

        case LC_MAIN:
            {
                struct entry_point_command *ep = (struct entry_point_command *)lc;
                info->entry = ep->entryoff + load_addr;
            }
            break;

        case LC_LOAD_DYLINKER:
            /* Note: We're using host dyld as per requirements */
            break;

        case LC_UUID:
        case LC_SOURCE_VERSION:
        case LC_BUILD_VERSION:
        case LC_VERSION_MIN_MACOSX:
        case LC_VERSION_MIN_IPHONEOS:
        case LC_DYLD_INFO:
        case LC_DYLD_INFO_ONLY:
        case LC_SYMTAB:
        case LC_DYSYMTAB:
        case LC_LOAD_DYLIB:
        case LC_ID_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE:
        case LC_CODE_SIGNATURE:
        case LC_DYLD_EXPORTS_TRIE:
        case LC_DYLD_CHAINED_FIXUPS:
            /* Informational or handled by dyld - skip for now */
            break;

        default:
            qemu_log("Unhandled load command: 0x%x\n", lc->cmd);
            break;
        }

        cmdptr += lc->cmdsize;
    }

    if (info->entry == 0) {
        fprintf(stderr, "No entry point found in Mach-O\n");
        goto exit_read;
    }

    info->load_addr = load_addr;
    info->load_bias = load_bias;

    /* Set up initial mmap region after loaded segments */
    info->start_mmap = TARGET_PAGE_ALIGN(info->end_data + 0x10000000);

    retval = 0;

exit_read:
    g_free(cmds);
    return retval;
}

/* Main loader entry point */
int loader_exec(const char *filename, char **argv, char **envp,
                struct target_pt_regs *regs, struct image_info *info,
                char **memp)
{
    int fd, retval;
    char *interp_name = NULL;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }

    retval = load_macho_image(filename, fd, info, &interp_name);
    close(fd);

    if (retval < 0) {
        return retval;
    }

    /* Set up initial registers for ARM64 */
    memset(regs, 0, sizeof(*regs));
    regs->pc = info->entry;
    regs->sp = TARGET_PAGE_ALIGN(0x7ffffffff000ULL); /* Initial stack */

    return 0;
}

/* Get hardware capabilities for auxv */
uint32_t get_elf_hwcap(void)
{
    /* Return ARM64 capabilities */
    return 0; /* TODO: populate with actual CPU features */
}
