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
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "exec/mmap-lock.h"
#include "qemu/path.h"
#include <mach-o/loader.h>
#include <mach-o/fat.h>

#define MACHO_MAGIC_32 0xfeedface
#define MACHO_MAGIC_64 0xfeedfacf
#define MACHO_MAGIC_FAT 0xcafebabe

/*
 * Find the arm64 slice inside a fat/universal Mach-O binary.
 * Fat headers are big-endian.  Returns the file offset on success, -1 on
 * failure.
 */
static off_t find_fat_arm64_offset(int fd)
{
    struct fat_header fh;
    uint32_t narch, i;

    if (pread(fd, &fh, sizeof(fh), 0) != sizeof(fh)) {
        return -1;
    }

    narch = be32_to_cpu(fh.nfat_arch);
    for (i = 0; i < narch; i++) {
        struct fat_arch fa;
        if (pread(fd, &fa, sizeof(fa),
                  sizeof(fh) + i * sizeof(fa)) != sizeof(fa)) {
            return -1;
        }
        cpu_type_t cputype = (cpu_type_t)be32_to_cpu(fa.cputype);
        if (cputype == CPU_TYPE_ARM64) {
            return (off_t)be32_to_cpu(fa.offset);
        }
    }
    return -1;
}

/* Load a Mach-O image into memory */
static int load_macho_image(const char *filename, int fd,
                            struct image_info *info,
                            char **pinterp_name)
{
    struct mach_header_64 hdr;
    struct load_command *cmds = NULL;
    uint8_t *cmdptr;
    int i;
    abi_ulong load_bias = 0;
    int retval = -1;
    off_t base_offset = 0;  /* offset of the thin Mach-O inside the file */

    /* Peek at magic to detect fat binaries */
    uint32_t magic;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        goto exit_read;
    }
    if (magic == FAT_CIGAM || magic == FAT_MAGIC) {
        /* Universal binary – locate the arm64 slice */
        base_offset = find_fat_arm64_offset(fd);
        if (base_offset < 0) {
            fprintf(stderr, "No arm64 slice found in universal binary %s\n",
                    filename);
            goto exit_read;
        }
    }

    /* Read the (possibly embedded) Mach-O 64-bit header */
    if (pread(fd, &hdr, sizeof(hdr), base_offset) != sizeof(hdr)) {
        goto exit_read;
    }

    /* Check magic number */
    if (hdr.magic != MACHO_MAGIC_64) {
        fprintf(stderr, "Invalid Mach-O magic: 0x%x (expected 0x%x)\n",
                hdr.magic, MACHO_MAGIC_64);
        goto exit_read;
    }

    /* Verify it's an executable or dynamic linker */
    if (hdr.filetype != MH_EXECUTE && hdr.filetype != MH_DYLINKER) {
        fprintf(stderr, "Not an executable Mach-O file (type %d)\n",
                hdr.filetype);
        goto exit_read;
    }

    /* Check CPU type - ARM64 only */
    if (hdr.cputype != CPU_TYPE_ARM64) {
        fprintf(stderr, "Unsupported CPU type: %d (expected ARM64)\n",
                hdr.cputype);
        goto exit_read;
    }

    /* Allocate space for load commands */
    cmds = g_malloc(hdr.sizeofcmds);
    if (pread(fd, cmds, hdr.sizeofcmds,
              base_offset + sizeof(hdr)) != hdr.sizeofcmds) {
        goto exit_read;
    }

    /*
     * Pass 1: find the loadable address range (lowest vmaddr to highest
     * vmaddr+vmsize), skipping __PAGEZERO.
     */
    abi_ulong lo = UINTPTR_MAX, hi = 0;

    cmdptr = (uint8_t *)cmds;
    for (i = 0; i < hdr.ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmdptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
                (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__PAGEZERO") != 0 &&
                seg->vmsize > 0) {
                if (seg->vmaddr < lo) {
                    lo = seg->vmaddr;
                }
                if (seg->vmaddr + seg->vmsize > hi) {
                    hi = seg->vmaddr + seg->vmsize;
                }
            }
        }
        cmdptr += lc->cmdsize;
    }

    if (lo >= hi) {
        fprintf(stderr, "No loadable segments in %s\n", filename);
        goto exit_read;
    }

    abi_ulong total_size = hi - lo;

    /*
     * Map the binary into the guest address space.
     *
     * When guest_base is set, we map at the binary's preferred addresses
     * (offset by guest_base).  guest_base is set up by main() before
     * loader_exec is called, so g2h_untagged() will translate correctly.
     *
     * When guest_base is 0 (static binaries), let the kernel choose to
     * avoid collisions with the host QEMU binary.
     */
    void *base;
    if (guest_base != 0) {
        /* Map at the original vmaddr, translated to host via guest_base */
        base = mmap(g2h_untagged(lo), total_size,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                    -1, 0);
    } else {
        base = mmap(NULL, total_size,
                    PROT_NONE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);
    }
    if (base == MAP_FAILED) {
        perror("mmap reserve");
        goto exit_read;
    }

    load_bias = (abi_ulong)(uintptr_t)base - lo;

    /*
     * Pass 2: map each segment at its biased address.
     * seg_start/seg_end are HOST addresses (for mmap/pread/mprotect).
     * We convert to guest addresses for page_set_flags and info fields.
     */
    info->start_code = UINTPTR_MAX;
    info->end_code = 0;
    info->start_data = UINTPTR_MAX;
    info->end_data = 0;
    info->entry = 0;

    cmdptr = (uint8_t *)cmds;
    for (i = 0; i < hdr.ncmds; i++) {
        struct load_command *lc = (struct load_command *)cmdptr;

        switch (lc->cmd) {
        case LC_SEGMENT_64:
            {
                struct segment_command_64 *seg =
                    (struct segment_command_64 *)lc;
                abi_ulong seg_start = seg->vmaddr + load_bias;
                abi_ulong seg_end = seg_start + seg->vmsize;
                abi_ulong guest_start = h2g(seg_start);
                abi_ulong guest_end = h2g(seg_end);
                off_t file_offset = seg->fileoff;
                size_t file_size = seg->filesize;
                int prot = 0;

                if (seg->maxprot & VM_PROT_READ)    prot |= PROT_READ;
                if (seg->maxprot & VM_PROT_WRITE)   prot |= PROT_WRITE;
                if (seg->maxprot & VM_PROT_EXECUTE)  prot |= PROT_EXEC;

                if (strcmp(seg->segname, "__PAGEZERO") == 0) {
                    cmdptr += lc->cmdsize;
                    continue;
                }

                if (file_size > 0) {
                    /*
                     * Map as RW; on Apple Silicon RWX requires JIT
                     * entitlements.  We write data then mprotect.
                     */
                    void *mapped = mmap(
                        (void *)(uintptr_t)seg_start,
                        seg_end - seg_start,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);

                    if (mapped == MAP_FAILED) {
                        perror("mmap segment");
                        goto exit_read;
                    }

                    if (pread(fd, (void *)(uintptr_t)seg_start,
                              file_size,
                              base_offset + file_offset) != (ssize_t)file_size) {
                        perror("pread segment");
                        goto exit_read;
                    }

                    if (prot != (PROT_READ | PROT_WRITE)) {
                        mprotect((void *)(uintptr_t)seg_start,
                                 seg_end - seg_start, prot);
                    }
                } else if (seg->vmsize > 0) {
                    /*
                     * Zero-fill segment (BSS / __DATA with filesize=0).
                     * Must still be mapped so the guest can access it.
                     */
                    void *mapped = mmap(
                        (void *)(uintptr_t)seg_start,
                        seg_end - seg_start,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                        -1, 0);

                    if (mapped == MAP_FAILED) {
                        perror("mmap zerofill segment");
                        goto exit_read;
                    }

                    if (prot != (PROT_READ | PROT_WRITE)) {
                        mprotect((void *)(uintptr_t)seg_start,
                                 seg_end - seg_start, prot);
                    }
                }

                if (seg->vmsize > 0) {
                    /*
                     * Register the mapping with QEMU's software page
                     * table so TCG can translate/access guest code+data.
                     */
                    int qemu_flags = PAGE_VALID;
                    if (prot & PROT_READ)  qemu_flags |= PAGE_READ;
                    if (prot & PROT_WRITE) qemu_flags |= PAGE_WRITE;
                    if (prot & PROT_EXEC)  qemu_flags |= PAGE_EXEC;
                    mmap_lock();
                    page_set_flags(guest_start, guest_end - 1,
                                   qemu_flags, ~0);
                    mmap_unlock();
                }

                /* Track code and data segments (guest addresses) */
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    if (guest_start < info->start_code) {
                        info->start_code = guest_start;
                    }
                    if (guest_end > info->end_code) {
                        info->end_code = guest_end;
                    }
                }
                if (strncmp(seg->segname, "__DATA", 6) == 0) {
                    if (guest_start < info->start_data) {
                        info->start_data = guest_start;
                    }
                    if (guest_end > info->end_data) {
                        info->end_data = guest_end;
                    }
                    info->brk = guest_end;
                    info->start_brk = guest_end;
                }
            }
            break;

        case LC_MAIN:
            {
                struct entry_point_command *ep =
                    (struct entry_point_command *)lc;
                /*
                 * entryoff is relative to __TEXT; start_code is
                 * already a guest address.
                 */
                info->entry = info->start_code + ep->entryoff;
            }
            break;

        case LC_UNIXTHREAD:
            {
                /*
                 * thread_command: cmd, cmdsize, flavor, count, then
                 * ARM_THREAD_STATE64: x[29], fp, lr, sp, pc, cpsr
                 * All values are uint64_t except cpsr (uint32_t+pad).
                 * We only need the pc field to get the entry point.
                 */
                uint32_t *tcdata = (uint32_t *)lc;
                /* Skip cmd(1) + cmdsize(1) + flavor(1) + count(1) = 4 words */
                uint64_t *regs64 = (uint64_t *)&tcdata[4];
                /* pc is at index 32: x[29] + fp + lr + sp + pc */
                uint64_t thread_pc = regs64[32];
                /*
                 * thread_pc is an absolute vmaddr from the Mach-O.
                 * Convert to guest address via load_bias + h2g.
                 */
                info->entry = h2g(thread_pc + load_bias);
            }
            break;

        case LC_LOAD_DYLINKER:
            {
                struct dylinker_command *dc =
                    (struct dylinker_command *)lc;
                if (pinterp_name && !*pinterp_name) {
                    *pinterp_name = g_strdup(
                        (char *)lc + dc->name.offset);
                }
            }
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
        case LC_ID_DYLINKER:
        case LC_LOAD_WEAK_DYLIB:
        case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE:
        case LC_CODE_SIGNATURE:
        case LC_DYLD_EXPORTS_TRIE:
        case LC_DYLD_CHAINED_FIXUPS:
        case LC_SEGMENT_SPLIT_INFO:
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

    info->load_addr = h2g((abi_ulong)(uintptr_t)base);
    info->load_bias = load_bias;

    /* Set up initial mmap region after loaded segments (guest addr) */
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
        g_free(interp_name);
        return retval;
    }

    /* Record the main binary's mach_header guest address */
    info->mach_header_addr = info->start_code;

    /*
     * If the binary has LC_LOAD_DYLINKER (dynamically linked),
     * load dyld into the guest address space and use its entry point.
     */
    if (interp_name) {
        struct image_info dyld_info = {0};

        fd = open(interp_name, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "Cannot open dynamic linker %s: %s\n",
                    interp_name, strerror(errno));
            g_free(interp_name);
            return -errno;
        }

        retval = load_macho_image(interp_name, fd, &dyld_info, NULL);
        close(fd);
        g_free(interp_name);

        if (retval < 0) {
            fprintf(stderr, "Failed to load dynamic linker\n");
            return retval;
        }

        /* Use dyld's entry point; store main binary's entry separately */
        info->interp_entry = dyld_info.entry;

        /* Extend mmap region past dyld's loaded segments */
        if (dyld_info.end_data > info->end_data) {
            info->start_mmap = TARGET_PAGE_ALIGN(
                dyld_info.end_data + 0x10000000);
        }
    } else {
        info->interp_entry = 0;
    }

    /* Set up initial registers for ARM64 */
    memset(regs, 0, sizeof(*regs));
    /*
     * For dynamic binaries, start at dyld's entry.
     * For static binaries, start at the binary's own entry.
     */
    regs->pc = info->interp_entry ? info->interp_entry : info->entry;
    /* sp will be set up properly by main.c after stack allocation */
    regs->sp = 0;

    return 0;
}

/* Get hardware capabilities for auxv */
uint32_t get_elf_hwcap(void)
{
    /* Return ARM64 capabilities */
    return 0; /* TODO: populate with actual CPU features */
}
