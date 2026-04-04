/*
 *  macOS system call implementation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include <sys/random.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include "qemu.h"
#include "user/guest-host.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"
#include "exec/mmap-lock.h"
#include "user/page-protection.h"

/* csops is a private syscall, declare it here */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

/*
 * On macOS with Cryptex volumes (macOS 13+), /System/Library/dyld/ does
 * not exist on the root volume.  The shared cache files live under the
 * Cryptex prefix.  dyld hardcodes the traditional path, so we redirect
 * file-system accesses to the actual location.
 */
#define CRYPTEX_PREFIX "/System/Volumes/Preboot/Cryptexes/OS"
#define DYLD_CACHE_DIR "/System/Library/dyld"

static const char *redirect_path(const char *path, char *buf, size_t bufsz)
{
    if (strncmp(path, DYLD_CACHE_DIR, strlen(DYLD_CACHE_DIR)) == 0) {
        snprintf(buf, bufsz, "%s%s", CRYPTEX_PREFIX, path);
        struct stat st;
        if (stat(buf, &st) == 0) {
            return buf;
        }
    }
    return path;
}

/*
 * PAC signing helpers — declared in target/arm/tcg/pauth_helper.c.
 * We use these to PAC-sign shared-cache pointers during fixup
 * processing so that the guest's autda/autia instructions can
 * successfully authenticate them at runtime.
 */
uint64_t helper_pacia(CPUARMState *env, uint64_t x, uint64_t y);
uint64_t helper_pacda(CPUARMState *env, uint64_t x, uint64_t y);

/*
 * Process ARM64e chained fixups (slide info v5) for a shared cache
 * mapping.  This replicates what XNU's vm_shared_region_slide_page_v5()
 * does: walk the fixup chains page by page, rebase every pointer by
 * (value_add + slide), and PAC-sign authenticated pointers using the
 * guest CPU's keys.
 *
 * @env:         guest CPU state (carries PAC keys)
 * @slide_buf:   slide info data read from the cache file
 * @slide_len:   length of slide_buf in bytes
 * @mapped_host: host pointer to the mapped region
 * @guest_addr:  guest base address of the mapped region
 * @region_size: size of the mapped region
 * @slide:       ASLR slide amount (0 for private caches)
 */
static void apply_slide_info_v5(CPUARMState *env,
                                const uint8_t *slide_buf,
                                uint64_t slide_len,
                                void *mapped_host,
                                uint64_t guest_addr,
                                uint64_t region_size,
                                uint32_t slide)
{
    /* dyld_cache_slide_info5 header (20 bytes) */
    if (slide_len < 20) {
        return;
    }
    uint32_t version, page_size, page_starts_count;
    uint64_t value_add;
    memcpy(&version, slide_buf, 4);
    memcpy(&page_size, slide_buf + 4, 4);
    memcpy(&page_starts_count, slide_buf + 8, 4);
    /* 4 bytes padding at offset 12 */
    memcpy(&value_add, slide_buf + 16, 8);

    if (version != 5 || page_size == 0 || page_starts_count == 0) {
        if (do_strace) {
            fprintf(stderr, "qemu: slide info version %u (expected 5), skipping\n",
                    version);
        }
        return;
    }

    /* page_starts array follows the header (uint16_t each) */
    const uint16_t *page_starts =
        (const uint16_t *)(slide_buf + 24);
    uint64_t needed = 24 + (uint64_t)page_starts_count * 2;
    if (needed > slide_len) {
        return;
    }

    for (uint32_t pi = 0; pi < page_starts_count; pi++) {
        uint16_t start = page_starts[pi];
        if (start == 0xFFFF) {
            continue; /* DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE */
        }

        uint64_t page_off = (uint64_t)pi * page_size;
        if (page_off + start >= region_size) {
            break;
        }

        uint8_t *loc = (uint8_t *)mapped_host + page_off;
        uint64_t delta = start;

        do {
            loc += delta;
            uint64_t raw;
            memcpy(&raw, loc, 8);

            /* Extract chain-next delta (bits 62:52, in 8-byte units) */
            delta = ((raw & 0x7FF0000000000000ULL) >> 52) * 8;

            bool is_auth = (raw & (1ULL << 63)) != 0;
            uint64_t runtime_offset = raw & 0x3FFFFFFFFULL;
            uint64_t target = runtime_offset + value_add + slide;

            if (is_auth) {
                uint16_t diversity = (uint16_t)((raw >> 34) & 0xFFFF);
                bool addr_div = (raw & (1ULL << 50)) != 0;
                bool key_is_data = (raw & (1ULL << 51)) != 0;

                uint64_t modifier;
                if (addr_div) {
                    uint64_t slot_addr = guest_addr +
                        (uint64_t)((uint8_t *)loc - (uint8_t *)mapped_host);
                    modifier = ((uint64_t)diversity << 48) |
                               (slot_addr & 0x0000FFFFFFFFFFFFULL);
                } else {
                    modifier = (uint64_t)diversity;
                }

                if (key_is_data) {
                    target = helper_pacda(env, target, modifier);
                } else {
                    target = helper_pacia(env, target, modifier);
                }
            } else {
                /* Non-auth rebase: add high8 bits */
                uint64_t high8 = (raw << 22) & 0xFF00000000000000ULL;
                target |= high8;
            }

            memcpy(loc, &target, 8);
        } while (delta != 0);
    }
}

/* Syscall implementation */

/* Guest address of the mapped shared cache (0 = not yet mapped) */
static uint64_t guest_shared_cache_addr;

abi_long do_macos_syscall(void *cpu_env, int num, abi_long arg1,
                          abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7,
                          abi_long arg8)
{
    CPUState *cpu = env_cpu(cpu_env);
    abi_long ret;

    if (do_strace) {
        print_syscall(cpu, num, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    switch (num) {
    case TARGET_MACOS_NR_exit:
        /* exit(int status) */
        gdb_exit(arg1);
        _exit(arg1);
        ret = 0; /* not reached */
        break;

    case TARGET_MACOS_NR_read:
        /* read(int fd, void *buf, size_t count) */
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_read(arg1, p, arg3));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_write:
        /* write(int fd, const void *buf, size_t count) */
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_write(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_open:
        /* open(const char *path, int flags, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                ret = get_errno(safe_open(rp, target_to_host_bitmask(arg2, fcntl_flags_tbl),
                                          arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_close:
        /* close(int fd) */
        ret = get_errno(close(arg1));
        break;

    case TARGET_MACOS_NR_getpid:
        ret = get_errno(getpid());
        break;

    case TARGET_MACOS_NR_getuid:
        ret = get_errno(getuid());
        break;

    case TARGET_MACOS_NR_geteuid:
        ret = get_errno(geteuid());
        break;

    case TARGET_MACOS_NR_getgid:
        ret = get_errno(getgid());
        break;

    case TARGET_MACOS_NR_getegid:
        ret = get_errno(getegid());
        break;

    case TARGET_MACOS_NR_getppid:
        ret = get_errno(getppid());
        break;

    case TARGET_MACOS_NR_dup:
        /* dup(int fd) */
        ret = get_errno(dup(arg1));
        break;

    case TARGET_MACOS_NR_dup2:
        /* dup2(int oldfd, int newfd) */
        ret = get_errno(dup2(arg1, arg2));
        break;

    case TARGET_MACOS_NR_fcntl:
        /* fcntl(int fd, int cmd, ...) */
        ret = do_bsd_fcntl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_ioctl:
        /* ioctl(int fd, unsigned long request, ...) */
        ret = do_bsd_ioctl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_lseek:
        /* lseek(int fd, off_t offset, int whence) */
        ret = get_errno(lseek(arg1, arg2, arg3));
        break;

    case TARGET_MACOS_NR_mmap:
        /* mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) */
        ret = target_mmap(arg1, arg2, arg3,
                         target_to_host_bitmask(arg4, mmap_flags_tbl),
                         arg5, arg6);
        break;

    case TARGET_MACOS_NR_munmap:
        /* munmap(void *addr, size_t len) */
        ret = target_munmap(arg1, arg2);
        break;

    case TARGET_MACOS_NR_mprotect:
        /* mprotect(void *addr, size_t len, int prot) */
        ret = target_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_msync:
        /* msync(void *addr, size_t len, int flags) */
        ret = target_msync(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_access:
        /* access(const char *path, int mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(access(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_chdir:
        /* chdir(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chdir(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchdir:
        /* fchdir(int fd) */
        ret = get_errno(fchdir(arg1));
        break;

    case TARGET_MACOS_NR_chmod:
        /* chmod(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chmod(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchmod:
        /* fchmod(int fd, mode_t mode) */
        ret = get_errno(fchmod(arg1, arg2));
        break;

    case TARGET_MACOS_NR_chown:
        /* chown(const char *path, uid_t owner, gid_t group) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chown(p, arg2, arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchown:
        /* fchown(int fd, uid_t owner, gid_t group) */
        ret = get_errno(fchown(arg1, arg2, arg3));
        break;

    case TARGET_MACOS_NR_gettimeofday:
        /* gettimeofday(struct timeval *tv, struct timezone *tz) */
        {
            struct timeval tv;
            ret = get_errno(gettimeofday(&tv, NULL));
            if (!is_error(ret)) {
                if (arg1 && copy_to_user_timeval(arg1, &tv)) {
                    ret = -TARGET_EFAULT;
                }
            }
        }
        break;

    case TARGET_MACOS_NR_readlink:
        /* readlink(const char *path, char *buf, size_t bufsiz) */
        {
            void *p = lock_user_string(arg1);
            void *p2 = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(readlink(p, p2, arg3));
            }
            unlock_user(p2, arg2, ret);
            unlock_user(p, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_symlink:
        /* symlink(const char *target, const char *linkpath) */
        {
            void *p = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(symlink(p, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_unlink:
        /* unlink(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(unlink(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_mkdir:
        /* mkdir(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkdir(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_rmdir:
        /* rmdir(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(rmdir(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_stat:
    case TARGET_MACOS_NR_stat64:
        /* stat(const char *path, struct stat *buf) */
        {
            struct stat st;
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                ret = get_errno(stat(rp, &st));
                unlock_user(p, arg1, 0);
                if (!is_error(ret)) {
                    if (arg2 && host_to_target_stat(arg2, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_fstat:
    case TARGET_MACOS_NR_fstat64:
        /* fstat(int fd, struct stat *buf) */
        {
            struct stat st;
            ret = get_errno(fstat(arg1, &st));
            if (!is_error(ret)) {
                if (arg2 && host_to_target_stat(arg2, &st)) {
                    ret = -TARGET_EFAULT;
                }
            }
        }
        break;

    case TARGET_MACOS_NR_lstat:
    case TARGET_MACOS_NR_lstat64:
        /* lstat(const char *path, struct stat *buf) */
        {
            struct stat st;
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(lstat(p, &st));
                unlock_user(p, arg1, 0);
                if (!is_error(ret)) {
                    if (arg2 && host_to_target_stat(arg2, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_link:
        /* link(const char *path, const char *link) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(link(p1, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_pipe:
        /* pipe() -> returns fd[0] in X0, fd[1] in X1 */
        {
            int pipefd[2];
            ret = get_errno(pipe(pipefd));
            if (!is_error(ret)) {
                CPUARMState *arm_env = (CPUARMState *)cpu_env;
                arm_env->xregs[0] = pipefd[0];
                arm_env->xregs[1] = pipefd[1];
                ret = 0;
            }
        }
        break;

    case TARGET_MACOS_NR_umask:
        /* umask(int newmask) */
        ret = get_errno(umask(arg1));
        break;

    case TARGET_MACOS_NR_rename:
        /* rename(const char *from, const char *to) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(rename(p1, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_flock:
        /* flock(int fd, int how) */
        ret = get_errno(flock(arg1, arg2));
        break;

    case TARGET_MACOS_NR_fsync:
        /* fsync(int fd) */
        ret = get_errno(fsync(arg1));
        break;

    case TARGET_MACOS_NR_fdatasync:
        /* fdatasync(int fd) */
        ret = get_errno(fdatasync(arg1));
        break;

    case TARGET_MACOS_NR_readv:
    case TARGET_MACOS_NR_readv_nocancel:
        /* readv(int fd, struct iovec *iovp, int iovcnt) */
        {
            struct iovec *vec;
            int count = arg3;
            if (count <= 0 || count > 1024) {
                ret = -TARGET_EINVAL;
                break;
            }
            vec = g_new(struct iovec, count);
            /* Direct mapping: guest iovec same as host iovec */
            void *p = lock_user(VERIFY_READ, arg2,
                                count * sizeof(struct iovec), 1);
            if (!p) {
                g_free(vec);
                ret = -TARGET_EFAULT;
                break;
            }
            memcpy(vec, p, count * sizeof(struct iovec));
            unlock_user(p, arg2, 0);
            ret = get_errno(readv(arg1, vec, count));
            g_free(vec);
        }
        break;

    case TARGET_MACOS_NR_writev:
    case TARGET_MACOS_NR_writev_nocancel:
        /* writev(int fd, struct iovec *iovp, int iovcnt) */
        {
            struct iovec *vec;
            int count = arg3;
            if (count <= 0 || count > 1024) {
                ret = -TARGET_EINVAL;
                break;
            }
            vec = g_new(struct iovec, count);
            void *p = lock_user(VERIFY_READ, arg2,
                                count * sizeof(struct iovec), 1);
            if (!p) {
                g_free(vec);
                ret = -TARGET_EFAULT;
                break;
            }
            memcpy(vec, p, count * sizeof(struct iovec));
            unlock_user(p, arg2, 0);
            ret = get_errno(writev(arg1, vec, count));
            g_free(vec);
        }
        break;

    case TARGET_MACOS_NR_pread:
    case TARGET_MACOS_NR_pread_nocancel:
        /* pread(int fd, void *buf, size_t nbyte, off_t offset) */
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pread(arg1, p, arg3, arg4));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_pwrite:
    case TARGET_MACOS_NR_pwrite_nocancel:
        /* pwrite(int fd, const void *buf, size_t nbyte, off_t offset) */
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pwrite(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_truncate:
        /* truncate(const char *path, off_t length) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(truncate(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_ftruncate:
        /* ftruncate(int fd, off_t length) */
        ret = get_errno(ftruncate(arg1, arg2));
        break;

    case TARGET_MACOS_NR_getdtablesize:
        /* getdtablesize() */
        ret = get_errno(getdtablesize());
        break;

    case TARGET_MACOS_NR_getpgrp:
        ret = get_errno(getpgrp());
        break;

    case TARGET_MACOS_NR_setpgid:
        /* setpgid(pid_t pid, pid_t pgid) */
        ret = get_errno(setpgid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_setsid:
        ret = get_errno(setsid());
        break;

    case TARGET_MACOS_NR_getpgid:
        /* getpgid(pid_t pid) */
        ret = get_errno(getpgid(arg1));
        break;

    case TARGET_MACOS_NR_getsid:
        /* getsid(pid_t pid) */
        ret = get_errno(getsid(arg1));
        break;

    case TARGET_MACOS_NR_setuid:
        ret = get_errno(setuid(arg1));
        break;

    case TARGET_MACOS_NR_setgid:
        ret = get_errno(setgid(arg1));
        break;

    case TARGET_MACOS_NR_seteuid:
        ret = get_errno(seteuid(arg1));
        break;

    case TARGET_MACOS_NR_setegid:
        ret = get_errno(setegid(arg1));
        break;

    case TARGET_MACOS_NR_setreuid:
        ret = get_errno(setreuid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_setregid:
        ret = get_errno(setregid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_getgroups:
        /* getgroups(int gidsetsize, gid_t *grouplist) */
        {
            gid_t *grouplist = NULL;
            if (arg1 > 0) {
                grouplist = lock_user(VERIFY_WRITE, arg2,
                                      arg1 * sizeof(gid_t), 0);
                if (!grouplist) {
                    ret = -TARGET_EFAULT;
                    break;
                }
            }
            ret = get_errno(getgroups(arg1, grouplist));
            if (grouplist) {
                unlock_user(grouplist, arg2, ret * sizeof(gid_t));
            }
        }
        break;

    case TARGET_MACOS_NR_setgroups:
        /* setgroups(int ngroups, const gid_t *gidset) */
        {
            gid_t *gidset = lock_user(VERIFY_READ, arg2,
                                       arg1 * sizeof(gid_t), 1);
            if (!gidset) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(setgroups(arg1, gidset));
                unlock_user(gidset, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getrlimit:
        /* getrlimit(int resource, struct rlimit *rlp) */
        {
            struct rlimit rlim;
            ret = get_errno(getrlimit(arg1, &rlim));
            if (!is_error(ret) && arg2) {
                struct rlimit *p = lock_user(VERIFY_WRITE, arg2,
                                             sizeof(struct rlimit), 0);
                if (!p) {
                    ret = -TARGET_EFAULT;
                } else {
                    *p = rlim;
                    unlock_user(p, arg2, sizeof(struct rlimit));
                }
            }
        }
        break;

    case TARGET_MACOS_NR_setrlimit:
        /* setrlimit(int resource, const struct rlimit *rlp) */
        {
            struct rlimit *p = lock_user(VERIFY_READ, arg2,
                                          sizeof(struct rlimit), 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(setrlimit(arg1, p));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_madvise:
        /* madvise(void *addr, size_t len, int advice) */
        ret = get_errno(madvise(g2h_untagged(arg1), arg2, arg3));
        break;

    case TARGET_MACOS_NR_mlock:
        /* mlock(const void *addr, size_t len) */
        ret = get_errno(mlock(g2h_untagged(arg1), arg2));
        break;

    case TARGET_MACOS_NR_munlock:
        /* munlock(const void *addr, size_t len) */
        ret = get_errno(munlock(g2h_untagged(arg1), arg2));
        break;

    case TARGET_MACOS_NR_pathconf:
        /* pathconf(const char *path, int name) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pathconf(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fpathconf:
        /* fpathconf(int fd, int name) */
        ret = get_errno(fpathconf(arg1, arg2));
        break;

    case TARGET_MACOS_NR_sync:
        sync();
        ret = 0;
        break;

    case TARGET_MACOS_NR_lchown:
        /* lchown(const char *path, uid_t owner, gid_t group) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(lchown(p, arg2, arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_chroot:
        /* chroot(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chroot(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_mkfifo:
        /* mkfifo(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkfifo(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getrusage:
        /* getrusage(int who, struct rusage *usage) */
        {
            struct rusage ru;
            ret = get_errno(getrusage(arg1, &ru));
            if (!is_error(ret) && arg2) {
                struct rusage *p = lock_user(VERIFY_WRITE, arg2,
                                              sizeof(struct rusage), 0);
                if (!p) {
                    ret = -TARGET_EFAULT;
                } else {
                    *p = ru;
                    unlock_user(p, arg2, sizeof(struct rusage));
                }
            }
        }
        break;

    case TARGET_MACOS_NR_getentropy:
        /* getentropy(void *buf, size_t buflen) */
        {
            void *p = lock_user(VERIFY_WRITE, arg1, arg2, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(getentropy(p, arg2));
                unlock_user(p, arg1, arg2);
            }
        }
        break;

    case TARGET_MACOS_NR_thread_selfid:
        /* thread_selfid() - return current thread ID */
        {
            uint64_t tid;
            pthread_threadid_np(NULL, &tid);
            ret = tid;
        }
        break;

    case TARGET_MACOS_NR_issetugid:
        /* issetugid() - always return 0 for now */
        ret = 0;
        break;

    /* _nocancel variants: delegate to their base syscalls */
    case TARGET_MACOS_NR_read_nocancel:
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_read(arg1, p, arg3));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_write_nocancel:
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_write(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_open_nocancel:
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_open(p, target_to_host_bitmask(arg2,
                                fcntl_flags_tbl), arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_close_nocancel:
        ret = get_errno(close(arg1));
        break;

    case TARGET_MACOS_NR_fcntl_nocancel:
        ret = do_bsd_fcntl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_fsync_nocancel:
        ret = get_errno(fsync(arg1));
        break;

    /* *at syscalls */
    case TARGET_MACOS_NR_openat:
    case TARGET_MACOS_NR_openat_nocancel:
        /* openat(int fd, const char *path, int oflag, mode_t mode) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                if (rp != p) {
                    /* Redirected to absolute path — use AT_FDCWD */
                    ret = get_errno(openat(AT_FDCWD, rp,
                                    target_to_host_bitmask(arg3,
                                        fcntl_flags_tbl), arg4));
                } else {
                    ret = get_errno(openat(arg1, p,
                                    target_to_host_bitmask(arg3,
                                        fcntl_flags_tbl), arg4));
                }
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_faccessat:
        /* faccessat(int fd, const char *path, int mode, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(faccessat(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchmodat:
        /* fchmodat(int fd, const char *path, mode_t mode, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(fchmodat(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchownat:
        /* fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(fchownat(arg1, p, arg3, arg4, arg5));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fstatat:
    case TARGET_MACOS_NR_fstatat64:
        /* fstatat(int fd, const char *path, struct stat *buf, int flag) */
        {
            struct stat st;
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                if (rp != p) {
                    ret = get_errno(fstatat(AT_FDCWD, rp, &st, arg4));
                } else {
                    ret = get_errno(fstatat(arg1, p, &st, arg4));
                }
                unlock_user(p, arg2, 0);
                if (!is_error(ret)) {
                    if (arg3 && host_to_target_stat(arg3, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_unlinkat:
        /* unlinkat(int fd, const char *path, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(unlinkat(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_readlinkat:
        /* readlinkat(int fd, const char *path, char *buf, size_t bufsiz) */
        {
            void *p = lock_user_string(arg2);
            void *p2 = lock_user(VERIFY_WRITE, arg3, arg4, 0);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(readlinkat(arg1, p, p2, arg4));
            }
            unlock_user(p2, arg3, ret);
            unlock_user(p, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_symlinkat:
        /* symlinkat(const char *target, int fd, const char *linkpath) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg3);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(symlinkat(p1, arg2, p2));
            }
            unlock_user(p2, arg3, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_mkdirat:
        /* mkdirat(int fd, const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkdirat(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_renameat:
        /* renameat(int fromfd, const char *from, int tofd, const char *to) */
        {
            void *p1 = lock_user_string(arg2);
            void *p2 = lock_user_string(arg4);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(renameat(arg1, p1, arg3, p2));
            }
            unlock_user(p2, arg4, 0);
            unlock_user(p1, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_linkat:
        /* linkat(int fd1, const char *name1, int fd2, const char *name2, int flag) */
        {
            void *p1 = lock_user_string(arg2);
            void *p2 = lock_user_string(arg4);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(linkat(arg1, p1, arg3, p2, arg5));
            }
            unlock_user(p2, arg4, 0);
            unlock_user(p1, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_sigaction:
        ret = do_sigaction(arg1,
                           arg2 ? g2h_untagged(arg2) : NULL,
                           arg3 ? g2h_untagged(arg3) : NULL);
        break;

    case TARGET_MACOS_NR_sigprocmask:
        /* sigprocmask(int how, const sigset_t *set, sigset_t *oldset) */
        ret = do_bsd_sigprocmask(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_sigaltstack:
        ret = do_sigaltstack(arg1, arg2,
                             ((CPUARMState *)cpu_env)->xregs[31]);
        break;

    case TARGET_MACOS_NR_sigreturn:
        ret = do_sigreturn(cpu_env, arg1);
        break;

    case TARGET_MACOS_NR_kill:
        /* kill(pid_t pid, int sig) */
        ret = get_errno(kill(arg1, target_to_host_signal(arg2)));
        break;

    /*
     * Syscalls required by dyld and dynamically linked programs
     */

    case TARGET_MACOS_NR_sysctl:
        /* __sysctl(int *name, u_int namelen, void *old, size_t *oldlenp,
         *          void *new, size_t newlen) */
        {
            int *name_ptr = NULL;
            void *old_ptr = NULL;
            size_t *oldlen_ptr = NULL;
            void *new_ptr = NULL;

            if (arg1) name_ptr = (int *)g2h_untagged(arg1);
            if (arg3) old_ptr = g2h_untagged(arg3);
            if (arg4) oldlen_ptr = (size_t *)g2h_untagged(arg4);
            if (arg5) new_ptr = g2h_untagged(arg5);

            ret = get_errno(sysctl(name_ptr, (u_int)arg2, old_ptr,
                                   oldlen_ptr, new_ptr, (size_t)arg6));
        }
        break;

    case TARGET_MACOS_NR_sysctlbyname:
        /* sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
         *              void *newp, size_t newlen) */
        {
            char *name_str = NULL;
            void *old_ptr = NULL;
            size_t *oldlen_ptr = NULL;
            void *new_ptr = NULL;

            if (arg1) name_str = (char *)g2h_untagged(arg1);
            if (arg3) old_ptr = g2h_untagged(arg3);
            if (arg4) oldlen_ptr = (size_t *)g2h_untagged(arg4);
            if (arg5) new_ptr = g2h_untagged(arg5);

            ret = get_errno(sysctlbyname(name_str, old_ptr,
                                         oldlen_ptr, new_ptr, (size_t)arg6));
        }
        break;

    case TARGET_MACOS_NR_csops:
    case TARGET_MACOS_NR_csops_audittoken:
        /*
         * csops(pid, ops, useraddr, usersize) — code signing operations.
         * Forward to host kernel so dyld gets valid code signing status.
         */
        {
            void *useraddr = NULL;
            if (arg3) useraddr = g2h_untagged(arg3);
            ret = get_errno(csops((pid_t)arg1, (unsigned int)arg2,
                                  useraddr, (size_t)arg4));
        }
        break;

    case TARGET_MACOS_NR_shared_region_check_np:
        /*
         * shared_region_check_np(uint64_t *start_address)
         *
         * If the shared cache has been mapped via our
         * shared_region_map_and_slide_2_np handler, return
         * the base address.  Otherwise return EINVAL.
         * Special case: arg1 == -1 is disablePageInLinking.
         */
        if (arg1 == (abi_ulong)-1) {
            ret = 0;
        } else if (guest_shared_cache_addr && arg1) {
            uint64_t addr = guest_shared_cache_addr;
            memcpy(g2h_untagged(arg1), &addr, sizeof(addr));
            ret = 0;
        } else {
            ret = -TARGET_EINVAL;
        }
        break;

    case TARGET_MACOS_NR_crossarch_trap:
        /*
         * crossarch_trap(uint32_t name)
         * Used for cross-architecture traps. Returns ENOTSUP in XNU.
         */
        ret = -TARGET_ENOSYS;
        break;

    case TARGET_MACOS_NR___mac_syscall:
        /*
         * __mac_syscall(const char *policy, int call, void *arg)
         * MAC framework syscall — used for sandbox checks.
         * Return 0 (no restrictions) in emulation.
         */
        ret = 0;
        break;

    case TARGET_MACOS_NR_fsgetpath:
        /*
         * fsgetpath(char *buf, size_t buflen, fsid_t *fsid, uint64_t objid)
         * Convert filesystem ID + object ID to a path.
         * Forward to host kernel with proper guest pointer translation.
         */
        {
            char *buf = arg1 ? (char *)g2h_untagged(arg1) : NULL;
            void *fsid = arg3 ? g2h_untagged(arg3) : NULL;
            ret = get_errno(syscall(SYS_fsgetpath, buf, (size_t)arg2,
                                    fsid, (uint64_t)arg4));
        }
        break;

    case 483: /* __nexus_register — stub */
        ret = -TARGET_ENOSYS;
        break;

    case 336: /* proc_info */
        /*
         * proc_info(int callnum, int pid, uint32_t flavor,
         *           uint64_t arg, void *buffer, int buffersize)
         * Forward most calls to host; stub SET_DYLD_IMAGES (callnum 15)
         * which notifies the kernel about loaded images.
         */
        {
            int callnum = (int)arg1;
            if (callnum == 0xf) {
                /* PROC_INFO_CALL_SET_DYLD_IMAGES — stub success */
                ret = 0;
            } else {
                void *buf = arg5 ? g2h_untagged(arg5) : NULL;
                ret = get_errno(syscall(336, callnum, (int)arg2,
                                        (uint32_t)arg3, (uint64_t)arg4,
                                        buf, (int)arg6));
            }
        }
        break;

    case TARGET_MACOS_NR_shared_region_map_and_slide_2_np:
        /*
         * shared_region_map_and_slide_2_np(files_count, files,
         *                                  mappings_count, mappings)
         *
         * Two-pass emulation of the XNU shared-region syscall:
         *  Pass 1 - mmap every segment (with PROT_WRITE for those
         *           needing fixups).
         *  Pass 2 - read the slide info from the now-mapped memory
         *           (sms_slide_start is a guest VA, like the kernel's
         *           copyin), apply chained fixups + PAC signing, then
         *           set final protection.
         */
        {
            uint32_t files_count = (uint32_t)arg1;
            uint32_t mappings_count = (uint32_t)arg3;

            if (!arg2 || !arg4 || files_count == 0 || mappings_count == 0) {
                ret = -TARGET_EINVAL;
                break;
            }

            struct {
                int32_t  sf_fd;
                uint32_t sf_mappings_count;
                uint32_t sf_slide;
            } *files_arr = g2h_untagged(arg2);

            struct {
                uint64_t sms_address;
                uint64_t sms_size;
                uint64_t sms_file_offset;
                uint64_t sms_slide_size;
                uint64_t sms_slide_start;
                int32_t  sms_max_prot;
                int32_t  sms_init_prot;
            } *maps_arr = g2h_untagged(arg4);

            /*
             * Build a per-mapping slide value from the per-file slide.
             * We need this in pass 2, so compute it now.
             */
            uint32_t *slide_per_map = g_new0(uint32_t, mappings_count);
            {
                uint32_t mi2 = 0;
                for (uint32_t fi = 0;
                     fi < files_count && mi2 < mappings_count; fi++) {
                    uint32_t cnt = files_arr[fi].sf_mappings_count;
                    for (uint32_t j = 0;
                         j < cnt && mi2 < mappings_count; j++, mi2++) {
                        slide_per_map[mi2] = files_arr[fi].sf_slide;
                    }
                }
            }

            /* ---- Pass 1: map every segment ---- */
            uint32_t mi = 0;
            ret = 0;
            for (uint32_t fi = 0; fi < files_count && mi < mappings_count; fi++) {
                int fd = files_arr[fi].sf_fd;
                uint32_t count = files_arr[fi].sf_mappings_count;
                for (uint32_t j = 0; j < count && mi < mappings_count; j++, mi++) {
                    uint64_t addr = maps_arr[mi].sms_address;
                    uint64_t size = maps_arr[mi].sms_size;
                    uint64_t off  = maps_arr[mi].sms_file_offset;
                    int iprot     = maps_arr[mi].sms_init_prot;
                    bool has_slide = (maps_arr[mi].sms_slide_size > 0 &&
                                     maps_arr[mi].sms_slide_start > 0);

                    int host_prot = 0;
                    if (iprot & 1) host_prot |= PROT_READ;
                    if (iprot & 2) host_prot |= PROT_WRITE;
                    if (iprot & 4) host_prot |= PROT_EXEC;

                    /* Need PROT_WRITE to apply fixups in pass 2 */
                    int map_prot = has_slide ?
                        (host_prot | PROT_WRITE) : host_prot;

                    void *host_addr = g2h_untagged(addr);
                    void *p;

                    if ((iprot & 0x10) || fd < 0) {
                        p = mmap(host_addr, size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                 -1, 0);
                        if (p != MAP_FAILED && fd < 0 && off != 0) {
                            void *src = g2h_untagged(off);
                            memcpy(p, src, size);
                        }
                        if (p != MAP_FAILED && host_prot &&
                            host_prot != (PROT_READ | PROT_WRITE)) {
                            mprotect(p, size, host_prot);
                        }
                    } else {
                        p = mmap(host_addr, size, map_prot,
                                 MAP_PRIVATE | MAP_FIXED, fd, off);
                    }

                    if (p == MAP_FAILED) {
                        fprintf(stderr, "qemu: shared_region mmap failed: "
                                "mi=%u addr=0x%llx size=0x%llx "
                                "off=0x%llx fd=%d prot=0x%x errno=%d\n",
                                mi,
                                (unsigned long long)addr,
                                (unsigned long long)size,
                                (unsigned long long)off,
                                fd, iprot, errno);
                        ret = -TARGET_ENOMEM;
                        break;
                    }

                    int qf = PAGE_VALID;
                    if (host_prot & PROT_READ)  qf |= PAGE_READ;
                    if (host_prot & PROT_WRITE) qf |= PAGE_WRITE;
                    if (host_prot & PROT_EXEC)  qf |= PAGE_EXEC;
                    mmap_lock();
                    page_set_flags(addr, addr + size - 1, qf, ~0);
                    mmap_unlock();
                }
            }

            /*
             * ---- Pass 2: apply chained fixups ----
             * sms_slide_start is a guest VA (the kernel uses copyin).
             * All mappings are now established so we can read the
             * slide info via g2h.
             */
            if (ret == 0) {
                for (mi = 0; mi < mappings_count; mi++) {
                    uint64_t slide_info_addr =
                        maps_arr[mi].sms_slide_start;
                    uint64_t slide_info_size =
                        maps_arr[mi].sms_slide_size;

                    if (slide_info_size == 0 || slide_info_addr == 0) {
                        continue;
                    }

                    void *slide_buf = g2h_untagged(slide_info_addr);
                    void *mapped = g2h_untagged(
                        maps_arr[mi].sms_address);

                    apply_slide_info_v5(
                        (CPUARMState *)cpu_env,
                        slide_buf, slide_info_size,
                        mapped,
                        maps_arr[mi].sms_address,
                        maps_arr[mi].sms_size,
                        slide_per_map[mi]);

                    if (do_strace) {
                        fprintf(stderr,
                                "qemu: applied slide fixups at "
                                "0x%llx (size=0x%llx)\n",
                                (unsigned long long)
                                    maps_arr[mi].sms_address,
                                (unsigned long long)
                                    maps_arr[mi].sms_size);
                    }

                    /* Restore read-only protection if needed */
                    int iprot = maps_arr[mi].sms_init_prot;
                    int host_prot = 0;
                    if (iprot & 1) host_prot |= PROT_READ;
                    if (iprot & 2) host_prot |= PROT_WRITE;
                    if (iprot & 4) host_prot |= PROT_EXEC;
                    if (!(host_prot & PROT_WRITE)) {
                        mprotect(mapped, maps_arr[mi].sms_size,
                                 host_prot);
                    }
                }
            }

            g_free(slide_per_map);

            /* Record the cache base for shared_region_check_np */
            if (ret == 0 && mappings_count > 0) {
                guest_shared_cache_addr = maps_arr[0].sms_address;
            }
        }
        break;

    case TARGET_MACOS_NR_shared_region_map_and_slide_np:
        /*
         * shared_region_map_and_slide_np (older variant)
         * Return ENOENT to force dyld's private mapping fallback.
         */
        ret = -TARGET_ENOENT;
        break;

    default:
        qemu_log_mask(LOG_UNIMP, "Unsupported macOS syscall: %d\n", num);
        ret = -TARGET_ENOSYS;
        break;
    }

    if (do_strace) {
        print_syscall_ret(cpu, num, ret, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    return ret;
}
