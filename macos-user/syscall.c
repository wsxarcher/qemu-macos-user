/*
 *  macOS system call implementation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"
#include "loader.h"
#include "user/syscall-trace.h"

/* Syscall implementation */
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
                ret = get_errno(safe_open(p, target_to_host_bitmask(arg2, fcntl_flags_tbl),
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
                ret = get_errno(stat(p, &st));
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

    case TARGET_MACOS_NR_issetugid:
        /* issetugid() - always return 0 for now */
        ret = 0;
        break;

    case TARGET_MACOS_NR_sigaction:
        ret = do_sigaction(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_sigprocmask:
        /* sigprocmask(int how, const sigset_t *set, sigset_t *oldset) */
        ret = do_bsd_sigprocmask(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_sigaltstack:
        ret = do_sigaltstack(arg1, arg2, cpu_env);
        break;

    case TARGET_MACOS_NR_sigreturn:
        ret = do_sigreturn(cpu_env, arg1);
        break;

    case TARGET_MACOS_NR_kill:
        /* kill(pid_t pid, int sig) */
        ret = get_errno(kill(arg1, target_to_host_signal(arg2)));
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
