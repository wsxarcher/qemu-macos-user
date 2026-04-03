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
#include "user/guest-host.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"

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
                ret = get_errno(openat(arg1, p,
                                target_to_host_bitmask(arg3,
                                    fcntl_flags_tbl), arg4));
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
                ret = get_errno(fstatat(arg1, p, &st, arg4));
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
