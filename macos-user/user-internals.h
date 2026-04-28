/*
 * User mode internals
 */

#ifndef USER_INTERNALS_H
#define USER_INTERNALS_H

#include "qemu/osdep.h"
#include "user/abitypes.h"
#include "user/guest-host.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include <mach/mach.h>
#include <sys/ioctl.h>

/* Environment list */
struct envlist;
extern struct envlist *envlist;

/* CPU model */
extern const char *cpu_model;

/* Strace */
extern bool do_strace;

void print_syscall(CPUState *cpu, int num,
                  abi_long arg1, abi_long arg2, abi_long arg3,
                  abi_long arg4, abi_long arg5, abi_long arg6);
void print_syscall_ret(CPUState *cpu, int num, abi_long ret,
                       abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6);

/* User memory access */
#define VERIFY_READ 0
#define VERIFY_WRITE 1

void *lock_user(int type, abi_ulong guest_addr, size_t len, bool copy);
void unlock_user(void *host_ptr, abi_ulong guest_addr, size_t len);
void *lock_user_string(abi_ulong guest_addr);

/* Error handling */
#define TARGET_EPERM        1
#define TARGET_ENOENT       2
#define TARGET_EINTR        4
#define TARGET_ENOMEM       12
#define TARGET_EACCES       13
#define TARGET_EFAULT       14
#define TARGET_EINVAL       22
#define TARGET_ENOTSUP      45
#define TARGET_ETIMEDOUT    60
#define TARGET_ENOSYS       78

static inline bool is_error(abi_long ret)
{
    return (abi_ulong)ret >= (abi_ulong)(-4096);
}

static inline abi_long get_errno(abi_long ret)
{
    if (ret == -1) {
        return -errno;
    }
    return ret;
}

/* Safe I/O wrappers */
static inline ssize_t safe_read(int fd, void *buf, size_t count)
{
    ssize_t ret;
    do {
        ret = read(fd, buf, count);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

static inline ssize_t safe_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;
    do {
        ret = write(fd, buf, count);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

static inline int safe_open(const char *path, int flags, mode_t mode)
{
    int ret;
    do {
        ret = open(path, flags, mode);
    } while (ret == -1 && errno == EINTR);
    return ret;
}

/* Page operations - TARGET_PAGE_BITS is defined per-target in cpu-param.h;
 * TARGET_PAGE_SIZE, TARGET_PAGE_MASK, and TARGET_PAGE_ALIGN are provided
 * by include/exec/target_page.h and must not be redefined here. */

/* BSD-style helpers */
static inline abi_long do_bsd_fcntl(int fd, int cmd, abi_ulong arg)
{
    switch (cmd) {
    case F_GETPATH:
#ifdef F_GETPATH_NOFIRMLINK
    case F_GETPATH_NOFIRMLINK:
#endif
    case F_ADDFILESIGS:
    case F_ADDFILESIGS_RETURN:
#ifdef F_ADDFILESIGS_FOR_DYLD_SIM
    case F_ADDFILESIGS_FOR_DYLD_SIM:
#endif
#ifdef F_ADDFILESIGS_INFO
    case F_ADDFILESIGS_INFO:
#endif
#ifdef F_CHECK_LV
    case F_CHECK_LV:
#endif
    case F_ADDSIGS:
    case F_FINDSIGS:
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW:
    {
        /* arg is a guest pointer to a struct — translate to host */
        void *p = g2h_untagged(arg);
        return get_errno(fcntl(fd, cmd, p));
    }
    default:
        return get_errno(fcntl(fd, cmd, arg));
    }
}

static inline abi_long do_bsd_ioctl(int fd, int cmd, abi_ulong arg)
{
    return get_errno(ioctl(fd, cmd, arg));
}

/* Signal handling - implemented in signal.c */
abi_long do_bsd_sigprocmask(void *env, int how,
                            abi_ulong set, abi_ulong oldset);
abi_long do_sigaltstack(abi_ulong ss, abi_ulong old_ss, abi_ulong sp);

/* Conversion functions (stubs for now) */
static inline int host_to_target_stat(abi_ulong target_addr, struct stat *host_st)
{
    /*
     * macOS target and host share the same stat layout (both arm64),
     * so just memcpy the struct into the guest buffer.
     */
    memcpy(g2h_untagged(target_addr), host_st, sizeof(struct stat));
    return 0;
}

static inline int copy_to_user_timeval(abi_ulong target_addr, const struct timeval *tv)
{
    memcpy(g2h_untagged(target_addr), tv, sizeof(struct timeval));
    return 0;
}

static inline unsigned int target_to_host_bitmask(unsigned int target_mask, const void *table)
{
    /* TODO: Implement proper bitmask conversion */
    return target_mask;
}

int target_to_host_signal(int sig);

/* Flag tables */
extern const void *fcntl_flags_tbl;
extern const void *mmap_flags_tbl;

/* GDB */
void gdb_exit(int code);
void dump_core_and_abort(int sig);

/* Thread support */
CPUArchState *cpu_copy(CPUArchState *env);
void cpu_loop(CPUArchState *env);
void service_pending_workloop_reqs(void);
void service_workloop_machport_events(void);
void mark_active_rcv_port(mach_port_t port);
void unmark_active_rcv_port(mach_port_t port);
bool is_port_active_rcv(mach_port_t port);
void record_workq_notification_port(mach_port_t port, mach_port_t watched_port,
                                    mach_msg_id_t msgid);
bool is_workq_notification_port(mach_port_t port);
void queue_workq_send_possible_notification(mach_port_t watched_port);
void service_workq_notification_events(void);
kern_return_t fixup_mig_reply_ool(void *reply_buf,
                                  mach_msg_size_t reply_buf_size,
                                  mach_port_name_t receive_set);

static inline void begin_parallel_context(CPUState *cs)
{
    if (!tcg_cflags_has(cs, CF_PARALLEL)) {
        tb_flush__exclusive_or_serial();
        tcg_cflags_set(cs, CF_PARALLEL);
    }
}

#endif /* USER_INTERNALS_H */
