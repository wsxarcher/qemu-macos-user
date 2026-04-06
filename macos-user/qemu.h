/*
 *  macOS user mode emulation main header
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef QEMU_H
#define QEMU_H

#include "cpu.h"
#include "qemu/int128.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/vcpu-state.h"

#include "user/abitypes.h"
#include "user/mmap.h"
#include "user/page-protection.h"
#include "user/guest-host.h"
#include "exec/gdbstub.h"
#include "exec/page-protection.h"
#include "syscall_defs.h"
#include "target_syscall.h"
#include "target_arch.h"
#include "target_arch_signal.h"

#undef DEBUG_REMAP

#include "qemu/log.h"

/* This struct is used to hold certain information about the image. */
struct image_info {
    abi_ulong load_bias;
    abi_ulong load_addr;
    abi_ulong start_code;
    abi_ulong end_code;
    abi_ulong start_data;
    abi_ulong end_data;
    abi_ulong start_brk;
    abi_ulong brk;
    abi_ulong start_mmap;
    abi_ulong start_stack;
    abi_ulong stack_limit;
    abi_ulong entry;
    abi_ulong code_offset;
    abi_ulong data_offset;
    abi_ulong arg_start;
    abi_ulong arg_end;
    uint32_t  elf_flags;

    /* dyld support */
    abi_ulong interp_entry;     /* dyld entry point (0 if static) */
    abi_ulong mach_header_addr; /* guest address of main binary mach_header */
};

struct emulated_sigtable {
    int pending;
    target_siginfo_t info;
};

/*
 * This structure is used to hold the arguments that are
 * used when loading binaries.
 */
struct macos_binprm {
    char *filename;         /* (Given) Name of binary */
    char *fullpath;         /* Full path of binary */
};

/*
 * Task state shared between all threads in a task
 */
struct TaskState {
    pid_t ts_tid;     /* tid (or pid) of this task */

    struct TaskState *next;
    struct macos_binprm *bprm;
    struct image_info *info;

    struct emulated_sigtable sync_signal;
    struct emulated_sigtable sigtab[TARGET_NSIG];
    /*
     * Nonzero if process_pending_signals() needs to do something (either
     * handle a pending signal or unblock signals).
     */
    int signal_pending;
    /* True if we're leaving a sigsuspend and sigsuspend_mask is valid. */
    bool in_sigsuspend;
    /*
     * This thread's signal mask, as requested by the guest program.
     */
    sigset_t signal_mask;
    /*
     * The signal mask imposed by a guest sigsuspend syscall
     */
    sigset_t sigsuspend_mask;

    /* This thread's sigaltstack, if it has one */
    struct target_sigaltstack sigaltstack_used;

    /* Workqueue thread stack geometry (for thread parking/reuse) */
    bool is_wq_thread;
    abi_ulong wq_self_addr;
    abi_ulong wq_stack_top;
    abi_ulong wq_stack_bottom;
    abi_ulong wq_tsd_base;
} __attribute__((aligned(16)));

abi_long do_macos_syscall(void *cpu_env, int num, abi_long arg1,
                          abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7,
                          abi_long arg8);

abi_long do_mach_trap(void *cpu_env, int trap_num, abi_long arg1,
                      abi_long arg2, abi_long arg3, abi_long arg4,
                      abi_long arg5, abi_long arg6, abi_long arg7,
                      abi_long arg8);

extern unsigned long target_maxtsiz;
extern unsigned long target_dfldsiz;
extern unsigned long target_maxdsiz;
extern unsigned long target_dflssiz;
extern unsigned long target_maxssiz;
extern unsigned long target_sgrowsiz;

/* Target macOS signal handling */
#define TARGET_SIG_DFL  ((abi_ulong)0)
#define TARGET_SIG_IGN  ((abi_ulong)1)
#define TARGET_SIG_ERR  ((abi_ulong)-1)

void signal_init(void);
long do_sigreturn(CPUArchState *env, abi_ulong addr);
long do_rt_sigreturn(CPUArchState *env);
void force_sig_fault(int sig, int code, abi_ulong addr);
void queue_signal(CPUArchState *env, int sig, int si_type,
                  target_siginfo_t *info);
void process_pending_signals(CPUArchState *env);
int do_sigaction(int sig, abi_ulong act_addr, abi_ulong oact_addr);
abi_ulong get_sigreturn_trampoline_addr(void);

/* Signal conversion helpers */
int host_to_target_signal(int sig);
void host_to_target_sigset(target_sigset_t *d, const sigset_t *s);
void target_to_host_sigset(sigset_t *d, const target_sigset_t *s);
int block_signals(void);

/* mmap */
abi_long target_mmap(abi_ulong start, abi_ulong len, int prot,
                     int flags, int fd, off_t offset);
int target_munmap(abi_ulong start, abi_ulong len);
abi_long target_mremap(abi_ulong old_addr, abi_ulong old_size,
                       abi_ulong new_size, unsigned long flags,
                       abi_ulong new_addr);
int target_msync(abi_ulong start, abi_ulong len, int flags);
int target_mprotect(abi_ulong start, abi_ulong len, int prot);

/* Main thread handling */
extern __thread CPUState *thread_cpu;

int loader_exec(const char *filename, char **argv, char **envp,
                struct target_pt_regs *regs, struct image_info *infop,
                char **memp);

uint32_t get_elf_hwcap(void);

void init_task_state(TaskState *ts);

/* Guest private shared cache address (0 = not mapped) */
extern uint64_t guest_cache_addr;

/* strace/printing support */
void print_taken_signal(int target_signum, const target_siginfo_t *tinfo);

#endif /* QEMU_H */
