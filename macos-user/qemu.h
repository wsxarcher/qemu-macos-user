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
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/vcpu-state.h"

#include "user/abitypes.h"
#include "user/mmap.h"
#include "user/page-protection.h"
#include "exec/gdbstub.h"
#include "syscall_defs.h"
#include "target_syscall.h"
#include "target_arch.h"

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

    struct target_sigaltstack sigaltstack_base;
    struct emulated_sigtable sigtab[TARGET_NSIG];

    sigset_t signal_mask;
    uint8_t stack[SIGSTKSZ] __attribute__((aligned(16)));
};

abi_long do_macos_syscall(void *cpu_env, int num, abi_long arg1,
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
void signal_init(void);
long do_sigreturn(CPUArchState *env, abi_ulong addr);
long do_rt_sigreturn(CPUArchState *env);
void force_sig_fault(int sig, int code, abi_ulong addr);
void queue_signal(CPUArchState *env, int sig, int si_type,
                  target_siginfo_t *info);
void process_pending_signals(CPUArchState *env);
int do_sigaction(int sig, const struct target_sigaction *act,
                 struct target_sigaction *oact);

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

#endif /* QEMU_H */
