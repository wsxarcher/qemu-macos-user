/*
 *  macOS signal handling
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "signal-common.h"
#include "user-internals.h"

/* Per-thread signal table */
static struct emulated_sigtable sigtable[TARGET_NSIG];
static sigset_t blocked_signals;

void signal_init(void)
{
    struct sigaction act;
    int i;

    /* Block all signals during initialization */
    sigfillset(&blocked_signals);
    sigprocmask(SIG_BLOCK, &blocked_signals, NULL);

    /* Set up host signal handlers */
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = host_signal_handler;
    act.sa_flags = SA_SIGINFO;
    sigfillset(&act.sa_mask);

    /* Install handlers for signals we care about */
    for (i = 1; i < TARGET_NSIG; i++) {
        if (i != SIGKILL && i != SIGSTOP) {
            sigaction(i, &act, NULL);
        }
    }

    sigemptyset(&blocked_signals);
}

void queue_signal(CPUArchState *env, int sig, int si_type,
                  target_siginfo_t *info)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;

    if (sig < 1 || sig > TARGET_NSIG) {
        return;
    }

    /* Queue the signal */
    ts->sigtab[sig - 1].pending = 1;
    ts->sigtab[sig - 1].info = *info;

    /* Mark CPU for signal processing */
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_exit(cpu);
}

void force_sig_fault(int sig, int code, abi_ulong addr)
{
    CPUState *cpu = thread_cpu;
    CPUArchState *env = cpu->env_ptr;
    target_siginfo_t info;

    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = code;
    info.si_addr = addr;

    queue_signal(env, sig, SI_KERNEL, &info);
}

void process_pending_signals(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = cpu->opaque;
    int sig;

    /* Check for pending signals */
    for (sig = 1; sig < TARGET_NSIG; sig++) {
        if (ts->sigtab[sig - 1].pending) {
            /* Check if signal is blocked */
            if (sigismember(&ts->signal_mask, sig)) {
                continue;
            }

            /* Deliver the signal */
            ts->sigtab[sig - 1].pending = 0;

            /* For now, just handle fatal signals */
            if (sig == TARGET_SIGSEGV || sig == TARGET_SIGILL ||
                sig == TARGET_SIGBUS || sig == TARGET_SIGABRT) {
                dump_core_and_abort(sig);
            }
        }
    }
}

int do_sigaction(int sig, const struct target_sigaction *act,
                 struct target_sigaction *oact)
{
    /* Basic sigaction implementation */
    if (sig < 1 || sig >= TARGET_NSIG || sig == SIGKILL || sig == SIGSTOP) {
        return -TARGET_EINVAL;
    }

    /* TODO: Implement full sigaction */
    return 0;
}

long do_sigreturn(CPUArchState *env, abi_ulong addr)
{
    /* TODO: Implement sigreturn */
    return -TARGET_ENOSYS;
}

long do_rt_sigreturn(CPUArchState *env)
{
    /* TODO: Implement rt_sigreturn */
    return -TARGET_ENOSYS;
}
