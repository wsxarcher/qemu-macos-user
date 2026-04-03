/*
 *  macOS signal handling
 *
 *  Copyright (c) 2003 - 2008 Fabrice Bellard
 *  Copyright (c) 2013 Stacey Son
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ops.h"
#include "qemu.h"
#include "user/cpu_loop.h"
#include "user/signal.h"
#include "signal-common.h"
#include "user-internals.h"
#include "gdbstub/user.h"
#include "trace.h"

/*
 * Signal action table: stores the guest program's registered signal actions.
 */
static struct target_sigaction sigact_table[TARGET_NSIG];

static void target_to_host_sigset_internal(sigset_t *d,
        const target_sigset_t *s);

/* Arch-specific functions implemented in aarch64/signal.c */
extern abi_long set_sigtramp_args(CPUArchState *env, int sig,
                                  struct target_sigframe *frame,
                                  abi_ulong frame_addr,
                                  struct target_sigaction *ka);
extern abi_long setup_sigframe_arch(CPUArchState *env, abi_ulong frame_addr,
                                    struct target_sigframe *frame, int flags);
extern abi_long set_mcontext(CPUArchState *env,
                             target_sigcontext *mcp, int srflag);
extern abi_long get_ucontext_sigreturn(CPUArchState *env,
                                       abi_ulong target_sf,
                                       abi_ulong *target_ucontext);

/* ---- Signal stack helpers ---- */

static inline int on_sig_stack(TaskState *ts, unsigned long sp)
{
    return sp - ts->sigaltstack_used.ss_sp < ts->sigaltstack_used.ss_size;
}

static inline int sas_ss_flags(TaskState *ts, unsigned long sp)
{
    return ts->sigaltstack_used.ss_size == 0 ? SS_DISABLE :
        on_sig_stack(ts, sp) ? SS_ONSTACK : 0;
}

/* ---- Host interrupt signal ---- */

/*
 * Use SIGUSR1 as the host interrupt signal.  The real macOS target uses
 * SIGINFO (29), but SIGINFO does not exist on Linux hosts, so SIGUSR1
 * is a portable substitute for the host side.
 */
int host_interrupt_signal = SIGUSR1;

/* ---- Signal number mapping (identity on macOS, same as BSD) ---- */

int host_to_target_signal(int sig)
{
    return sig;
}

int target_to_host_signal(int sig)
{
    return sig;
}

/* ---- Target sigset operations ---- */

/*
 * macOS target_sigset_t is a simple abi_ulong bitmask (32 bits),
 * NOT a struct with __bits like FreeBSD.
 */
static inline void target_sigemptyset(target_sigset_t *set)
{
    *set = 0;
}

static inline void target_sigaddset(target_sigset_t *set, int signum)
{
    signum--;
    abi_ulong mask = (abi_ulong)1 << signum;
    *set |= mask;
}

static inline int target_sigismember(const target_sigset_t *set, int signum)
{
    signum--;
    abi_ulong mask = (abi_ulong)1 << signum;
    return (*set & mask) != 0;
}

/* ---- Sigset conversions ---- */

static void host_to_target_sigset_internal(target_sigset_t *d,
        const sigset_t *s)
{
    int i;

    target_sigemptyset(d);
    for (i = 1; i <= TARGET_NSIG; i++) {
        if (sigismember(s, i)) {
            target_sigaddset(d, host_to_target_signal(i));
        }
    }
}

void host_to_target_sigset(target_sigset_t *d, const sigset_t *s)
{
    host_to_target_sigset_internal(d, s);
}

static void target_to_host_sigset_internal(sigset_t *d,
        const target_sigset_t *s)
{
    int i;

    sigemptyset(d);
    for (i = 1; i <= TARGET_NSIG; i++) {
        if (target_sigismember(s, i)) {
            sigaddset(d, target_to_host_signal(i));
        }
    }
}

void target_to_host_sigset(sigset_t *d, const target_sigset_t *s)
{
    target_to_host_sigset_internal(d, s);
}

/* ---- Safe syscall rewind ---- */

/*
 * Adjust the signal context to rewind out of safe-syscall if we're in it.
 * This simplified version does not use host-signal.h (not available for
 * macos-user), so it is a no-op.  The cpu_exit() call in
 * host_signal_handler() ensures the main loop picks up the signal.
 */
static inline void rewind_if_in_safe_syscall(void *puc)
{
    /* No-op: host-signal.h helpers not available for macos-user */
}

/* ---- Helper predicates ---- */

static int fatal_signal(int sig)
{
    switch (sig) {
    case TARGET_SIGCHLD:
    case TARGET_SIGURG:
    case TARGET_SIGWINCH:
    case TARGET_SIGINFO:
        /* Ignored by default. */
        return 0;
    case TARGET_SIGCONT:
    case TARGET_SIGSTOP:
    case TARGET_SIGTSTP:
    case TARGET_SIGTTIN:
    case TARGET_SIGTTOU:
        /* Job control signals. */
        return 0;
    default:
        return 1;
    }
}

static int core_dump_signal(int sig)
{
    switch (sig) {
    case TARGET_SIGABRT:
    case TARGET_SIGFPE:
    case TARGET_SIGILL:
    case TARGET_SIGQUIT:
    case TARGET_SIGSEGV:
    case TARGET_SIGTRAP:
    case TARGET_SIGBUS:
        return 1;
    default:
        return 0;
    }
}

/* ---- block_signals ---- */

int block_signals(void)
{
    TaskState *ts = get_task_state(thread_cpu);
    sigset_t set;

    /*
     * Block everything while we atomically snapshot signal_pending.
     * Signals will be unblocked again in process_pending_signals().
     */
    sigfillset(&set);
    sigprocmask(SIG_SETMASK, &set, 0);

    return qatomic_xchg(&ts->signal_pending, 1);
}

/* ---- Queue / force signals ---- */

/*
 * Queue a signal so that it will be sent to the virtual CPU as soon as
 * possible.  Uses sync_signal in TaskState (like bsd-user).
 */
void queue_signal(CPUArchState *env, int sig, int si_type,
                  target_siginfo_t *info)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = get_task_state(cpu);

    info->si_code = deposit32(info->si_code, 24, 8, si_type);

    ts->sync_signal.info = *info;
    ts->sync_signal.pending = sig;
    /* Signal that a new signal is pending. */
    qatomic_set(&ts->signal_pending, 1);
}

/*
 * Force a synchronously taken QEMU_SI_FAULT signal.  For QEMU the
 * 'force' part is handled in process_pending_signals().
 */
void force_sig_fault(int sig, int code, abi_ulong addr)
{
    CPUState *cpu = thread_cpu;
    target_siginfo_t info = {};

    info.si_signo = sig;
    info.si_errno = 0;
    info.si_code = code;
    info.si_addr = addr;
    queue_signal(cpu_env(cpu), sig, QEMU_SI_FAULT, &info);
}

/* ---- Host signal handler ---- */

/*
 * Simplified host signal handler for macos-user.
 *
 * Handles the host interrupt signal (used to kick the vCPU) and queues
 * all other signals for delivery inside the guest.  The complex
 * SIGSEGV/SIGBUS synchronous-fault path that requires host-signal.h is
 * not needed here because cpu_loop_exit_sigsegv/sigbus already handle
 * the synchronous case from within the translated code.
 */
void host_signal_handler(int host_sig, siginfo_t *info, void *puc)
{
    CPUState *cpu = thread_cpu;
    TaskState *ts = get_task_state(cpu);
    target_siginfo_t tinfo;
    struct emulated_sigtable *k;
    int guest_sig;

    if (host_sig == host_interrupt_signal) {
        ts->signal_pending = 1;
        cpu_exit(cpu);
        return;
    }

    /* Get the target signal number. */
    guest_sig = host_to_target_signal(host_sig);
    if (guest_sig < 1 || guest_sig > TARGET_NSIG) {
        return;
    }

    memset(&tinfo, 0, sizeof(tinfo));
    tinfo.si_signo = guest_sig;
    tinfo.si_errno = info->si_errno;
    tinfo.si_code = info->si_code;
    tinfo.si_pid = info->si_pid;
    tinfo.si_uid = info->si_uid;
    tinfo.si_addr = (abi_ulong)(unsigned long)info->si_addr;

    k = &ts->sigtab[guest_sig - 1];
    k->info = tinfo;
    k->pending = guest_sig;
    ts->signal_pending = 1;

    rewind_if_in_safe_syscall(puc);

    /*
     * Block host signals until target signal handler entered.  We
     * can't block SIGSEGV or SIGBUS while we're executing guest
     * code in case the guest code provokes one in the window between
     * now and it getting out to the main loop.  Signals will be
     * unblocked again in process_pending_signals().
     */
    {
        ucontext_t *uc = puc;
        sigfillset(&uc->uc_sigmask);
        sigdelset(&uc->uc_sigmask, SIGSEGV);
        sigdelset(&uc->uc_sigmask, SIGBUS);
    }

    /* Interrupt the virtual CPU as soon as possible. */
    cpu_exit(cpu);
}

/* ---- do_sigaction ---- */

int do_sigaction(int sig, const struct target_sigaction *act,
                 struct target_sigaction *oact)
{
    struct target_sigaction *k;
    struct sigaction act1;
    int host_sig;
    int ret = 0;

    if (sig < 1 || sig > TARGET_NSIG) {
        return -TARGET_EINVAL;
    }

    if ((sig == TARGET_SIGKILL || sig == TARGET_SIGSTOP) &&
        act != NULL && act->_sa_handler != TARGET_SIG_DFL) {
        return -TARGET_EINVAL;
    }

    if (block_signals()) {
        return -TARGET_ERESTART;
    }

    k = &sigact_table[sig - 1];
    if (oact) {
        oact->_sa_handler = k->_sa_handler;
        oact->sa_flags = k->sa_flags;
        oact->sa_mask = k->sa_mask;
    }
    if (act) {
        k->_sa_handler = act->_sa_handler;
        k->sa_flags = act->sa_flags;
        k->sa_mask = act->sa_mask;

        /* Update the host signal state. */
        host_sig = target_to_host_signal(sig);
        if (host_sig != SIGSEGV && host_sig != SIGBUS) {
            memset(&act1, 0, sizeof(struct sigaction));
            sigfillset(&act1.sa_mask);
            act1.sa_flags = SA_SIGINFO;
            if (k->sa_flags & TARGET_SA_RESTART) {
                act1.sa_flags |= SA_RESTART;
            }
            /*
             * Update the host kernel signal mask to avoid getting
             * unexpected interrupted system calls.
             */
            if (k->_sa_handler == TARGET_SIG_IGN) {
                act1.sa_sigaction = (void *)SIG_IGN;
            } else if (k->_sa_handler == TARGET_SIG_DFL) {
                if (fatal_signal(sig)) {
                    act1.sa_sigaction = host_signal_handler;
                } else {
                    act1.sa_sigaction = (void *)SIG_DFL;
                }
            } else {
                act1.sa_sigaction = host_signal_handler;
            }
            ret = sigaction(host_sig, &act1, NULL);
        }
    }
    return ret;
}

/* ---- do_sigaltstack ---- */

abi_long do_sigaltstack(abi_ulong uss_addr, abi_ulong uoss_addr,
                        abi_ulong sp)
{
    TaskState *ts = get_task_state(thread_cpu);
    int ret;
    struct target_sigaltstack oss;

    if (uoss_addr) {
        /* Save current signal stack params */
        oss.ss_sp = ts->sigaltstack_used.ss_sp;
        oss.ss_size = ts->sigaltstack_used.ss_size;
        oss.ss_flags = sas_ss_flags(ts, sp);
    }

    if (uss_addr) {
        struct target_sigaltstack *uss;
        struct target_sigaltstack ss;
        size_t minstacksize = TARGET_MINSIGSTKSZ;

        ret = -TARGET_EFAULT;
        uss = lock_user(VERIFY_READ, uss_addr, sizeof(*uss), 1);
        if (!uss) {
            goto out;
        }
        ss.ss_sp = uss->ss_sp;
        ss.ss_size = uss->ss_size;
        ss.ss_flags = uss->ss_flags;
        unlock_user(uss, uss_addr, 0);

        ret = -TARGET_EPERM;
        if (on_sig_stack(ts, sp)) {
            goto out;
        }

        ret = -TARGET_EINVAL;
        if (ss.ss_flags != TARGET_SS_DISABLE
            && ss.ss_flags != TARGET_SS_ONSTACK
            && ss.ss_flags != 0) {
            goto out;
        }

        if (ss.ss_flags == TARGET_SS_DISABLE) {
            ss.ss_size = 0;
            ss.ss_sp = 0;
        } else {
            ret = -TARGET_ENOMEM;
            if (ss.ss_size < minstacksize) {
                goto out;
            }
        }

        ts->sigaltstack_used.ss_sp = ss.ss_sp;
        ts->sigaltstack_used.ss_size = ss.ss_size;
    }

    if (uoss_addr) {
        struct target_sigaltstack *uoss;
        ret = -TARGET_EFAULT;
        uoss = lock_user(VERIFY_WRITE, uoss_addr, sizeof(*uoss), 0);
        if (!uoss) {
            goto out;
        }
        uoss->ss_sp = oss.ss_sp;
        uoss->ss_size = oss.ss_size;
        uoss->ss_flags = oss.ss_flags;
        unlock_user(uoss, uoss_addr, sizeof(*uoss));
    }

    ret = 0;
out:
    return ret;
}

/* ---- signal_init ---- */

void signal_init(void)
{
    TaskState *ts = get_task_state(thread_cpu);
    struct sigaction act;
    struct sigaction oact;
    int i;
    int host_sig;

    /* Set the signal mask from the host mask. */
    sigprocmask(0, 0, &ts->signal_mask);

    sigfillset(&act.sa_mask);
    act.sa_sigaction = host_signal_handler;
    act.sa_flags = SA_SIGINFO;

    for (i = 1; i <= TARGET_NSIG; i++) {
        host_sig = target_to_host_signal(i);
        if (host_sig == host_interrupt_signal) {
            continue;
        }
        sigaction(host_sig, NULL, &oact);
        if (oact.sa_sigaction == (void *)SIG_IGN) {
            sigact_table[i - 1]._sa_handler = TARGET_SIG_IGN;
        } else if (oact.sa_sigaction == (void *)SIG_DFL) {
            sigact_table[i - 1]._sa_handler = TARGET_SIG_DFL;
        }
        /*
         * If there's already a handler installed then something has
         * gone horribly wrong, so don't even try to handle that case.
         * Install some handlers for our own use.  We need at least
         * SIGSEGV and SIGBUS, to detect exceptions.  We can not just
         * trap all signals because it affects syscall interrupt
         * behavior.  But do trap all default-fatal signals.
         */
        if (fatal_signal(i)) {
            sigaction(host_sig, &act, NULL);
        }
    }
    sigaction(host_interrupt_signal, &act, NULL);
}

/* ---- Signal frame setup ---- */

static inline abi_ulong get_sigframe(struct target_sigaction *ka,
        CPUArchState *env, size_t frame_size)
{
    TaskState *ts = get_task_state(thread_cpu);
    abi_ulong sp;

    /* Use default user stack */
    sp = get_sp_from_cpustate(env);

    if ((ka->sa_flags & TARGET_SA_ONSTACK) && sas_ss_flags(ts, sp) == 0) {
        sp = ts->sigaltstack_used.ss_sp + ts->sigaltstack_used.ss_size;
    }

    /* 16-byte align for AArch64 */
    return ROUND_DOWN(sp - frame_size, TARGET_SIGSTACK_ALIGN);
}

/*
 * Setup the signal frame on the guest stack and redirect execution to the
 * guest signal handler.  Delegates to arch-specific set_sigtramp_args() and
 * setup_sigframe_arch().
 */
void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUArchState *env)
{
    struct target_sigframe *frame;
    abi_ulong frame_addr;

    frame_addr = get_sigframe(ka, env, sizeof(*frame));
    frame = lock_user(VERIFY_WRITE, frame_addr, sizeof(*frame), 0);
    if (!frame) {
        dump_core_and_abort(TARGET_SIGILL);
        return;
    }

    memset(frame, 0, sizeof(*frame));
    setup_sigframe_arch(env, frame_addr, frame, 0);

    frame->uc_sigmask = *set;

    set_sigtramp_args(env, sig, frame, frame_addr, ka);

    unlock_user(frame, frame_addr, sizeof(*frame));
}

/* ---- do_sigreturn ---- */

long do_sigreturn(CPUArchState *env, abi_ulong addr)
{
    struct target_sigframe *frame;
    target_sigset_t target_set;
    sigset_t blocked;

    frame = lock_user(VERIFY_READ, addr, sizeof(*frame), 1);
    if (!frame) {
        return -TARGET_EFAULT;
    }

    /* Restore the register state. */
    if (set_mcontext(env, &frame->uc_mcontext, 1)) {
        unlock_user(frame, addr, 0);
        return -TARGET_EFAULT;
    }

    /* Reset the signal mask. */
    target_set = frame->uc_sigmask;
    target_to_host_sigset_internal(&blocked, &target_set);
    get_task_state(thread_cpu)->signal_mask = blocked;

    unlock_user(frame, addr, 0);
    return -TARGET_EJUSTRETURN;
}

/* ---- do_rt_sigreturn ---- */

long do_rt_sigreturn(CPUArchState *env)
{
    /* macOS does not use rt_sigreturn; use do_sigreturn instead. */
    return -TARGET_ENOSYS;
}

/* ---- handle_pending_signal ---- */

static void handle_pending_signal(CPUArchState *env, int sig,
                                  struct emulated_sigtable *k)
{
    CPUState *cpu = env_cpu(env);
    TaskState *ts = get_task_state(cpu);
    struct target_sigaction *sa;
    sigset_t set;
    abi_ulong handler;
    target_sigset_t target_old_set;

    k->pending = 0;

    sig = gdb_handlesig(cpu, sig, NULL, &k->info, sizeof(k->info));
    if (!sig) {
        sa = NULL;
        handler = TARGET_SIG_IGN;
    } else {
        sa = &sigact_table[sig - 1];
        handler = sa->_sa_handler;
    }

    if (do_strace) {
        print_taken_signal(sig, &k->info);
    }

    if (handler == TARGET_SIG_DFL) {
        /*
         * Default handler: ignore some signals.  The rest are job
         * control or fatal.
         */
        if (sig == TARGET_SIGTSTP || sig == TARGET_SIGTTIN ||
            sig == TARGET_SIGTTOU) {
            kill(getpid(), SIGSTOP);
        } else if (sig != TARGET_SIGCHLD && sig != TARGET_SIGURG &&
                   sig != TARGET_SIGINFO && sig != TARGET_SIGWINCH &&
                   sig != TARGET_SIGCONT) {
            dump_core_and_abort(sig);
        }
    } else if (handler == TARGET_SIG_IGN) {
        /* ignore sig */
    } else if (handler == TARGET_SIG_ERR) {
        dump_core_and_abort(sig);
    } else {
        /* Compute the blocked signals during handler execution. */
        sigset_t *blocked_set;

        target_to_host_sigset(&set, &sa->sa_mask);
        /*
         * SA_NODEFER indicates that the current signal should not be
         * blocked during the handler.
         */
        if (!(sa->sa_flags & TARGET_SA_NODEFER)) {
            sigaddset(&set, target_to_host_signal(sig));
        }

        /*
         * Save the previous blocked signal state to restore it at the
         * end of the signal execution (see do_sigreturn).
         */
        host_to_target_sigset_internal(&target_old_set, &ts->signal_mask);

        blocked_set = ts->in_sigsuspend ?
            &ts->sigsuspend_mask : &ts->signal_mask;
        sigorset(&ts->signal_mask, blocked_set, &set);
        ts->in_sigsuspend = false;
        sigprocmask(SIG_SETMASK, &ts->signal_mask, NULL);

        /* Prepare the stack frame of the virtual CPU. */
        setup_frame(sig, sa, &target_old_set, env);

        if (sa->sa_flags & TARGET_SA_RESETHAND) {
            sa->_sa_handler = TARGET_SIG_DFL;
        }
    }
}

/* ---- process_pending_signals ---- */

void process_pending_signals(CPUArchState *env)
{
    CPUState *cpu = env_cpu(env);
    int sig;
    sigset_t *blocked_set, set;
    struct emulated_sigtable *k;
    TaskState *ts = get_task_state(cpu);

    while (qatomic_read(&ts->signal_pending)) {
        sigfillset(&set);
        sigprocmask(SIG_SETMASK, &set, 0);

    restart_scan:
        sig = ts->sync_signal.pending;
        if (sig) {
            /*
             * Synchronous signals are forced by the emulated CPU in
             * some way.  If they are set to ignore, restore the default
             * handler (see FreeBSD trapsignal() / execsigs() behavior).
             */
            if (sigismember(&ts->signal_mask, target_to_host_signal(sig)) ||
                sigact_table[sig - 1]._sa_handler == TARGET_SIG_IGN) {
                sigdelset(&ts->signal_mask, target_to_host_signal(sig));
                sigact_table[sig - 1]._sa_handler = TARGET_SIG_DFL;
            }
            handle_pending_signal(env, sig, &ts->sync_signal);
            goto restart_scan;
        }

        k = ts->sigtab;
        for (sig = 1; sig <= TARGET_NSIG; sig++, k++) {
            blocked_set = ts->in_sigsuspend ?
                &ts->sigsuspend_mask : &ts->signal_mask;
            if (k->pending &&
                !sigismember(blocked_set, target_to_host_signal(sig))) {
                handle_pending_signal(env, sig, k);
                goto restart_scan;
            }
        }

        /*
         * Unblock signals and check once more.  Unblocking may cause us
         * to take another host signal, which will set signal_pending again.
         */
        qatomic_set(&ts->signal_pending, 0);
        ts->in_sigsuspend = false;
        set = ts->signal_mask;
        sigdelset(&set, SIGSEGV);
        sigdelset(&set, SIGBUS);
        sigprocmask(SIG_SETMASK, &set, 0);
    }
    ts->in_sigsuspend = false;
}

/* ---- cpu_loop_exit_sigsegv / cpu_loop_exit_sigbus ---- */

void cpu_loop_exit_sigsegv(CPUState *cpu, vaddr addr,
                           MMUAccessType access_type, bool maperr, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigsegv) {
        tcg_ops->record_sigsegv(cpu, addr, access_type, maperr, ra);
    }

    force_sig_fault(TARGET_SIGSEGV,
                    maperr ? TARGET_SEGV_MAPERR : TARGET_SEGV_ACCERR,
                    addr);
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

void cpu_loop_exit_sigbus(CPUState *cpu, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    const TCGCPUOps *tcg_ops = cpu->cc->tcg_ops;

    if (tcg_ops->record_sigbus) {
        tcg_ops->record_sigbus(cpu, addr, access_type, ra);
    }

    force_sig_fault(TARGET_SIGBUS, TARGET_BUS_ADRALN, addr);
    cpu->exception_index = EXCP_INTERRUPT;
    cpu_loop_exit_restore(cpu, ra);
}

/* ---- print_taken_signal (stub) ---- */

void print_taken_signal(int target_signum, const target_siginfo_t *tinfo)
{
    /* Stub: detailed signal printing not yet implemented. */
}

/* ---- do_bsd_sigprocmask ---- */

abi_long do_bsd_sigprocmask(void *cpu_env, int how,
                            abi_ulong arg_set, abi_ulong arg_oldset)
{
    TaskState *ts = get_task_state(thread_cpu);
    target_sigset_t target_set;
    sigset_t set, oset;

    if (arg_oldset) {
        target_sigset_t *p;
        host_to_target_sigset(&target_set, &ts->signal_mask);
        p = lock_user(VERIFY_WRITE, arg_oldset, sizeof(target_sigset_t), 0);
        if (!p) {
            return -TARGET_EFAULT;
        }
        *p = target_set;
        unlock_user(p, arg_oldset, sizeof(target_sigset_t));
    }

    if (arg_set) {
        target_sigset_t *p;
        p = lock_user(VERIFY_READ, arg_set, sizeof(target_sigset_t), 1);
        if (!p) {
            return -TARGET_EFAULT;
        }
        target_set = *p;
        unlock_user(p, arg_set, 0);

        target_to_host_sigset(&set, &target_set);

        switch (how) {
        case SIG_BLOCK:
            sigorset(&ts->signal_mask, &ts->signal_mask, &set);
            break;
        case SIG_UNBLOCK:
        {
            int i;
            for (i = 1; i < NSIG; i++) {
                if (sigismember(&set, i)) {
                    sigdelset(&ts->signal_mask, i);
                }
            }
            break;
        }
        case SIG_SETMASK:
            ts->signal_mask = set;
            break;
        default:
            return -TARGET_EINVAL;
        }

        /* Apply the new mask, keeping SIGSEGV/SIGBUS unblocked. */
        oset = ts->signal_mask;
        sigdelset(&oset, SIGSEGV);
        sigdelset(&oset, SIGBUS);
        sigprocmask(SIG_SETMASK, &oset, NULL);
    }

    return 0;
}
