/*
 * ARM AArch64 signal handling for macOS user mode
 *
 * Architecture-specific signal helpers called from macos-user/signal.c.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "target_arch_signal.h"
#include "signal-common.h"

/* Set up the signal trampoline arguments (registers) for the handler. */
abi_long set_sigtramp_args(CPUARMState *env, int sig,
                           struct target_sigframe *frame,
                           abi_ulong frame_addr,
                           struct target_sigaction *ka)
{
    /*
     * macOS AArch64 signal delivery.
     *
     * On real macOS the kernel calls sa_tramp (__sigtramp) which
     * then calls the handler and sigreturn.  We instead run the
     * handler directly and use a persistent sigreturn trampoline
     * page (allocated during signal_init) as the return address.
     *
     * We save frame_addr in X28 (callee-saved per AAPCS64, so the
     * handler must preserve it).  The trampoline copies X28 to X0
     * (the sigreturn argument) then invokes the sigreturn syscall.
     *
     * Registers on entry to handler:
     *   X0  = signal number
     *   X28 = frame address (for sigreturn trampoline)
     *   LR  = sigreturn trampoline address
     *   SP  = below signal frame (16-byte aligned)
     *   PC  = handler address
     */

    abi_ulong tramp_addr = get_sigreturn_trampoline_addr();

    env->xregs[0] = sig;
    env->xregs[28] = frame_addr;        /* saved for sigreturn trampoline */
    env->xregs[30] = tramp_addr;        /* LR = sigreturn trampoline */
    env->xregs[31] = frame_addr & ~15;  /* SP aligned at frame */
    env->pc = ka->_sa_handler;
    return 0;
}

/* Write architecture-specific context into the signal frame. */
abi_long setup_sigframe_arch(CPUARMState *env, abi_ulong frame_addr,
                             struct target_sigframe *frame, int flags)
{
    int i;

    frame->uc_mcontext.fault_address = 0;
    for (i = 0; i < 31; i++) {
        frame->uc_mcontext.regs[i] = env->xregs[i];
    }
    frame->uc_mcontext.sp = env->xregs[31];
    frame->uc_mcontext.pc = env->pc;
    frame->uc_mcontext.pstate = pstate_read(env);
    return 0;
}

/* Restore register state from the signal frame's mcontext. */
abi_long set_mcontext(CPUARMState *env, target_sigcontext *mcp, int srflag)
{
    int i;

    for (i = 0; i < 31; i++) {
        env->xregs[i] = mcp->regs[i];
    }
    env->xregs[31] = mcp->sp;
    env->pc = mcp->pc;
    pstate_write(env, mcp->pstate);
    return 0;
}

/*
 * Get the ucontext address from the signal frame for sigreturn.
 * For our simple frame layout the frame address itself contains the context.
 */
abi_long get_ucontext_sigreturn(CPUARMState *env, abi_ulong target_sf,
                                abi_ulong *target_ucontext)
{
    *target_ucontext = target_sf;
    return 0;
}
