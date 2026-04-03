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
     * macOS AArch64 signal handler calling convention:
     *   X0 = signal number
     *   X1 = pointer to siginfo  (not yet passed; future work)
     *   X2 = pointer to ucontext (not yet passed; future work)
     *   SP = frame address
     *   PC = handler address
     *   LR = signal trampoline return address (TODO: set up trampoline)
     */
    env->xregs[0] = sig;
    env->xregs[31] = frame_addr;
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
