/* ARM AArch64 signal definitions for macOS */

#ifndef TARGET_ARCH_SIGNAL_H
#define TARGET_ARCH_SIGNAL_H

#include "cpu.h"

/* Signal context structure */
typedef struct target_sigcontext {
    uint64_t fault_address;
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} target_sigcontext;

#define TARGET_SIGCONTEXT_PC(sc) ((sc)->pc)
#define TARGET_SIGCONTEXT_SP(sc) ((sc)->sp)

/* macOS target_sigset_t is a simple abi_ulong bitmask */
typedef abi_ulong target_sigset_t;

/* AArch64 signal stack alignment */
#define TARGET_SIGSTACK_ALIGN 16

/* Get stack pointer from CPU state */
static inline abi_ulong get_sp_from_cpustate(CPUARMState *state)
{
    return state->xregs[31];
}

/*
 * The structures a macOS arm64 SA_SIGINFO handler is called with:
 *
 *   void handler(int sig, siginfo_t *info, void *uctx)
 *
 * These mirror <sys/signal.h>, <sys/_types/_ucontext.h> and
 * <mach/arm/_structs.h>.  uc_mcontext is a *pointer* to the mcontext,
 * so the frame carries both and links them together.
 */
typedef struct target_darwin_siginfo {
    int32_t   si_signo;
    int32_t   si_errno;
    int32_t   si_code;
    int32_t   si_pid;
    uint32_t  si_uid;
    int32_t   si_status;
    uint64_t  si_addr;
    uint64_t  si_value;
    int64_t   si_band;
    uint64_t  __pad[7];
} target_darwin_siginfo;

typedef struct target_arm_exception_state64 {
    uint64_t far;
    uint32_t esr;
    int32_t  exception;
} target_arm_exception_state64;

typedef struct target_arm_thread_state64 {
    uint64_t x[29];
    uint64_t fp;
    uint64_t lr;
    uint64_t sp;
    uint64_t pc;
    uint32_t cpsr;
    uint32_t pad;
} target_arm_thread_state64;

typedef struct target_arm_neon_state64 {
    __uint128_t v[32];
    uint32_t fpsr;
    uint32_t fpcr;
} target_arm_neon_state64;

typedef struct target_mcontext64 {
    target_arm_exception_state64 es;
    target_arm_thread_state64    ss;
    target_arm_neon_state64      ns;
} target_mcontext64;

typedef struct target_sigaltstack_t {
    uint64_t ss_sp;
    uint64_t ss_size;
    int32_t  ss_flags;
    int32_t  pad;
} target_sigaltstack_t;

typedef struct target_ucontext {
    int32_t              uc_onstack;
    uint32_t             uc_sigmask;   /* __darwin_sigset_t */
    target_sigaltstack_t uc_stack;
    uint64_t             uc_link;
    uint64_t             uc_mcsize;
    uint64_t             uc_mcontext;  /* pointer to target_mcontext64 */
} target_ucontext;

/*
 * macOS ARM64 signal frame.
 *
 * uc/mc/si are what the guest handler sees; uc_mcontext (the flat
 * sigcontext) is what do_sigreturn() restores from.
 */
struct target_sigframe {
    target_ucontext   uc;
    target_mcontext64 mc;
    target_darwin_siginfo si;
    target_sigcontext uc_mcontext;
    target_sigset_t   uc_sigmask;
};

#endif /* TARGET_ARCH_SIGNAL_H */
