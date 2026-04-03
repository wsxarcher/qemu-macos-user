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

/* macOS ARM64 signal frame structure */
struct target_sigframe {
    target_sigcontext uc_mcontext;
    target_sigset_t   uc_sigmask;
};

#endif /* TARGET_ARCH_SIGNAL_H */
