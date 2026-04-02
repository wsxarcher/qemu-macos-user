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

/* Signal stack */
typedef abi_ulong target_sigset_t;

#endif /* TARGET_ARCH_SIGNAL_H */
