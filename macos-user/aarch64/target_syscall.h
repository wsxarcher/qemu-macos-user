/*
 * ARM AArch64 syscall handling for macOS
 */

#ifndef TARGET_SYSCALL_H
#define TARGET_SYSCALL_H

/* ARM64 specific syscall handling */

struct target_pt_regs {
    abi_ulong regs[31];
    abi_ulong sp;
    abi_ulong pc;
    abi_ulong pstate;
};

#define UNAME_MACHINE "arm64"
#define UNAME_MINIMUM_RELEASE "14.0"

#define TARGET_MCL_CURRENT  0x01
#define TARGET_MCL_FUTURE   0x02

#endif /* TARGET_SYSCALL_H */
