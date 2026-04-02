/*
 * ARM AArch64 definitions for macOS user mode
 */

#ifndef TARGET_ARCH_H
#define TARGET_ARCH_H

#include "qemu/osdep.h"

/* Target register set structures */
struct target_pt_regs {
    abi_ulong regs[31];
    abi_ulong sp;
    abi_ulong pc;
    abi_ulong pstate;
};

#define TARGET_FREEBSD_NR_syscall    0
#define TARGET_FREEBSD_NR___syscall  198

#if defined(__FreeBSD__)
#define TARGET_HW_MACHINE       "arm64"
#define TARGET_HW_MACHINE_ARCH  "aarch64"
#endif

#endif /* TARGET_ARCH_H */
