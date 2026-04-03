/*
 * Common signal handling definitions
 */

#ifndef SIGNAL_COMMON_H
#define SIGNAL_COMMON_H

#include "qemu/osdep.h"
#include "target_arch_signal.h"
#include "qemu.h"

void host_signal_handler(int host_signum, siginfo_t *info, void *puc);
void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUArchState *env);

#define SI_KERNEL 0x80

/*
 * Internal si_code type markers stored in the top 8 bits of si_code
 * between host_to_target_siginfo_noswap() and tswap_siginfo().
 * They are stripped before writing to guest memory.
 */
#define QEMU_SI_NOINFO   0
#define QEMU_SI_FAULT    1
#define QEMU_SI_TIMER    2
#define QEMU_SI_MESGQ    3
#define QEMU_SI_POLL     4

#endif /* SIGNAL_COMMON_H */
