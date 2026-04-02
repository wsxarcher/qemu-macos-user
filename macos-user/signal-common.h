/*
 * Common signal handling definitions
 */

#ifndef SIGNAL_COMMON_H
#define SIGNAL_COMMON_H

#include "qemu/osdep.h"
#include "qemu.h"

void host_signal_handler(int host_signum, siginfo_t *info, void *puc);
void setup_frame(int sig, struct target_sigaction *ka,
                 target_sigset_t *set, CPUArchState *env);

#define SI_KERNEL 0x80

/* Get task state from CPU */
static inline TaskState *get_task_state(CPUState *cpu)
{
    return (TaskState *)cpu->opaque;
}

#endif /* SIGNAL_COMMON_H */
