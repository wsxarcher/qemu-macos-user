/*
 * User memory access helpers
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/guest-host.h"

struct envlist *envlist;
const char *cpu_model;

/* Flag tables (stubs) */
const void *fcntl_flags_tbl = NULL;
const void *mmap_flags_tbl = NULL;

void *lock_user(int type, abi_ulong guest_addr, size_t len, bool copy)
{
    if (!guest_addr) {
        return NULL;
    }
    return g2h_untagged(guest_addr);
}

void unlock_user(void *host_ptr, abi_ulong guest_addr, size_t len)
{
    /* Nothing to do for direct access */
}

void *lock_user_string(abi_ulong guest_addr)
{
    if (!guest_addr) {
        return NULL;
    }
    return g2h_untagged(guest_addr);
}

void dump_core_and_abort(int sig)
{
    CPUState *cpu = thread_cpu;
    if (cpu) {
        CPUArchState *env = cpu_env(cpu);
        fprintf(stderr, "dump_core_and_abort: sig=%d, guest PC=0x%lx\n",
                sig, (unsigned long)env->pc);
        cpu_dump_state(cpu, stderr, 0);

        /* Walk guest frame pointer chain for backtrace */
        fprintf(stderr, "Guest backtrace:\n");
        fprintf(stderr, "  [0] PC=0x%lx\n", (unsigned long)env->pc);
        fprintf(stderr, "  [1] LR=0x%lx\n", (unsigned long)env->xregs[30]);
        uint64_t fp = env->xregs[29];
        for (int i = 2; i < 32 && fp != 0; i++) {
            uint64_t *frame = g2h_untagged(fp);
            uint64_t saved_fp = frame[0];
            uint64_t saved_lr = frame[1];
            fprintf(stderr, "  [%d] 0x%lx\n", i, (unsigned long)saved_lr);
            if (saved_fp <= fp) break;
            fp = saved_fp;
        }
    }
    abort();
}
