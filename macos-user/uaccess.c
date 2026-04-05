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
    }
    abort();
}
