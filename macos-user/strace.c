/*
 * Strace support for macOS user mode
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"

bool do_strace;

void print_syscall(CPUState *cpu, int num,
                  abi_long arg1, abi_long arg2, abi_long arg3,
                  abi_long arg4, abi_long arg5, abi_long arg6)
{
    if (do_strace) {
        fprintf(stderr, "syscall[%d] = %ld, %ld, %ld, %ld, %ld, %ld\n",
                num, arg1, arg2, arg3, arg4, arg5, arg6);
    }
}

void print_syscall_ret(CPUState *cpu, int num, abi_long ret,
                       abi_long arg1, abi_long arg2, abi_long arg3,
                       abi_long arg4, abi_long arg5, abi_long arg6)
{
    if (do_strace) {
        fprintf(stderr, "syscall[%d] -> %ld\n", num, ret);
    }
}
