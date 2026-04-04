/*
 *  Mach trap implementation for macOS user mode
 *
 *  On macOS ARM64, Mach traps are invoked via SVC #0x80 with a negative
 *  value in X16.  The trap index is -X16.  These traps provide Mach IPC,
 *  virtual memory management, port operations, and timer services.
 *
 *  This file implements the minimum set of Mach traps needed for the
 *  system dynamic linker (dyld) to start and load shared libraries.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/guest-host.h"
#include "user/page-protection.h"
#include "exec/mmap-lock.h"
#include <mach/mach.h>
#include <mach/mach_time.h>

/* Functions not exposed in public headers but available at link time */
extern mach_port_t mach_reply_port(void);
extern mach_port_t thread_get_special_reply_port(void);

/* Mach trap numbers (negated x16 values) */
#define MACH_TRAP_ABSTIME                       (-3)
#define MACH_TRAP_CONTTIME                      (-4)
#define MACH_TRAP_VM_ALLOCATE                   (-10)
#define MACH_TRAP_VM_PURGABLE_CONTROL           (-11)
#define MACH_TRAP_VM_DEALLOCATE                 (-12)
#define MACH_TRAP_VM_PROTECT                    (-14)
#define MACH_TRAP_VM_MAP                        (-15)
#define MACH_TRAP_PORT_ALLOCATE                 (-16)
#define MACH_TRAP_PORT_DEALLOCATE               (-18)
#define MACH_TRAP_PORT_MOD_REFS                 (-19)
#define MACH_TRAP_PORT_MOVE_MEMBER              (-20)
#define MACH_TRAP_PORT_INSERT_RIGHT             (-21)
#define MACH_TRAP_PORT_INSERT_MEMBER            (-22)
#define MACH_TRAP_PORT_EXTRACT_MEMBER           (-23)
#define MACH_TRAP_PORT_CONSTRUCT                (-24)
#define MACH_TRAP_PORT_DESTRUCT                 (-25)
#define MACH_TRAP_REPLY_PORT                    (-26)
#define MACH_TRAP_THREAD_SELF                   (-27)
#define MACH_TRAP_TASK_SELF                     (-28)
#define MACH_TRAP_HOST_SELF                     (-29)
#define MACH_TRAP_MACH_MSG                      (-31)
#define MACH_TRAP_MACH_MSG_OVERWRITE            (-32)
#define MACH_TRAP_SEMAPHORE_SIGNAL              (-33)
#define MACH_TRAP_SEMAPHORE_SIGNAL_ALL          (-34)
#define MACH_TRAP_SEMAPHORE_WAIT                (-36)
#define MACH_TRAP_MACH_MSG2                     (-47)
#define MACH_TRAP_THREAD_GET_SPECIAL_REPLY_PORT (-50)
#define MACH_TRAP_SWTCH_PRI                     (-59)
#define MACH_TRAP_SWTCH                         (-60)
#define MACH_TRAP_SYSCALL_THREAD_SWITCH         (-61)
#define MACH_TRAP_PORT_TYPE                     (-76)
#define MACH_TRAP_TIMEBASE_INFO                 (-89)
#define MACH_TRAP_WAIT_UNTIL                    (-90)
#define MACH_TRAP_MK_TIMER_CREATE               (-91)
#define MACH_TRAP_MK_TIMER_DESTROY              (-92)
#define MACH_TRAP_MK_TIMER_ARM                  (-93)
#define MACH_TRAP_MK_TIMER_CANCEL               (-94)

/*
 * We use real Mach ports from the host where possible.
 * This lets us forward Mach IPC (mach_msg) to the host kernel
 * for operations that dyld needs.
 */

abi_long do_mach_trap(void *cpu_env, int trap_num, abi_long arg1,
                      abi_long arg2, abi_long arg3, abi_long arg4,
                      abi_long arg5, abi_long arg6, abi_long arg7,
                      abi_long arg8)
{
    abi_long ret = 0;

    if (do_strace && trap_num != MACH_TRAP_ABSTIME &&
        trap_num != MACH_TRAP_CONTTIME) {
        fprintf(stderr, "mach_trap[%d] = %lx, %lx, %lx, %lx, %lx\n",
                trap_num, (long)arg1, (long)arg2, (long)arg3,
                (long)arg4, (long)arg5);
    }

    switch (trap_num) {

    case MACH_TRAP_ABSTIME:
        /* mach_absolute_time() — return host absolute time */
        ret = (abi_long)mach_absolute_time();
        break;

    case MACH_TRAP_CONTTIME:
        /* mach_continuous_time() — return host continuous time */
        ret = (abi_long)mach_continuous_time();
        break;

    case MACH_TRAP_TASK_SELF:
        /* task_self_trap() — return host task port */
        ret = (abi_long)mach_task_self();
        break;

    case MACH_TRAP_THREAD_SELF:
        /* thread_self_trap() — return host thread port */
        ret = (abi_long)mach_thread_self();
        break;

    case MACH_TRAP_REPLY_PORT:
        /* mach_reply_port() — allocate a reply port */
        ret = (abi_long)mach_reply_port();
        break;

    case MACH_TRAP_HOST_SELF:
        /* host_self_trap() — return host port */
        ret = (abi_long)mach_host_self();
        break;

    case MACH_TRAP_THREAD_GET_SPECIAL_REPLY_PORT:
        /* thread_get_special_reply_port() */
        ret = (abi_long)thread_get_special_reply_port();
        break;

    case MACH_TRAP_VM_ALLOCATE:
        /*
         * _kernelrpc_mach_vm_allocate_trap(target, address, size, flags)
         *   arg1 = target task port
         *   arg2 = pointer to address (in/out)
         *   arg3 = size
         *   arg4 = flags (VM_FLAGS_ANYWHERE, etc.)
         */
        {
            mach_vm_address_t addr = 0;
            if (arg2) {
                memcpy(&addr, g2h_untagged(arg2), sizeof(addr));
            }
            int flags = (int)arg4;
            int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
            abi_ulong guest_start;

            if (flags & VM_FLAGS_ANYWHERE) {
                guest_start = 0;
            } else {
                guest_start = (abi_ulong)addr;
                mflags |= MAP_FIXED;
            }

            abi_long result = target_mmap(guest_start, (abi_ulong)arg3,
                                          PROT_READ | PROT_WRITE,
                                          mflags, -1, 0);
            if (result < 0) {
                ret = KERN_NO_SPACE;
            } else {
                addr = (mach_vm_address_t)result;
                if (arg2) {
                    memcpy(g2h_untagged(arg2), &addr, sizeof(addr));
                }
                mmap_lock();
                page_set_flags(result, result + arg3 - 1,
                               PAGE_VALID | PAGE_READ | PAGE_WRITE, ~0);
                mmap_unlock();
                ret = KERN_SUCCESS;
            }
        }
        break;

    case MACH_TRAP_VM_DEALLOCATE:
        /*
         * _kernelrpc_mach_vm_deallocate_trap(target, address, size)
         */
        {
            void *addr = g2h_untagged(arg2);
            size_t size = (size_t)arg3;
            if (munmap(addr, size) == 0) {
                mmap_lock();
                page_set_flags((abi_ulong)arg2,
                               (abi_ulong)arg2 + size - 1, 0, ~0);
                mmap_unlock();
                ret = KERN_SUCCESS;
            } else {
                ret = KERN_INVALID_ADDRESS;
            }
        }
        break;

    case MACH_TRAP_VM_PROTECT:
        /*
         * _kernelrpc_mach_vm_protect_trap(target, addr, size, set_max, prot)
         */
        {
            void *addr = g2h_untagged(arg2);
            size_t size = (size_t)arg3;
            int prot = (int)arg5;
            int host_prot = 0;

            if (prot & VM_PROT_READ)    host_prot |= PROT_READ;
            if (prot & VM_PROT_WRITE)   host_prot |= PROT_WRITE;
            if (prot & VM_PROT_EXECUTE) host_prot |= PROT_EXEC;

            if (mprotect(addr, size, host_prot) == 0) {
                int qemu_flags = PAGE_VALID;
                if (host_prot & PROT_READ)  qemu_flags |= PAGE_READ;
                if (host_prot & PROT_WRITE) qemu_flags |= PAGE_WRITE;
                if (host_prot & PROT_EXEC)  qemu_flags |= PAGE_EXEC;
                mmap_lock();
                page_set_flags((abi_ulong)arg2,
                               (abi_ulong)arg2 + size - 1,
                               qemu_flags, ~0);
                mmap_unlock();
                ret = KERN_SUCCESS;
            } else {
                ret = KERN_PROTECTION_FAILURE;
            }
        }
        break;

    case MACH_TRAP_VM_MAP:
        /*
         * _kernelrpc_mach_vm_map_trap(target, addr, size, mask, flags, cur_prot)
         * Simplified: allocate anonymous memory like vm_allocate but with
         * protection control.
         */
        {
            mach_vm_address_t addr = 0;
            if (arg2) {
                memcpy(&addr, g2h_untagged(arg2), sizeof(addr));
            }
            size_t size = (size_t)arg3;
            int flags = (int)arg5;
            int cur_prot = (int)arg6;

            int host_prot = 0;
            if (cur_prot & VM_PROT_READ)    host_prot |= PROT_READ;
            if (cur_prot & VM_PROT_WRITE)   host_prot |= PROT_WRITE;
            if (cur_prot & VM_PROT_EXECUTE) host_prot |= PROT_EXEC;

            int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
            abi_ulong guest_start;
            if (flags & VM_FLAGS_ANYWHERE) {
                guest_start = 0;
            } else {
                guest_start = (abi_ulong)addr;
                mflags |= MAP_FIXED;
            }

            abi_long result = target_mmap(guest_start, size,
                                          host_prot, mflags, -1, 0);
            if (result < 0) {
                ret = KERN_NO_SPACE;
            } else {
                addr = (mach_vm_address_t)result;
                if (arg2) {
                    memcpy(g2h_untagged(arg2), &addr, sizeof(addr));
                }
                int qemu_flags = PAGE_VALID;
                if (host_prot & PROT_READ)  qemu_flags |= PAGE_READ;
                if (host_prot & PROT_WRITE) qemu_flags |= PAGE_WRITE;
                if (host_prot & PROT_EXEC)  qemu_flags |= PAGE_EXEC;
                mmap_lock();
                page_set_flags(result, result + size - 1,
                               qemu_flags, ~0);
                mmap_unlock();
                ret = KERN_SUCCESS;
            }
        }
        break;

    case MACH_TRAP_PORT_ALLOCATE:
    case MACH_TRAP_PORT_DEALLOCATE:
    case MACH_TRAP_PORT_MOD_REFS:
    case MACH_TRAP_PORT_MOVE_MEMBER:
    case MACH_TRAP_PORT_INSERT_RIGHT:
    case MACH_TRAP_PORT_INSERT_MEMBER:
    case MACH_TRAP_PORT_EXTRACT_MEMBER:
    case MACH_TRAP_PORT_CONSTRUCT:
    case MACH_TRAP_PORT_DESTRUCT:
    case MACH_TRAP_PORT_TYPE:
        /*
         * Port management traps — forward to host kernel.
         * dyld uses these for Mach IPC setup.
         */
        {
            /*
             * These are complex port operations. For now, forward the
             * most common ones to the host and stub the rest.
             */
            if (trap_num == MACH_TRAP_PORT_DEALLOCATE) {
                ret = mach_port_deallocate(mach_task_self(),
                                           (mach_port_name_t)arg2);
            } else if (trap_num == MACH_TRAP_PORT_ALLOCATE) {
                mach_port_name_t name;
                ret = mach_port_allocate(mach_task_self(),
                                         (mach_port_right_t)arg3,
                                         &name);
                if (ret == KERN_SUCCESS && arg3) {
                    memcpy(g2h_untagged(arg3), &name, sizeof(name));
                }
            } else if (trap_num == MACH_TRAP_PORT_MOD_REFS) {
                ret = mach_port_mod_refs(mach_task_self(),
                                         (mach_port_name_t)arg2,
                                         (mach_port_right_t)arg3,
                                         (mach_port_delta_t)arg4);
            } else if (trap_num == MACH_TRAP_PORT_INSERT_RIGHT) {
                ret = mach_port_insert_right(mach_task_self(),
                                             (mach_port_name_t)arg2,
                                             (mach_port_t)arg3,
                                             (mach_msg_type_name_t)arg4);
            } else {
                ret = KERN_SUCCESS;
            }
        }
        break;

    case MACH_TRAP_MACH_MSG:
    case MACH_TRAP_MACH_MSG_OVERWRITE:
        /*
         * mach_msg_trap — the core Mach IPC primitive.
         * Forward directly to host kernel.
         *
         * arg1 = msg pointer, arg2 = option, arg3 = send_size,
         * arg4 = rcv_size, arg5 = rcv_name, arg6 = timeout, arg7 = notify
         */
        {
            mach_msg_header_t *msg = NULL;
            if (arg1) {
                msg = (mach_msg_header_t *)g2h_untagged(arg1);
            }
            ret = mach_msg(msg,
                           (mach_msg_option_t)arg2,
                           (mach_msg_size_t)arg3,
                           (mach_msg_size_t)arg4,
                           (mach_port_name_t)arg5,
                           (mach_msg_timeout_t)arg6,
                           (mach_port_name_t)arg7);
        }
        break;

    case MACH_TRAP_MACH_MSG2:
        /*
         * mach_msg2_trap — newer IPC variant.
         * For now, treat like mach_msg with the data pointer in arg1.
         */
        {
            mach_msg_header_t *msg = NULL;
            if (arg1) {
                msg = (mach_msg_header_t *)g2h_untagged(arg1);
            }
            ret = mach_msg(msg,
                           (mach_msg_option_t)arg2,
                           (mach_msg_size_t)arg3,
                           (mach_msg_size_t)arg4,
                           (mach_port_name_t)arg5,
                           (mach_msg_timeout_t)arg6,
                           (mach_port_name_t)arg7);
        }
        break;

    case MACH_TRAP_TIMEBASE_INFO:
        /* mach_timebase_info_trap(info_ptr) */
        {
            if (arg1) {
                mach_timebase_info_data_t info;
                mach_timebase_info(&info);
                memcpy(g2h_untagged(arg1), &info, sizeof(info));
            }
            ret = KERN_SUCCESS;
        }
        break;

    case MACH_TRAP_WAIT_UNTIL:
        /* mach_wait_until(deadline) — sleep until absolute time */
        ret = mach_wait_until((uint64_t)arg1);
        break;

    case MACH_TRAP_SWTCH_PRI:
    case MACH_TRAP_SWTCH:
    case MACH_TRAP_SYSCALL_THREAD_SWITCH:
        /* Thread yield operations — just yield */
        sched_yield();
        ret = KERN_SUCCESS;
        break;

    case MACH_TRAP_SEMAPHORE_SIGNAL:
    case MACH_TRAP_SEMAPHORE_SIGNAL_ALL:
    case MACH_TRAP_SEMAPHORE_WAIT:
        /* Semaphore operations — forward to host */
        if (trap_num == MACH_TRAP_SEMAPHORE_SIGNAL) {
            ret = semaphore_signal((semaphore_t)arg1);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_SIGNAL_ALL) {
            ret = semaphore_signal_all((semaphore_t)arg1);
        } else {
            ret = semaphore_wait((semaphore_t)arg1);
        }
        break;

    case MACH_TRAP_MK_TIMER_CREATE:
    case MACH_TRAP_MK_TIMER_DESTROY:
    case MACH_TRAP_MK_TIMER_ARM:
    case MACH_TRAP_MK_TIMER_CANCEL:
        /* Timer operations — stub for now */
        ret = KERN_SUCCESS;
        break;

    case MACH_TRAP_VM_PURGABLE_CONTROL:
        /* vm_purgable_control — stub */
        ret = KERN_SUCCESS;
        break;

    default:
        fprintf(stderr, "Unhandled Mach trap %d (x16=0x%x)\n",
                 trap_num, (unsigned)trap_num);
        ret = KERN_FAILURE;
        break;
    }

    if (do_strace && trap_num != MACH_TRAP_ABSTIME &&
        trap_num != MACH_TRAP_CONTTIME) {
        fprintf(stderr, "mach_trap[%d] -> %ld\n", trap_num, (long)ret);
    }

    return ret;
}
