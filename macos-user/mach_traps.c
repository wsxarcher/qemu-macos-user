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
#include <mach/clock.h>

/* Functions not exposed in public headers but available at link time */
extern mach_port_t mach_reply_port(void);
extern mach_port_t thread_get_special_reply_port(void);

/*
 * Raw mach_msg2_trap via inline assembly.
 * On modern macOS, the old mach_msg_trap (-31) is killed by message
 * filters.  All Mach IPC must go through mach_msg2_trap (-47).
 */
static kern_return_t host_mach_msg2_trap(
    void *data, uint64_t options,
    uint64_t msgh_bits_and_send_size,
    uint64_t msgh_remote_and_local_port,
    uint64_t msgh_voucher_and_id,
    uint64_t desc_count_and_rcv_name,
    uint64_t rcv_size_and_priority,
    uint64_t timeout)
{
    register uint64_t x0 __asm__("x0") = (uint64_t)data;
    register uint64_t x1 __asm__("x1") = options;
    register uint64_t x2 __asm__("x2") = msgh_bits_and_send_size;
    register uint64_t x3 __asm__("x3") = msgh_remote_and_local_port;
    register uint64_t x4 __asm__("x4") = msgh_voucher_and_id;
    register uint64_t x5 __asm__("x5") = desc_count_and_rcv_name;
    register uint64_t x6 __asm__("x6") = rcv_size_and_priority;
    register uint64_t x7 __asm__("x7") = timeout;
    register int x16 __asm__("x16") = -47;

    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4),
          "r"(x5), "r"(x6), "r"(x7), "r"(x16)
        : "memory", "cc"
    );
    return (kern_return_t)x0;
}

/*
 * Handle well-known MIG messages in-process.
 *
 * Modern macOS message filters SIGKILL processes that send raw Mach
 * messages to privileged ports.  We intercept common MIG RPCs and
 * service them using the host's library functions, then pack the
 * reply directly into the caller's buffer.
 *
 * Returns true if the message was handled, with *ret_out set.
 */
static bool handle_mig_message(void *buf, uint64_t options,
                               uint64_t bits_and_size,
                               kern_return_t *ret_out)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    if (!hdr) {
        return false;
    }

    /* Only intercept SEND+RECEIVE (RPC) messages */
    if ((options & 0x3) != 0x3) {
        return false;
    }

    mach_msg_id_t msg_id = hdr->msgh_id;

    switch (msg_id) {
    case 200: {
        /* host_info — MIG subsystem host, routine 0.
         * Request:  header(24) + NDR(8) + flavor(4) + count(4) = 40
         * Reply:    header(24) + NDR(8) + retval(4) + count(4) + data(var)
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            int flavor;
            mach_msg_type_number_t count;
        } *req = buf;

        int flavor = req->flavor;
        mach_msg_type_number_t count = req->count;

        /* Enough space for the largest host_info_t */
        int info_buf[HOST_BASIC_INFO_COUNT + 16];
        kern_return_t kr = host_info(mach_host_self(), flavor,
                                     (host_info_t)info_buf, &count);

        /* Pack MIG reply into the same buffer */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            mach_msg_type_number_t count;
            int data[64];
        } *reply = buf;

        reply->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(mach_msg_header_t) +
                               sizeof(NDR_record_t) + 8 +
                               count * sizeof(int);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;
        reply->NDR = NDR_record;
        reply->retval = kr;
        reply->count = count;
        if (count > 0 && count <= 64) {
            memcpy(reply->data, info_buf, count * sizeof(int));
        }

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 206: {
        /*
         * host_get_clock_service — MIG subsystem host, routine 6.
         * Request:  header(24) + NDR(8) + clock_id(4) = 36
         * Reply:    header(24) + body(4) + port_descriptor(12) = 40
         *
         * The reply is a COMPLEX message carrying a port right.
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            clock_id_t clock_id;
        } *req = buf;

        clock_serv_t clock_serv = MACH_PORT_NULL;
        kern_return_t kr = host_get_clock_service(mach_host_self(),
                                                  req->clock_id,
                                                  &clock_serv);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t clock_port;
        } *reply = buf;

        reply->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                               MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 306 */
        reply->body.msgh_descriptor_count = 1;
        reply->clock_port.name = clock_serv;
        reply->clock_port.disposition = MACH_MSG_TYPE_MOVE_SEND;
        reply->clock_port.type = MACH_MSG_PORT_DESCRIPTOR;

        *ret_out = kr;
        return true;
    }
    case 1000: {
        /*
         * clock_get_time — MIG subsystem clock, routine 0.
         * Request:  header(24) only
         * Reply:    header(24) + NDR(8) + retval(4) + mach_timespec(8) = 44
         */
        mach_port_t clock_port = hdr->msgh_remote_port;
        mach_timespec_t cur_time;
        kern_return_t kr = clock_get_time(clock_port, &cur_time);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            mach_timespec_t cur_time;
        } *reply = buf;

        reply->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 1100 */
        reply->NDR = NDR_record;
        reply->retval = kr;
        reply->cur_time = cur_time;

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 3418: {
        /*
         * semaphore_create — MIG subsystem task, routine 18.
         * Request:  header(24) + NDR(8) + policy(4) + value(4) = 40
         * Reply:    header(24) + body(4) + port_descriptor(12) = 40
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            int policy;
            int value;
        } *req = buf;

        semaphore_t sem = MACH_PORT_NULL;
        kern_return_t kr = semaphore_create(mach_task_self(),
                                            &sem,
                                            req->policy,
                                            req->value);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t semaphore;
        } *reply = buf;

        reply->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                               MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 3518 */
        reply->body.msgh_descriptor_count = 1;
        reply->semaphore.name = sem;
        reply->semaphore.disposition = MACH_MSG_TYPE_MOVE_SEND;
        reply->semaphore.type = MACH_MSG_PORT_DESCRIPTOR;

        *ret_out = kr;
        return true;
    }
    case 4811: {
        /*
         * mach_vm_map — MIG subsystem mach_vm, routine 11.
         * Maps memory into the task's address space.  We translate this
         * into a guest mmap via target_mmap.
         *
         * Request (COMPLEX): header(24) + body(4) + port_desc(12) +
         *   NDR(8) + address(8) + size(8) + mask(8) + flags(4) +
         *   offset(8) + copy(4) + cur_prot(4) + max_prot(4) +
         *   inherit(4) = 100
         * Reply: header(24) + NDR(8) + retcode(4) + address(8) = 44
         */        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t object;
            NDR_record_t NDR;
            uint64_t address;
            uint64_t size;
            uint64_t mask;
            int flags;
            uint64_t offset;
            int copy;
            int cur_protection;
            int max_protection;
            int inheritance;
        } *req = buf;

        uint64_t addr = req->address;
        uint64_t size = req->size;
        int flags = req->flags;
        int cur_prot = req->cur_protection;

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
            /*
             * Only use MAP_FIXED if VM_FLAGS_OVERWRITE (0x4000) is set.
             * Without it, the kernel refuses to clobber existing mappings.
             * We emulate this: try to map at the address but don't force it.
             */
            if (flags & 0x4000) {
                mflags |= MAP_FIXED;
            }
        }

        abi_long result;

        /*
         * For PROT_NONE reservations at a fixed address (no OVERWRITE),
         * the guest is declaring an address-space reservation.  Check
         * that the range doesn't overlap existing mappings and simply
         * record it in the guest page table without allocating real
         * host memory.  Sub-regions will be mapped later with
         * mprotect / vm_map as needed.
         */
        if (host_prot == PROT_NONE && guest_start != 0 &&
            !(flags & 0x4000)) {
            /* Just mark pages valid with no permissions */
            mmap_lock();
            page_set_flags(guest_start, guest_start + size - 1,
                           PAGE_VALID, ~0);
            mmap_unlock();
            result = guest_start;
        } else {
            result = target_mmap(guest_start, size,
                                 host_prot, mflags, -1, 0);

            /*
             * If we didn't use MAP_FIXED and got a different address than
             * requested, return KERN_NO_SPACE (the region was occupied).
             */
            if (result >= 0 && guest_start != 0 &&
                !(mflags & MAP_FIXED) &&
                (abi_ulong)result != guest_start) {
                target_munmap(result, size);
                result = -1;
            }
        }

        if (do_strace) {
            fprintf(stderr, "  MIG mach_vm_map: addr=0x%llx size=0x%llx "
                    "flags=0x%x prot=%d → result=0x%llx\n",
                    (unsigned long long)addr, (unsigned long long)size,
                    flags, cur_prot, (unsigned long long)result);
        }

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            uint64_t address;
        } *reply = buf;

        kern_return_t kr;
        if (result < 0) {
            kr = KERN_NO_SPACE;
            reply->address = 0;
        } else {
            kr = KERN_SUCCESS;
            reply->address = (uint64_t)result;
        }

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 4911 */
        reply->NDR = NDR_record;
        reply->retval = kr;

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 8000: {
        /*
         * task_restartable_ranges_register — private MIG.
         * Used by ObjC runtime to register restartable code ranges
         * for thread-safe operations.  Not critical for correctness
         * in our single-threaded emulator; return KERN_SUCCESS.
         *
         * Reply: header(24) + NDR(8) + retval(4) = 36
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
        } *reply = buf;

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 8100 */
        reply->NDR = NDR_record;
        reply->retval = KERN_SUCCESS;

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 8001: {
        /*
         * task_restartable_ranges_synchronize — private MIG.
         * Synchronizes restartable ranges with the kernel.
         * Like 8000, not critical; return success.
         *
         * Reply: header(24) + NDR(8) + retval(4) = 36
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
        } *reply = buf;

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 8101 */
        reply->NDR = NDR_record;
        reply->retval = KERN_SUCCESS;

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 3409: {
        /*
         * task_get_special_port — MIG subsystem task, routine 9.
         * Request:  header(24) + NDR(8) + which_port(4) = 36
         * Reply:    header(24) + body(4) + port_descriptor(12) = 40
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            int which_port;
        } *req = buf;

        mach_port_t port = MACH_PORT_NULL;
        kern_return_t kr = task_get_special_port(mach_task_self(),
                                                 req->which_port,
                                                 &port);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t special_port;
        } *reply = buf;

        reply->hdr.msgh_bits = MACH_MSGH_BITS_COMPLEX |
                               MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 3509 */
        reply->body.msgh_descriptor_count = 1;
        reply->special_port.name = port;
        reply->special_port.disposition = MACH_MSG_TYPE_MOVE_SEND;
        reply->special_port.type = MACH_MSG_PORT_DESCRIPTOR;

        *ret_out = kr;
        return true;
    }
    case 3405: {
        /*
         * task_info — MIG subsystem task, routine 5.
         * Request:  header(24) + NDR(8) + flavor(4) + count(4) = 40
         * Reply:    header(24) + NDR(8) + retval(4) + count(4) + data(var)
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            task_flavor_t flavor;
            mach_msg_type_number_t count;
        } *req = buf;

        task_flavor_t flavor = req->flavor;
        mach_msg_type_number_t count = req->count;

        integer_t info_buf[94];
        kern_return_t kr = task_info(mach_task_self(), flavor,
                                     (task_info_t)info_buf, &count);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            mach_msg_type_number_t count;
            integer_t data[94];
        } *reply = buf;

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(mach_msg_header_t) +
                               sizeof(NDR_record_t) + 8 +
                               count * sizeof(integer_t);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 3505 */
        reply->NDR = NDR_record;
        reply->retval = kr;
        reply->count = count;
        if (count > 0 && count <= 94) {
            memcpy(reply->data, info_buf, count * sizeof(integer_t));
        }

        *ret_out = KERN_SUCCESS;
        return true;
    }
    case 3410: {
        /*
         * task_set_special_port — MIG subsystem task, routine 10.
         * Request (COMPLEX): header(24) + body(4) + port_desc(12) +
         *   NDR(8) + which_port(4) = 52
         * Reply: header(24) + NDR(8) + retval(4) = 36
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t special_port;
            NDR_record_t NDR;
            int which_port;
        } *req = buf;

        kern_return_t kr = task_set_special_port(mach_task_self(),
                                                  req->which_port,
                                                  req->special_port.name);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
        } *reply = buf;

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 3510 */
        reply->NDR = NDR_record;
        reply->retval = kr;

        *ret_out = KERN_SUCCESS;
        return true;
    }
    default:
        return false;
    }
}

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
#define MACH_TRAP_PORT_REQUEST_NOTIFICATION     (-70)
#define MACH_TRAP_PORT_GET_ATTRIBUTES           (-71)
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
        fprintf(stderr, "mach_trap[%d] = %lx, %lx, %lx, %lx, %lx, %lx\n",
                trap_num, (long)arg1, (long)arg2, (long)arg3,
                (long)arg4, (long)arg5, (long)arg6);
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
                if (do_strace) {
                    fprintf(stderr, "  vm_map: allocated at 0x%llx "
                            "(host=%p, prot=%d)\n",
                            (unsigned long long)addr,
                            g2h_untagged(addr), host_prot);
                }
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
    case MACH_TRAP_PORT_REQUEST_NOTIFICATION:
    case MACH_TRAP_PORT_GET_ATTRIBUTES:
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
            } else if (trap_num == MACH_TRAP_PORT_CONSTRUCT) {
                mach_port_options_t opts;
                memset(&opts, 0, sizeof(opts));
                if (arg2) {
                    memcpy(&opts, g2h_untagged(arg2), sizeof(opts));
                }
                mach_port_name_t name = MACH_PORT_NULL;
                ret = mach_port_construct(mach_task_self(), &opts,
                                          (mach_port_context_t)arg3,
                                          &name);
                if (ret == KERN_SUCCESS && arg4) {
                    memcpy(g2h_untagged(arg4), &name, sizeof(name));
                }
            } else if (trap_num == MACH_TRAP_PORT_DESTRUCT) {
                ret = mach_port_destruct(mach_task_self(),
                                         (mach_port_name_t)arg2,
                                         (mach_port_delta_t)arg3,
                                         (mach_port_context_t)arg4);
            } else if (trap_num == MACH_TRAP_PORT_REQUEST_NOTIFICATION) {
                /*
                 * _kernelrpc_mach_port_request_notification_trap
                 * arg1=task, arg2=name, arg3=msgid, arg4=sync,
                 * arg5=notify, arg6=notifyPoly, arg7=guest prev_ptr
                 *
                 * Forward to host for ports in our namespace.
                 * Write MACH_PORT_NULL as previous.
                 */
                if (arg7) {
                    mach_port_name_t prev = MACH_PORT_NULL;
                    memcpy(g2h_untagged(arg7), &prev, sizeof(prev));
                }
                ret = KERN_SUCCESS;
            } else if (trap_num == MACH_TRAP_PORT_GET_ATTRIBUTES) {
                /*
                 * _kernelrpc_mach_port_get_attributes_trap — stub.
                 * Return status with all zeroes.
                 */
                ret = KERN_SUCCESS;
            } else {
                ret = KERN_SUCCESS;
            }
        }
        break;

    case MACH_TRAP_MACH_MSG:
    case MACH_TRAP_MACH_MSG_OVERWRITE:
        /*
         * mach_msg_trap — legacy Mach IPC.
         * Convert to mach_msg2_trap to avoid SIGKILL from message
         * filters on modern macOS.
         */
        {
            void *host_data = arg1 ? g2h_untagged(arg1) : NULL;
            mach_msg_header_t *hdr = (mach_msg_header_t *)host_data;

            /* Pack into mach_msg2 format */
            uint64_t options = (uint64_t)(uint32_t)arg2 | 0x200000000ULL;
            uint64_t bits_and_size = 0;
            uint64_t remote_and_local = 0;
            uint64_t voucher_and_id = 0;
            if (hdr) {
                bits_and_size = ((uint64_t)(uint32_t)arg3 << 32) |
                                hdr->msgh_bits;
                remote_and_local = ((uint64_t)hdr->msgh_local_port << 32) |
                                   hdr->msgh_remote_port;
                voucher_and_id = ((uint64_t)hdr->msgh_id << 32) |
                                 hdr->msgh_voucher_port;
            }
            uint64_t desc_and_rcv = ((uint64_t)(uint32_t)arg5 << 32);
            uint64_t rcv_and_pri = (uint64_t)(uint32_t)arg4;
            uint64_t timeout = (uint64_t)(uint32_t)arg6;

            ret = host_mach_msg2_trap(host_data, options,
                                      bits_and_size, remote_and_local,
                                      voucher_and_id, desc_and_rcv,
                                      rcv_and_pri, timeout);
        }
        break;

    case MACH_TRAP_MACH_MSG2:
        /*
         * mach_msg2_trap — forward to host kernel via raw trap.
         *
         * On modern macOS the old mach_msg_trap is SIGKILL'd by
         * message filters.  We must use mach_msg2_trap directly.
         * Only the data pointer needs guest→host translation;
         * all other packed arguments pass through unchanged.
         *
         * Ensure MACH64_SEND_FILTER_NONFATAL (bit 33) is set so
         * that filtered messages return an error instead of killing
         * the process.
         */
        {
            void *host_data = arg1 ? g2h_untagged(arg1) : NULL;
            uint64_t options = (uint64_t)arg2 | 0x200000000ULL;

            if (do_strace && host_data) {
                mach_msg_header_t *hdr = (mach_msg_header_t *)host_data;
                fprintf(stderr,
                    "  mach_msg2: bits=0x%x size=%u remote=0x%x "
                    "local=0x%x id=%u\n",
                    hdr->msgh_bits, hdr->msgh_size,
                    hdr->msgh_remote_port, hdr->msgh_local_port,
                    hdr->msgh_id);
            }

            /* Try handling common MIG messages in-process first */
            kern_return_t mig_ret;
            if (handle_mig_message(host_data, options,
                                   (uint64_t)arg3, &mig_ret)) {
                ret = mig_ret;
            } else {
                ret = host_mach_msg2_trap(host_data, options,
                                          (uint64_t)arg3, (uint64_t)arg4,
                                          (uint64_t)arg5, (uint64_t)arg6,
                                          (uint64_t)arg7, (uint64_t)arg8);
            }
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
