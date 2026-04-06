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
 * XPC receive timeout tracking.
 *
 * When we inject a timeout into an XPC receive-only call (see
 * OPT_STRICT below), the library will retry on MACH_RCV_INTERRUPTED.
 * If the service genuinely won't reply (e.g. cfprefsd for emulated
 * processes), we need to escalate so XPC tears down the connection
 * instead of looping forever.
 *
 * Strategy: add a 5-second timeout to receive-only operations (those
 * submitted without SEND flag and without their own timeout).
 * On timeout:
 *   - First few retries: return MACH_RCV_INTERRUPTED (caller retries)
 *   - After enough retries: return MACH_RCV_PORT_DIED (caller tears
 *     down the channel gracefully)
 *
 * MACH_RCV_TIMED_OUT must NOT be returned — dispatch aborts on it.
 * MACH_RCV_PORT_DIED is handled by dispatch (graceful teardown).
 */
#define IPC_RECV_TIMEOUT_MS   5000   /* 5s per attempt */
#define IPC_RECV_MAX_RETRY    3      /* then PORT_DIED */

static mach_port_name_t ipc_timeout_port;
static int ipc_timeout_count;

static kern_return_t ipc_timeout_result(mach_port_name_t rcv_port,
                                        bool strace)
{
    if (rcv_port == ipc_timeout_port) {
        ipc_timeout_count++;
    } else {
        ipc_timeout_port = rcv_port;
        ipc_timeout_count = 1;
    }

    if (ipc_timeout_count <= IPC_RECV_MAX_RETRY) {
        if (strace) {
            fprintf(stderr,
                "  ipc timeout %d/%d on port 0x%x — interrupted\n",
                ipc_timeout_count, IPC_RECV_MAX_RETRY, rcv_port);
        }
        return 0x10004005;  /* MACH_RCV_INTERRUPTED — caller retries */
    }

    ipc_timeout_port = 0;
    ipc_timeout_count = 0;
    if (strace) {
        fprintf(stderr,
            "  ipc timeout exhausted on port 0x%x — port died\n",
            rcv_port);
    }
    return 0x10004006;  /* MACH_RCV_PORT_DIED — graceful teardown */
}

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
 * Raw mk_timer traps via inline assembly.
 * mk_timer_create returns a port name (not kern_return_t).
 */
static mach_port_name_t host_mk_timer_create(void)
{
    register uint64_t x0 __asm__("x0");
    register int x16 __asm__("x16") = -91;
    __asm__ volatile(
        "svc #0x80"
        : "=r"(x0)
        : "r"(x16)
        : "memory", "cc"
    );
    return (mach_port_name_t)x0;
}

static kern_return_t host_mk_timer_destroy(mach_port_name_t name)
{
    register uint64_t x0 __asm__("x0") = name;
    register int x16 __asm__("x16") = -92;
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x16)
        : "memory", "cc"
    );
    return (kern_return_t)x0;
}

static kern_return_t host_mk_timer_arm(mach_port_name_t name,
                                       uint64_t expire_time)
{
    register uint64_t x0 __asm__("x0") = name;
    register uint64_t x1 __asm__("x1") = expire_time;
    register int x16 __asm__("x16") = -93;
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x16)
        : "memory", "cc"
    );
    return (kern_return_t)x0;
}

static kern_return_t host_mk_timer_cancel(mach_port_name_t name,
                                          uint64_t *result_time)
{
    register uint64_t x0 __asm__("x0") = name;
    register uint64_t x1 __asm__("x1") = (uint64_t)result_time;
    register int x16 __asm__("x16") = -94;
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x16)
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
         * the guest is declaring an address-space reservation.  We
         * cannot use MAP_FIXED because that would clobber existing
         * mappings within the range.
         *
         * Instead, register the reservation in the guest page table
         * and mmap only the sub-pages that aren't already mapped.
         * Later vm_protect or vm_allocate calls will materialise
         * real pages within this reservation.  The vm_protect handler
         * falls back to target_mmap when mprotect fails on pages
         * that were never host-mapped.
         */
        if (host_prot == PROT_NONE && guest_start != 0 &&
            !(flags & 0x4000)) {
            /*
             * Walk the range in page-sized chunks: mmap(PROT_NONE)
             * each page that doesn't already have a host mapping.
             * For small reservations this is fine.  For huge ones
             * (>1GB) we skip the per-page mmap and just record
             * pages — the vm_protect fallback will materialise on
             * demand.
             */
            if (size <= 256 * 1024 * 1024) {
                /* Small enough to mmap the whole thing */
                abi_long r = target_mmap(guest_start, size,
                                         PROT_NONE,
                                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                         -1, 0);
                result = (r == (abi_long)guest_start) ? guest_start : -1;
            } else {
                /*
                 * Too large — just register in guest page table.
                 * Use clr_flags=0 to preserve existing page flags
                 * (e.g. the sigreturn trampoline) that may already
                 * be mapped within this range.
                 */
                mmap_lock();
                page_set_flags(guest_start, guest_start + size - 1,
                               PAGE_VALID, 0);
                mmap_unlock();
                result = guest_start;
            }
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
    case 4817: {
        /*
         * _mach_make_memory_entry — MIG subsystem mach_vm, routine 17.
         * Creates a named memory entry (port) for a VM region.
         * We translate the guest offset to a host address.
         *
         * Request (COMPLEX): header(24) + body(4) + port_desc(12) +
         *   NDR(8) + size(8) + offset(8) + permission(4) = 68
         * Reply (COMPLEX, success): header(24) + body(4) +
         *   port_desc(12) + NDR(8) + size(8) = 56
         * Reply (error): header(24) + NDR(8) + retval(4) = 36
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t parent;
            NDR_record_t NDR;
            uint64_t size;
            uint64_t offset;
            int permission;
        } *req = buf;

        memory_object_size_t size = req->size;
        memory_object_offset_t guest_offset = req->offset;
        vm_prot_t permission = req->permission;
        mem_entry_name_port_t parent = req->parent.name;
        mach_port_t object_handle = MACH_PORT_NULL;

        void *host_addr = g2h_untagged((abi_ulong)guest_offset);
        memory_object_offset_t host_offset =
            (memory_object_offset_t)(uintptr_t)host_addr;

        if (do_strace) {
            fprintf(stderr,
                "  _mach_make_memory_entry: guest_off=0x%llx "
                "host_off=0x%llx size=0x%llx perm=0x%x\n",
                (unsigned long long)guest_offset,
                (unsigned long long)host_offset,
                (unsigned long long)size, permission);
        }

        kern_return_t kr = mach_make_memory_entry_64(
            mach_task_self(), &size, host_offset,
            permission, &object_handle, parent);

        if (do_strace) {
            fprintf(stderr,
                "  _mach_make_memory_entry -> %d, handle=0x%x size=0x%llx\n",
                kr, object_handle, (unsigned long long)size);
        }

        if (kr == KERN_SUCCESS) {
            /* COMPLEX reply — no RetCode field for success */
            struct __attribute__((packed)) {
                mach_msg_header_t hdr;
                mach_msg_body_t body;
                mach_msg_port_descriptor_t object;
                NDR_record_t NDR;
                memory_object_size_t size;
            } *reply = buf;

            reply->hdr.msgh_bits =
                MACH_MSGH_BITS_COMPLEX |
                MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
            reply->hdr.msgh_size = sizeof(*reply);
            reply->hdr.msgh_remote_port = MACH_PORT_NULL;
            reply->hdr.msgh_local_port = hdr->msgh_local_port;
            reply->hdr.msgh_id = msg_id + 100;  /* 4917 */
            reply->body.msgh_descriptor_count = 1;
            reply->object.name = object_handle;
            reply->object.disposition = MACH_MSG_TYPE_MOVE_SEND;
            reply->object.type = MACH_MSG_PORT_DESCRIPTOR;
            reply->NDR = NDR_record;
            reply->size = size;
        } else {
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
            reply->hdr.msgh_id = msg_id + 100;  /* 4917 */
            reply->NDR = NDR_record;
            reply->retval = kr;
        }

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
        if (do_strace) {
            fprintf(stderr, "  MIG unhandled: id=%d remote=0x%x local=0x%x\n",
                    msg_id, hdr->msgh_remote_port, hdr->msgh_local_port);
        }
        return false;
    }
}

/*
 * fixup_mig_request_addrs -- translate guest addresses in MIG requests.
 *
 * Some MIG routines accept buffer addresses from user space so the kernel
 * can copyout() data directly into a caller-provided buffer.  Under QEMU
 * user-mode emulation the guest sees addresses relative to guest_base, but
 * the host kernel's copyout() operates on real (host) virtual addresses.
 * We patch the embedded pointer(s) before forwarding the message.
 *
 * Known routines:
 *   2880  io_connect_method
 *         Variable layout: selector(4) + scalar_input(var) + inband_input(var)
 *         + ool_input(8) + ool_input_size(8) + counts(8) + ool_output(8)
 *   2881  io_connect_async_method
 *         Same as 2880 but prepended with body(4) + port_desc(12) + NDR(8)
 *         + reference[8](64) + selector(4); scalar_inputCnt at offset 116.
 *   2888  io_registry_entry_get_properties_bin_buf
 *         Request: Head(24) + NDR(8) + buf(8) + bufsize(8) = 48
 *         buf at offset 32 (mach_vm_address_t)
 *   2889  io_registry_entry_get_property_bin_buf
 *         Variable layout: planeCnt + plane + nameCnt + name + opts + buf(8)
 */
static void fixup_mig_request_addrs(void *msg_buf, uint32_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;

    if (!guest_base) {
        return;
    }

    switch (hdr->msgh_id) {
    case 2880:   /* io_connect_method */
    case 2881: { /* io_connect_async_method */
        /*
         * io_connect_method — variable layout (pack(4)):
         *   Head(24) + NDR(8) + selector(4)
         *   + scalar_inputCnt(4) + scalar_input[cnt*8]
         *   + inband_inputCnt(4) + inband_input[cnt,pad4]
         *   + ool_input(8) + ool_input_size(8)
         *   + inband_outputCnt(4) + scalar_outputCnt(4)
         *   + ool_output(8) + ool_output_size(8)
         *
         * io_connect_async_method prepends:
         *   Head(24) + body(4) + port_desc(12) + NDR(8)
         *   + reference[8](64) + selector(4)
         * scalar_inputCnt starts at offset 116 instead of 36.
         */
        uint8_t *p = (uint8_t *)hdr;
        uint32_t off;
        if (hdr->msgh_id == 2881) {
            if (send_size < 136) break;
            off = 116;  /* Head+body+port_desc+NDR+ref[8]+selector */
        } else {
            if (send_size < 56) break;
            off = 36;   /* Head+NDR+selector */
        }
        uint32_t scnt = *(uint32_t *)(p + off);
        off += 4 + scnt * 8;
        if (off + 4 > send_size) break;
        uint32_t icnt = *(uint32_t *)(p + off);
        off += 4 + ((icnt + 3) & ~3u);
        if (off + 16 > send_size) break;
        /* ool_input */
        uint64_t *ool_in = (uint64_t *)(p + off);
        if (*ool_in != 0) {
            *ool_in += (uint64_t)guest_base;
        }
        off += 16;  /* skip ool_input + ool_input_size */
        off += 8;   /* skip inband_outputCnt + scalar_outputCnt */
        if (off + 8 > send_size) break;
        /* ool_output */
        uint64_t *ool_out = (uint64_t *)(p + off);
        if (*ool_out != 0) {
            *ool_out += (uint64_t)guest_base;
        }
        break;
    }

    case 2888: /* io_registry_entry_get_properties_bin_buf */
        /* Request: Head(24) + NDR(8) + buf(8) + bufsize(8) = 48 */
        if (send_size >= 48) {
            uint64_t *bufp = (uint64_t *)((uint8_t *)hdr + 32);
            if (*bufp != 0) {
                if (do_strace) {
                    fprintf(stderr,
                        "  MIG %u: translate buf 0x%llx -> 0x%llx\n",
                        hdr->msgh_id, *bufp,
                        *bufp + (uint64_t)guest_base);
                }
                *bufp += (uint64_t)guest_base;
            }
        }
        break;

    case 2889: {
        /*
         * io_registry_entry_get_property_bin_buf
         * MIG c_string[*:N] emits: Offset(4) + Cnt(4) + data(var,pad4)
         *   Head(24) + NDR(8) + planeOff(4) + planeCnt(4) + plane(var)
         *   + nameOff(4) + nameCnt(4) + name(var)
         *   + options(4) + buf(8) + bufsize(8)
         */
        uint8_t *p = (uint8_t *)hdr;
        if (send_size < 56) break;
        /* plane: offset + count + data */
        uint32_t plane_cnt = *(uint32_t *)(p + 36);
        uint32_t plane_pad = (plane_cnt + 3) & ~3u;
        uint32_t name_off_field = 40 + plane_pad;
        if (name_off_field + 8 > send_size) break;
        /* property_name: offset + count + data */
        uint32_t name_cnt = *(uint32_t *)(p + name_off_field + 4);
        uint32_t name_pad = (name_cnt + 3) & ~3u;
        uint32_t opts_off = name_off_field + 8 + name_pad;
        uint32_t buf_off = opts_off + 4;
        if (buf_off + 8 > send_size) break;
        uint64_t *bufp = (uint64_t *)(p + buf_off);
        if (*bufp != 0) {
            if (do_strace) {
                fprintf(stderr,
                    "  MIG %u: translate buf @%u 0x%llx -> 0x%llx\n",
                    hdr->msgh_id, buf_off, *bufp,
                    *bufp + (uint64_t)guest_base);
            }
            *bufp += (uint64_t)guest_base;
        }
        break;
    }

    default:
        break;
    }
}

/*
 * fixup_mig_reply_ool -- translate OOL descriptors in MIG replies.
 *
 * When the host kernel returns a complex MIG reply, any out-of-line (OOL)
 * memory descriptors contain host virtual addresses.  With guest_base != 0,
 * the guest cannot dereference these directly because TCG adds guest_base
 * to every address.  We fix this by:
 *   1. Allocating guest-visible memory via target_mmap
 *   2. Copying the OOL data there
 *   3. Releasing the kernel's original mapping
 *   4. Patching the descriptor to hold the guest address
 */
static void fixup_mig_reply_ool(void *reply_buf)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)reply_buf;

    if (!guest_base) {
        return;  /* no translation needed */
    }
    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return;  /* no descriptors */
    }

    mach_msg_body_t *body = (mach_msg_body_t *)(hdr + 1);
    uint8_t *dp = (uint8_t *)(body + 1);

    if (do_strace && body->msgh_descriptor_count > 0) {
        fprintf(stderr, "  OOL fixup: msg_id=%u desc_count=%u msg_size=%u\n",
                hdr->msgh_id, body->msgh_descriptor_count, hdr->msgh_size);
    }

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        mach_msg_type_descriptor_t *td = (mach_msg_type_descriptor_t *)dp;

        switch (td->type) {
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool = (mach_msg_ool_descriptor_t *)dp;
            void *host_addr = ool->address;
            mach_msg_size_t size = ool->size;

            if (host_addr && size > 0) {
                /* Allocate in guest address space */
                abi_long guest_addr = target_mmap(0, size,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (guest_addr > 0) {
                    memcpy(g2h_untagged(guest_addr), host_addr, size);
                    munmap(host_addr, size);
                    ool->address = (void *)(uintptr_t)guest_addr;
                    if (do_strace) {
                        fprintf(stderr,
                            "    OOL[%u]: host %p -> guest 0x%llx "
                            "size=%u\n",
                            i, host_addr,
                            (unsigned long long)guest_addr, size);
                    }
                }
            }
            dp += sizeof(mach_msg_ool_descriptor_t);
            break;
        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op =
                (mach_msg_ool_ports_descriptor_t *)dp;
            if (do_strace) {
                fprintf(stderr,
                    "  OOL_PORTS desc[%u]: count=%u disp=%u\n",
                    i, op->count, op->disposition);
            }
            dp += sizeof(mach_msg_ool_ports_descriptor_t);
            break;
        }
        case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t *pd =
                (mach_msg_port_descriptor_t *)dp;
            if (do_strace) {
                mach_port_type_t ptype = 0;
                mach_port_type(mach_task_self(), pd->name, &ptype);
                fprintf(stderr,
                    "  PORT desc[%u]: name=0x%x disp=%u type=0x%x\n",
                    i, pd->name, pd->disposition, ptype);
            }
            dp += sizeof(mach_msg_port_descriptor_t);
            break;
        }
        default:
            if (do_strace) {
                fprintf(stderr,
                    "  UNKNOWN desc[%u]: type=%u\n", i, td->type);
            }
            /* Unknown descriptor — skip using guarded size */
            dp += sizeof(mach_msg_ool_descriptor_t);
            break;
        }
    }
}
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
#define MACH_TRAP_PORT_GET_ATTRIBUTES           (-40)
#define MACH_TRAP_PORT_GUARD                    (-41)
#define MACH_TRAP_PORT_UNGUARD                  (-42)
#define MACH_TRAP_GENERATE_ACTIVITY_ID          (-43)
#define MACH_TRAP_REPLY_PORT                    (-26)
#define MACH_TRAP_THREAD_SELF                   (-27)
#define MACH_TRAP_TASK_SELF                     (-28)
#define MACH_TRAP_HOST_SELF                     (-29)
#define MACH_TRAP_MACH_MSG                      (-31)
#define MACH_TRAP_MACH_MSG_OVERWRITE            (-32)
#define MACH_TRAP_SEMAPHORE_SIGNAL              (-33)
#define MACH_TRAP_SEMAPHORE_SIGNAL_ALL          (-34)
#define MACH_TRAP_SEMAPHORE_SIGNAL_THREAD       (-35)
#define MACH_TRAP_SEMAPHORE_WAIT                (-36)
#define MACH_TRAP_SEMAPHORE_WAIT_SIGNAL         (-37)
#define MACH_TRAP_SEMAPHORE_TIMEDWAIT           (-38)
#define MACH_TRAP_SEMAPHORE_TIMEDWAIT_SIGNAL    (-39)
#define MACH_TRAP_PORT_SET_ATTRIBUTES           (-44)
#define MACH_TRAP_MACH_MSG2                     (-47)
#define MACH_TRAP_THREAD_GET_SPECIAL_REPLY_PORT (-50)
#define MACH_TRAP_SWTCH_PRI                     (-59)
#define MACH_TRAP_SWTCH                         (-60)
#define MACH_TRAP_SYSCALL_THREAD_SWITCH         (-61)
#define MACH_TRAP_HOST_CREATE_MACH_VOUCHER      (-70)
#define MACH_TRAP_PORT_TYPE                     (-76)
#define MACH_TRAP_PORT_REQUEST_NOTIFICATION     (-77)
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
        fprintf(stderr,
                "mach_trap[%d] = %lx, %lx, %lx, %lx, %lx, %lx, %lx, %lx\n",
                trap_num, (long)arg1, (long)arg2, (long)arg3,
                (long)arg4, (long)arg5, (long)arg6,
                (long)arg7, (long)arg8);
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
            abi_ulong guest_addr = (abi_ulong)arg2;
            void *addr = g2h_untagged(guest_addr);
            size_t size = (size_t)arg3;
            int prot = (int)arg5;
            int host_prot = 0;

            if (prot & VM_PROT_READ)    host_prot |= PROT_READ;
            if (prot & VM_PROT_WRITE)   host_prot |= PROT_WRITE;
            if (prot & VM_PROT_EXECUTE) host_prot |= PROT_EXEC;

            /*
             * Align to host page boundaries — macOS requires mprotect
             * addresses to be aligned to the host page size (16K on
             * Apple Silicon), but the guest may use 4K pages.
             */
            unsigned long hpgsz = qemu_real_host_page_size();
            abi_ulong aligned_start = guest_addr & ~(hpgsz - 1);
            abi_ulong aligned_end = (guest_addr + size + hpgsz - 1) & ~(hpgsz - 1);
            size_t aligned_size = aligned_end - aligned_start;
            void *aligned_addr = g2h_untagged(aligned_start);

            if (mprotect(aligned_addr, aligned_size, host_prot) == 0) {
                /* Host pages already mapped — just update QEMU page flags */
                int qemu_flags = PAGE_VALID;
                if (host_prot & PROT_READ)  qemu_flags |= PAGE_READ;
                if (host_prot & PROT_WRITE) qemu_flags |= PAGE_WRITE;
                if (host_prot & PROT_EXEC)  qemu_flags |= PAGE_EXEC;
                mmap_lock();
                page_set_flags(guest_addr, guest_addr + size - 1,
                               qemu_flags, ~0);
                mmap_unlock();
                ret = KERN_SUCCESS;
            } else if (host_prot != 0) {
                /*
                 * mprotect failed — likely because the host pages don't
                 * exist yet (PROT_NONE reservation created by vm_map only
                 * registered pages in the guest page table).  Materialise
                 * the host mapping now with target_mmap(MAP_FIXED).
                 */
                abi_long result = target_mmap(guest_addr, size, host_prot,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (result == (abi_long)guest_addr) {
                    ret = KERN_SUCCESS;
                } else {
                    ret = KERN_PROTECTION_FAILURE;
                }
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
                    fprintf(stderr, "  vm_map_trap: at 0x%llx size=0x%zx "
                            "prot=%d\n",
                            (unsigned long long)addr, size, host_prot);
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
                /*
                 * _kernelrpc_mach_port_allocate_trap
                 * arg1=task, arg2=right, arg3=guest name_ptr
                 */
                mach_port_name_t name;
                ret = mach_port_allocate(mach_task_self(),
                                         (mach_port_right_t)arg2,
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
                 */
                mach_port_t previous = MACH_PORT_NULL;
                ret = mach_port_request_notification(
                    mach_task_self(),
                    (mach_port_name_t)arg2,
                    (mach_msg_id_t)arg3,
                    (mach_port_mscount_t)arg4,
                    (mach_port_t)arg5,
                    (mach_msg_type_name_t)arg6,
                    &previous);
                if (arg7 > 0x1000) {
                    memcpy(g2h_untagged(arg7), &previous,
                           sizeof(previous));
                }
            } else if (trap_num == MACH_TRAP_PORT_GET_ATTRIBUTES) {
                /*
                 * _kernelrpc_mach_port_get_attributes_trap
                 * arg1=task, arg2=name, arg3=flavor,
                 * arg4=guest info_ptr, arg5=guest count_ptr
                 */
                mach_msg_type_number_t count = 0;
                if (arg5) {
                    memcpy(&count, g2h_untagged(arg5), sizeof(count));
                }
                mach_port_info_t info = g2h_untagged(arg4);
                ret = mach_port_get_attributes(
                    mach_task_self(),
                    (mach_port_name_t)arg2,
                    (mach_port_flavor_t)arg3,
                    info, &count);
                if (ret == KERN_SUCCESS && arg5) {
                    memcpy(g2h_untagged(arg5), &count, sizeof(count));
                }
            } else if (trap_num == MACH_TRAP_PORT_INSERT_MEMBER) {
                ret = mach_port_insert_member(mach_task_self(),
                                              (mach_port_name_t)arg2,
                                              (mach_port_name_t)arg3);
            } else if (trap_num == MACH_TRAP_PORT_EXTRACT_MEMBER) {
                ret = mach_port_extract_member(mach_task_self(),
                                               (mach_port_name_t)arg2,
                                               (mach_port_name_t)arg3);
            } else if (trap_num == MACH_TRAP_PORT_MOVE_MEMBER) {
                ret = mach_port_move_member(mach_task_self(),
                                            (mach_port_name_t)arg2,
                                            (mach_port_name_t)arg3);
            } else if (trap_num == MACH_TRAP_PORT_TYPE) {
                mach_port_type_t type = 0;
                ret = mach_port_type(mach_task_self(),
                                     (mach_port_name_t)arg2, &type);
                if (ret == KERN_SUCCESS && arg3) {
                    memcpy(g2h_untagged(arg3), &type, sizeof(type));
                }
            } else {
                ret = KERN_SUCCESS;
            }
        }
        break;

    case MACH_TRAP_PORT_GUARD:
    case MACH_TRAP_PORT_UNGUARD:
        /*
         * _kernelrpc_mach_port_guard_trap(task, name, guard, strict)
         * _kernelrpc_mach_port_unguard_trap(task, name, guard)
         * Port guarding is advisory protection.  Forward to host,
         * but tolerate all errors — guarding doesn't affect
         * functional correctness.
         */
        if (trap_num == MACH_TRAP_PORT_GUARD) {
            ret = mach_port_guard(mach_task_self(),
                                  (mach_port_name_t)arg2,
                                  (mach_port_context_t)arg3,
                                  (boolean_t)arg4);
        } else {
            ret = mach_port_unguard(mach_task_self(),
                                    (mach_port_name_t)arg2,
                                    (mach_port_context_t)arg3);
        }
        if (ret != KERN_SUCCESS) {
            ret = KERN_SUCCESS;
        }
        break;

    case MACH_TRAP_GENERATE_ACTIVITY_ID:
        /*
         * mach_generate_activity_id(mach_port_t target, int count,
         *                           uint64_t *activity_id)
         * Generate activity IDs for diagnostics/tracing.  We generate
         * sequential IDs without going to the kernel.
         */
        {
            static uint64_t next_activity_id = 1;
            if (arg3) {
                uint64_t *out = (uint64_t *)g2h_untagged(arg3);
                *out = next_activity_id;
                next_activity_id += (int)arg2;
            }
            ret = KERN_SUCCESS;
        }
        break;

    case MACH_TRAP_PORT_SET_ATTRIBUTES:
        /*
         * _kernelrpc_mach_port_set_attributes_trap(task, name,
         *                                           flavor, info, count)
         * Set port attributes.  Forward to host with pointer translation.
         */
        {
            void *info = arg4 ? g2h_untagged(arg4) : NULL;
            ret = mach_port_set_attributes(mach_task_self(),
                                           (mach_port_name_t)arg2,
                                           (int)arg3,
                                           (mach_port_info_t)info,
                                           (mach_msg_type_number_t)arg5);
        }
        break;

    case MACH_TRAP_HOST_CREATE_MACH_VOUCHER:
        /*
         * host_create_mach_voucher_trap(host, recipes, recipes_size,
         *                               voucher_ptr)
         * Create a Mach voucher for resource accounting.  Forward to
         * host kernel with pointer translation.
         */
        {
            void *recipes = arg2 ? g2h_untagged(arg2) : NULL;
            mach_port_name_t voucher = MACH_PORT_NULL;
            ret = host_create_mach_voucher(mach_host_self(),
                                            (mach_voucher_attr_raw_recipe_array_t)recipes,
                                            (mach_msg_type_number_t)arg3,
                                            &voucher);
            if (ret == KERN_SUCCESS && arg4) {
                memcpy(g2h_untagged(arg4), &voucher, sizeof(voucher));
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
            uint64_t options = (uint64_t)(uint32_t)arg2 | 0x10000ULL;
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
         *
         * When MACH64_MSG_VECTOR (bit 32 of options) is set, arg1
         * points to a mach_msg_vector_t array whose msgv_data fields
         * contain guest pointers that need translation.  Otherwise
         * arg1 is a direct mach_msg_header_t pointer.
         *
         * Ensure MACH_SEND_FILTER_NONFATAL (0x10000) is set so
         * that filtered messages return an error instead of killing
         * the process.
         */
        {
#define MACH64_MSG_VECTOR          0x100000000ULL
#define MACH64_SEND_KOBJECT_CALL   0x200000000ULL
#define MACH64_SEND_MQ_CALL        0x400000000ULL
#define MACH64_SEND_ANY            0x800000000ULL

            /*
             * mach_msg_vector_t: used when MACH64_MSG_VECTOR is set.
             * Each entry has a data pointer, receive address, and sizes.
             */
            typedef struct {
                uint64_t msgv_data;
                uint64_t msgv_rcv_addr;
                uint32_t msgv_send_size;
                uint32_t msgv_rcv_size;
            } mach_msg_vector_t;

            uint64_t options = (uint64_t)arg2 | 0x10000ULL;
            void *host_data;

            /*
             * Do NOT strip MACH64_SEND_KOBJECT_CALL or MACH64_SEND_MQ_CALL.
             * These are kernel optimization hints that are REQUIRED by
             * message filters — stripping them causes SIGKILL even with
             * MACH_SEND_FILTER_NONFATAL set.
             */

            if (options & MACH64_MSG_VECTOR) {
                /*
                 * Vector mode: arg1 points to guest mach_msg_vector_t.
                 * Translate the vector pointer, then translate each
                 * msgv_data guest pointer inside to a host pointer.
                 * Save original guest pointers to restore after the
                 * trap (the guest may reuse the vector).
                 */
                mach_msg_vector_t *vec =
                    (mach_msg_vector_t *)g2h_untagged(arg1);
                host_data = vec;

                /*
                 * The send count comes from the lower 32 bits of arg3
                 * (packed as send_size | (send_count << 0) for vectors).
                 * For MACH64_MSG_VECTOR, the lower 32 bits of arg3 is
                 * actually the count of vector entries for send.
                 * There can be 1 send entry and optionally 1 receive entry.
                 * We translate msgv_data for all entries that have nonzero
                 * send or receive sizes.
                 */
                uint64_t save_data[2] = {0, 0};
                uint64_t save_rcv[2] = {0, 0};
                int nentries = 0;

                /*
                 * Vector entry layout:
                 *   Entry 0: message (send and/or receive)
                 *   Entry 1: auxiliary data (only when AUX flags set)
                 *
                 * Entry 0's msgv_data is the send buffer, msgv_rcv_addr
                 * is the receive buffer (0 = use msgv_data for both).
                 * When entry 0 has both send_size and rcv_size, there
                 * is NO entry 1 for the message — only for aux data.
                 *
                 * We must NOT access vec[1] when only 1 entry exists,
                 * as it would corrupt adjacent stack data.
                 */
                if (vec[0].msgv_send_size || vec[0].msgv_rcv_size) {
                    save_data[0] = vec[0].msgv_data;
                    save_rcv[0] = vec[0].msgv_rcv_addr;
                    if (vec[0].msgv_data) {
                        vec[0].msgv_data =
                            (uint64_t)g2h_untagged(vec[0].msgv_data);
                    }
                    if (vec[0].msgv_rcv_addr) {
                        vec[0].msgv_rcv_addr =
                            (uint64_t)g2h_untagged(vec[0].msgv_rcv_addr);
                    }
                    nentries = 1;
                }
                /*
                 * Translate entry 1 (aux data) if the kernel will
                 * read it.  The kernel copins MAX(snd_count, rcv_count)
                 * entries where:
                 *   snd_count = upper 32 of arg3 (mb_ss >> 32)
                 *   rcv_count = lower 32 of arg7 (rs_pr)
                 * We must translate vec[1] if count >= 2.
                 */
                uint32_t snd_count = (uint32_t)((uint64_t)arg3 >> 32);
                uint32_t rcv_count = (uint32_t)(uint64_t)arg7;
                uint32_t max_count = snd_count > rcv_count ?
                                     snd_count : rcv_count;
                if (nentries == 1 && max_count >= 2) {
                    save_data[1] = vec[1].msgv_data;
                    save_rcv[1] = vec[1].msgv_rcv_addr;
                    if (vec[1].msgv_data) {
                        vec[1].msgv_data =
                            (uint64_t)g2h_untagged(vec[1].msgv_data);
                    }
                    if (vec[1].msgv_rcv_addr) {
                        vec[1].msgv_rcv_addr =
                            (uint64_t)g2h_untagged(vec[1].msgv_rcv_addr);
                    }
                    nentries = 2;
                }

                if (do_strace) {
                    /* Log the actual message header from the first vector */
                    void *msg = (void *)(uintptr_t)vec[0].msgv_data;
                    if (msg) {
                        mach_msg_header_t *hdr = (mach_msg_header_t *)msg;
                        fprintf(stderr,
                            "  mach_msg2[vec]: bits=0x%x size=%u "
                            "remote=0x%x local=0x%x id=%u "
                            "opts=0x%llx send_sz=%u rcv_sz=%u\n",
                            hdr->msgh_bits, hdr->msgh_size,
                            hdr->msgh_remote_port,
                            hdr->msgh_local_port,
                            hdr->msgh_id, options,
                            vec[0].msgv_send_size,
                            vec[0].msgv_rcv_size);
                        fprintf(stderr,
                            "    vec[0]: data=0x%llx rcv=0x%llx "
                            "ssz=%u rsz=%u | vec[1]: data=0x%llx "
                            "rcv=0x%llx ssz=%u rsz=%u | "
                            "snd_count=%u nentries=%d\n",
                            vec[0].msgv_data, vec[0].msgv_rcv_addr,
                            vec[0].msgv_send_size, vec[0].msgv_rcv_size,
                            vec[1].msgv_data, vec[1].msgv_rcv_addr,
                            vec[1].msgv_send_size, vec[1].msgv_rcv_size,
                            (uint32_t)((uint64_t)arg3 >> 32), nentries);
                    }
                }

                /* MIG handling for vector messages */
                kern_return_t mig_ret;
                void *msg_buf =
                    (void *)(uintptr_t)vec[0].msgv_data;
                if (msg_buf && handle_mig_message(msg_buf, options,
                                                  (uint64_t)arg3,
                                                  &mig_ret)) {
                    ret = mig_ret;
                } else {
                    /* Translate guest addresses in MIG requests */
                    if (msg_buf && (options & 0x1)) {
                        fixup_mig_request_addrs(msg_buf,
                            vec[0].msgv_send_size);
                    }

                    uint64_t vec_opts = options;
                    uint64_t vec_tmout = (uint64_t)arg8;
                    bool vec_added_tmout = false;

#define OPT_SEND   0x1
#define OPT_RCV    0x2
#define OPT_TMOUT  0x100
                    if ((vec_opts & (OPT_SEND | OPT_RCV)) == OPT_RCV
                        && !(vec_opts & OPT_TMOUT)
                        && vec_tmout == 0) {
                        vec_opts |= OPT_TMOUT;
                        vec_tmout = IPC_RECV_TIMEOUT_MS;
                        vec_added_tmout = true;
                    }
#undef OPT_SEND
#undef OPT_RCV
#undef OPT_TMOUT

                    ret = host_mach_msg2_trap(host_data, vec_opts,
                                              (uint64_t)arg3,
                                              (uint64_t)arg4,
                                              (uint64_t)arg5,
                                              (uint64_t)arg6,
                                              (uint64_t)arg7,
                                              vec_tmout);

                    if (vec_added_tmout && ret == 0x10004003) {
                        uint32_t rcv_name =
                            (uint32_t)((uint64_t)arg6 >> 32);
                        ret = ipc_timeout_result(rcv_name, do_strace);
                    }

                    if (do_strace && ret != KERN_SUCCESS) {
                        fprintf(stderr,
                            "  mach_msg2[vec] FAILED: ret=0x%x\n",
                            (unsigned)ret);
                    }
                    /* Translate OOL descriptors in the reply */
                    if (ret == KERN_SUCCESS && (options & 0x2)) {
                        void *rcv_buf;
                        if (nentries >= 2 && vec[1].msgv_rcv_addr) {
                            rcv_buf = g2h_untagged(save_rcv[1]);
                        } else {
                            rcv_buf = (void *)(uintptr_t)vec[0].msgv_data;
                        }
                        if (rcv_buf) {
                            fixup_mig_reply_ool(rcv_buf);
                        }
                    }
                }

                /* Restore guest pointers */
                if (nentries >= 1) {
                    vec[0].msgv_data = save_data[0];
                    vec[0].msgv_rcv_addr = save_rcv[0];
                }
                if (nentries >= 2) {
                    vec[1].msgv_data = save_data[1];
                    vec[1].msgv_rcv_addr = save_rcv[1];
                }
            } else {
                /* Direct message pointer mode */
                host_data = arg1 ? g2h_untagged(arg1) : NULL;

                if (do_strace && host_data) {
                    mach_msg_header_t *hdr =
                        (mach_msg_header_t *)host_data;
                    /*
                     * macOS 15 mach_msg2 uses 8 register args:
                     *   X0=data X1=opts X2=bits_send_sz
                     *   X3=remote_local X4=voucher_id
                     *   X5=desc_rcvname X6=rcvsz_pri X7=timeout
                     * Our arg3-arg8 map to X2-X7.
                     * rcv_name = upper32 of X5 = upper32 of arg6
                     * rcv_size = lower32 of X6 = lower32 of arg7
                     */
                    fprintf(stderr,
                        "  mach_msg2: bits=0x%x size=%u remote=0x%x "
                        "local=0x%x id=%u opts=0x%llx "
                        "rcvname=0x%x rcvsize=%u\n",
                        hdr->msgh_bits, hdr->msgh_size,
                        hdr->msgh_remote_port,
                        hdr->msgh_local_port,
                        hdr->msgh_id, options,
                        (uint32_t)((uint64_t)arg6 >> 32),
                        (uint32_t)((uint64_t)arg7));
                }

                kern_return_t mig_ret;
                if (handle_mig_message(host_data, options,
                                       (uint64_t)arg3, &mig_ret)) {
                    ret = mig_ret;
                } else {
                    /* Translate guest addresses in MIG requests */
                    if (host_data && (options & 0x1)) {
                        mach_msg_header_t *shdr =
                            (mach_msg_header_t *)host_data;
                        fixup_mig_request_addrs(host_data,
                            shdr->msgh_size);
                    }

                    uint64_t trap_options = options;
                    uint64_t trap_timeout = (uint64_t)arg8;
                    bool added_timeout = false;

#define OPT_SEND   0x1
#define OPT_RCV    0x2
#define OPT_TMOUT  0x100
                    if ((trap_options & (OPT_SEND | OPT_RCV)) == OPT_RCV
                        && !(trap_options & OPT_TMOUT)
                        && trap_timeout == 0) {
                        trap_options |= OPT_TMOUT;
                        trap_timeout = IPC_RECV_TIMEOUT_MS;
                        added_timeout = true;
                    }
#undef OPT_SEND
#undef OPT_RCV
#undef OPT_TMOUT

                    ret = host_mach_msg2_trap(host_data, trap_options,
                                              (uint64_t)arg3,
                                              (uint64_t)arg4,
                                              (uint64_t)arg5,
                                              (uint64_t)arg6,
                                              (uint64_t)arg7,
                                              trap_timeout);

                    if (added_timeout && ret == 0x10004003) {
                        uint32_t rcv_name =
                            (uint32_t)((uint64_t)arg6 >> 32);
                        ret = ipc_timeout_result(rcv_name, do_strace);
                    }

                    if (do_strace && ret == KERN_SUCCESS &&
                        (options & 0x2) && host_data) {
                        mach_msg_header_t *rhdr =
                            (mach_msg_header_t *)host_data;
                        fprintf(stderr,
                            "  mach_msg2 reply: bits=0x%x size=%u "
                            "id=%u\n",
                            rhdr->msgh_bits, rhdr->msgh_size,
                            rhdr->msgh_id);
                    }
                    if (do_strace && ret != KERN_SUCCESS) {
                        fprintf(stderr,
                            "  mach_msg2 FAILED: ret=0x%x\n",
                            (unsigned)ret);
                        if (host_data) {
                            mach_msg_header_t *hdr =
                                (mach_msg_header_t *)host_data;
                            fprintf(stderr,
                                "  reply: bits=0x%x size=%u "
                                "remote=0x%x local=0x%x id=%u\n",
                                hdr->msgh_bits, hdr->msgh_size,
                                hdr->msgh_remote_port,
                                hdr->msgh_local_port,
                                hdr->msgh_id);
                        }
                    }
                    /* Translate OOL descriptors in the reply */
                    if (ret == KERN_SUCCESS && host_data &&
                        (options & 0x2)) {
                        fixup_mig_reply_ool(host_data);
                    }
                }
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
    case MACH_TRAP_SEMAPHORE_SIGNAL_THREAD:
    case MACH_TRAP_SEMAPHORE_WAIT:
    case MACH_TRAP_SEMAPHORE_WAIT_SIGNAL:
    case MACH_TRAP_SEMAPHORE_TIMEDWAIT:
    case MACH_TRAP_SEMAPHORE_TIMEDWAIT_SIGNAL:
        /* Semaphore operations — forward to host */
        if (trap_num == MACH_TRAP_SEMAPHORE_SIGNAL) {
            ret = semaphore_signal((semaphore_t)arg1);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_SIGNAL_ALL) {
            ret = semaphore_signal_all((semaphore_t)arg1);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_SIGNAL_THREAD) {
            ret = semaphore_signal_thread((semaphore_t)arg1,
                                          (thread_t)arg2);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_WAIT) {
            ret = semaphore_wait((semaphore_t)arg1);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_WAIT_SIGNAL) {
            ret = semaphore_wait_signal((semaphore_t)arg1,
                                        (semaphore_t)arg2);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_TIMEDWAIT) {
            mach_timespec_t ts;
            ts.tv_sec = (unsigned int)arg2;
            ts.tv_nsec = (clock_res_t)arg3;
            ret = semaphore_timedwait((semaphore_t)arg1, ts);
        } else {
            mach_timespec_t ts;
            ts.tv_sec = (unsigned int)arg3;
            ts.tv_nsec = (clock_res_t)arg4;
            ret = semaphore_timedwait_signal((semaphore_t)arg1,
                                             (semaphore_t)arg2, ts);
        }
        break;

    case MACH_TRAP_MK_TIMER_CREATE:
        /* mk_timer_create — returns a port name, not kern_return_t */
        ret = (abi_long)host_mk_timer_create();
        break;

    case MACH_TRAP_MK_TIMER_DESTROY:
        /* mk_timer_destroy(name) */
        ret = host_mk_timer_destroy((mach_port_name_t)arg1);
        break;

    case MACH_TRAP_MK_TIMER_ARM:
        /* mk_timer_arm(name, expire_time) */
        ret = host_mk_timer_arm((mach_port_name_t)arg1, (uint64_t)arg2);
        break;

    case MACH_TRAP_MK_TIMER_CANCEL:
        /* mk_timer_cancel(name, result_time_ptr) */
        {
            uint64_t result_time = 0;
            ret = host_mk_timer_cancel((mach_port_name_t)arg1, &result_time);
            if (ret == KERN_SUCCESS && arg2) {
                memcpy(g2h_untagged(arg2), &result_time, sizeof(result_time));
            }
        }
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
