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
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
#include <mach/clock.h>
#include <mach/notify.h>
#include <dlfcn.h>

/* Functions not exposed in public headers but available at link time */
extern mach_port_t mach_reply_port(void);
extern mach_port_t thread_get_special_reply_port(void);

/*
 * XPC receive timeout tracking.
 *
 * When we inject a timeout into an XPC receive-only call (see
 * OPT_STRICT below), the library will retry on MACH_RCV_INTERRUPTED.
 * If cfprefsd genuinely won't reply for emulated processes, we need to
 * escalate so XPC tears down that connection instead of looping forever.
 *
 * Strategy: add a 5-second timeout to receive-only operations (those
 * submitted without SEND flag and without their own timeout).
 * On timeout:
 *   - First few retries: return MACH_RCV_INTERRUPTED (caller retries)
 *   - For tracked CFPreferences reply ports only, after enough retries:
 *     return MACH_RCV_PORT_DIED (caller tears down the channel gracefully)
 *
 * MACH_RCV_TIMED_OUT must NOT be returned — dispatch aborts on it.  Do not
 * synthesize MACH_RCV_PORT_DIED for ordinary CFRunLoop/AppKit receive ports:
 * CoreFoundation expects MACH_RCV_INTERRUPTED to be transparent/retryable.
 */
#define IPC_RECV_TIMEOUT_MS   1000   /* 1s per attempt */
#define IPC_RECV_MAX_RETRY    3      /* then PORT_DIED */
#define WORKLOOP_POLL_SLICE_MS 100
#define DISPATCH_MACH_CHECKIN_MSGID 0x77303074U
#define CFPREFERENCES_REPLY_TIMEOUT_MS 100

/*
 * Timeout escalation is per waiting thread: AppKit/libdispatch may have
 * multiple concurrent reply waits on different ports, and a single global
 * counter lets one thread reset another thread's retry budget.
 *
 * ipc_timeout_port / ipc_timeout_count: per-port retry escalation (original).
 * ipc_timeout_single_streak: counts consecutive "1 timeout then port change"
 *   events.  When each retry creates a fresh special-reply-port the per-port
 *   counter never accumulates past 1/3, so we add this cross-port circuit-
 *   breaker.  Normal XPC receives with >1 timeout on the same port reset it.
 */
static __thread mach_port_name_t ipc_timeout_port;
static __thread int ipc_timeout_count;
static __thread int ipc_timeout_single_streak;
#define IPC_RECV_MAX_SINGLE_STREAK 5  /* port-per-retry spin breaker */

#define MAX_CFPREFERENCES_REPLY_PORTS 64
static mach_port_name_t cfprefs_reply_ports[MAX_CFPREFERENCES_REPLY_PORTS];
static int cfprefs_reply_port_count;
static pthread_mutex_t cfprefs_reply_port_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_SPECIAL_REPLY_PORTS 64
static mach_port_name_t special_reply_ports[MAX_SPECIAL_REPLY_PORTS];
static int special_reply_port_count;
static pthread_mutex_t special_reply_port_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_ANALYTICSD_SERVICE_PORTS 16
static mach_port_name_t analyticsd_service_ports[MAX_ANALYTICSD_SERVICE_PORTS];
static int analyticsd_service_port_count;
static pthread_mutex_t analyticsd_service_port_lock = PTHREAD_MUTEX_INITIALIZER;
static mach_port_name_t cgs_window_memory_object_port;

#define MAX_EXTERNAL_OOL_IDENTITY_MAPPINGS 64
typedef struct ExternalOolIdentityMapping {
    abi_ulong start;
    abi_ulong size;
} ExternalOolIdentityMapping;

static ExternalOolIdentityMapping
external_ool_identity_mappings[MAX_EXTERNAL_OOL_IDENTITY_MAPPINGS];
static int external_ool_identity_mapping_count;

typedef enum DeferredActiveRcvPortOpKind {
    DEFER_ACTIVE_RCV_PORT_DEALLOCATE,
    DEFER_ACTIVE_RCV_PORT_DESTRUCT,
} DeferredActiveRcvPortOpKind;

typedef struct DeferredActiveRcvPortOp {
    DeferredActiveRcvPortOpKind kind;
    mach_port_name_t port;
    mach_port_delta_t srdelta;
    mach_port_context_t guard;
} DeferredActiveRcvPortOp;

#define MAX_DEFERRED_ACTIVE_RCV_PORT_OPS 64
static DeferredActiveRcvPortOp
    deferred_active_rcv_port_ops[MAX_DEFERRED_ACTIVE_RCV_PORT_OPS];
static int deferred_active_rcv_port_op_count;
static pthread_mutex_t deferred_active_rcv_port_lock =
    PTHREAD_MUTEX_INITIALIZER;

static bool defer_active_rcv_port_op(DeferredActiveRcvPortOpKind kind,
                                     mach_port_name_t port,
                                     mach_port_delta_t srdelta,
                                     mach_port_context_t guard,
                                     bool strace)
{
    bool queued = false;

    pthread_mutex_lock(&deferred_active_rcv_port_lock);
    if (deferred_active_rcv_port_op_count < MAX_DEFERRED_ACTIVE_RCV_PORT_OPS) {
        deferred_active_rcv_port_ops[deferred_active_rcv_port_op_count++] =
            (DeferredActiveRcvPortOp) {
                .kind = kind,
                .port = port,
                .srdelta = srdelta,
                .guard = guard,
            };
        queued = true;
    }
    pthread_mutex_unlock(&deferred_active_rcv_port_lock);

    if (strace) {
        if (kind == DEFER_ACTIVE_RCV_PORT_DEALLOCATE) {
            fprintf(stderr,
                    "  port_deallocate: %s active receive port 0x%x\n",
                    queued ? "deferring" : "queue full; forwarding",
                    port);
        } else {
            fprintf(stderr,
                    "  port_destruct: %s active receive port 0x%x "
                    "srdelta=%d guard=0x%llx\n",
                    queued ? "deferring" : "queue full; forwarding",
                    port, srdelta, (unsigned long long)guard);
        }
    }

    return queued;
}

static bool has_deferred_active_rcv_port_op(mach_port_name_t port)
{
    bool found = false;

    pthread_mutex_lock(&deferred_active_rcv_port_lock);
    for (int i = 0; i < deferred_active_rcv_port_op_count; i++) {
        if (deferred_active_rcv_port_ops[i].port == port) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&deferred_active_rcv_port_lock);
    return found;
}

static void flush_deferred_active_rcv_port_ops(mach_port_name_t port,
                                               bool strace)
{
    DeferredActiveRcvPortOp pending[MAX_DEFERRED_ACTIVE_RCV_PORT_OPS];
    int pending_count = 0;

    pthread_mutex_lock(&deferred_active_rcv_port_lock);
    for (int i = 0; i < deferred_active_rcv_port_op_count; ) {
        if (deferred_active_rcv_port_ops[i].port != port) {
            i++;
            continue;
        }
        pending[pending_count++] = deferred_active_rcv_port_ops[i];
        memmove(&deferred_active_rcv_port_ops[i],
                &deferred_active_rcv_port_ops[i + 1],
                (deferred_active_rcv_port_op_count - i - 1) *
                sizeof(deferred_active_rcv_port_ops[0]));
        deferred_active_rcv_port_op_count--;
    }
    pthread_mutex_unlock(&deferred_active_rcv_port_lock);

    for (int i = 0; i < pending_count; i++) {
        kern_return_t ret;

        if (pending[i].kind == DEFER_ACTIVE_RCV_PORT_DEALLOCATE) {
            ret = mach_port_deallocate(mach_task_self(), pending[i].port);
            if (strace) {
                fprintf(stderr,
                        "  port_deallocate: flushed active receive port 0x%x "
                        "ret=%ld\n",
                        pending[i].port, (long)ret);
            }
        } else {
            ret = mach_port_destruct(mach_task_self(), pending[i].port,
                                     pending[i].srdelta, pending[i].guard);
            if (strace) {
                fprintf(stderr,
                        "  port_destruct: flushed active receive port 0x%x "
                        "srdelta=%d guard=0x%llx ret=%ld\n",
                        pending[i].port, pending[i].srdelta,
                        (unsigned long long)pending[i].guard, (long)ret);
            }
        }
    }
}

static void remember_cfpreferences_reply_port(mach_port_name_t port,
                                              bool strace)
{
    if (port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&cfprefs_reply_port_lock);
    for (int i = 0; i < cfprefs_reply_port_count; i++) {
        if (cfprefs_reply_ports[i] == port) {
            pthread_mutex_unlock(&cfprefs_reply_port_lock);
            return;
        }
    }
    if (cfprefs_reply_port_count < MAX_CFPREFERENCES_REPLY_PORTS) {
        cfprefs_reply_ports[cfprefs_reply_port_count++] = port;
    }
    pthread_mutex_unlock(&cfprefs_reply_port_lock);

    if (strace) {
        fprintf(stderr,
                "  CFPreferences: short-timeout reply port 0x%x\n", port);
    }
}

static bool is_cfpreferences_reply_port(mach_port_name_t port)
{
    bool found = false;

    pthread_mutex_lock(&cfprefs_reply_port_lock);
    for (int i = 0; i < cfprefs_reply_port_count; i++) {
        if (cfprefs_reply_ports[i] == port) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&cfprefs_reply_port_lock);
    return found;
}

static void forget_cfpreferences_reply_port(mach_port_name_t port)
{
    pthread_mutex_lock(&cfprefs_reply_port_lock);
    for (int i = 0; i < cfprefs_reply_port_count; i++) {
        if (cfprefs_reply_ports[i] == port) {
            cfprefs_reply_ports[i] =
                cfprefs_reply_ports[--cfprefs_reply_port_count];
            break;
        }
    }
    pthread_mutex_unlock(&cfprefs_reply_port_lock);
}

static void remember_special_reply_port(mach_port_name_t port, bool strace)
{
    if (port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&special_reply_port_lock);
    for (int i = 0; i < special_reply_port_count; i++) {
        if (special_reply_ports[i] == port) {
            pthread_mutex_unlock(&special_reply_port_lock);
            return;
        }
    }
    if (special_reply_port_count < MAX_SPECIAL_REPLY_PORTS) {
        special_reply_ports[special_reply_port_count++] = port;
    }
    pthread_mutex_unlock(&special_reply_port_lock);

    if (strace) {
        fprintf(stderr, "  special reply port 0x%x tracked\n", port);
    }
}

static bool is_special_reply_port(mach_port_name_t port)
{
    bool found = false;

    pthread_mutex_lock(&special_reply_port_lock);
    for (int i = 0; i < special_reply_port_count; i++) {
        if (special_reply_ports[i] == port) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&special_reply_port_lock);
    return found;
}

static void forget_special_reply_port(mach_port_name_t port)
{
    pthread_mutex_lock(&special_reply_port_lock);
    for (int i = 0; i < special_reply_port_count; i++) {
        if (special_reply_ports[i] == port) {
            special_reply_ports[i] =
                special_reply_ports[--special_reply_port_count];
            break;
        }
    }
    pthread_mutex_unlock(&special_reply_port_lock);
}

static void remember_analyticsd_service_port(mach_port_name_t port,
                                             bool strace)
{
    if (port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&analyticsd_service_port_lock);
    for (int i = 0; i < analyticsd_service_port_count; i++) {
        if (analyticsd_service_ports[i] == port) {
            pthread_mutex_unlock(&analyticsd_service_port_lock);
            return;
        }
    }
    if (analyticsd_service_port_count < MAX_ANALYTICSD_SERVICE_PORTS) {
        analyticsd_service_ports[analyticsd_service_port_count++] = port;
    }
    pthread_mutex_unlock(&analyticsd_service_port_lock);

    if (strace) {
        fprintf(stderr, "  analyticsd service port 0x%x tracked\n", port);
    }
}

static void remember_cgs_window_memory_object_port(mach_port_name_t port)
{
    if (MACH_PORT_VALID(port)) {
        cgs_window_memory_object_port = port;
    }
}

static abi_long copy_external_mach_mapping_to_guest(mach_vm_address_t host_addr,
                                                    mach_vm_size_t size,
                                                    abi_ulong preferred_guest,
                                                    const char *label)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    abi_long guest_addr;

    if (preferred_guest) {
        flags |= MAP_FIXED;
    }
    guest_addr = target_mmap(preferred_guest, size, PROT_READ | PROT_WRITE,
                             flags, -1, 0);
    if (guest_addr == (abi_long)-1 ||
        (preferred_guest && (abi_ulong)guest_addr != preferred_guest)) {
        if (guest_addr != (abi_long)-1) {
            target_munmap(guest_addr, size);
        }
        if (preferred_guest) {
            target_munmap(preferred_guest, size);
            preferred_guest = 0;
            guest_addr = target_mmap(0, size, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
        if (guest_addr == (abi_long)-1) {
            return (abi_long)-1;
        }
    }

    memcpy(g2h_untagged(guest_addr), (void *)(uintptr_t)host_addr, size);
    mach_vm_deallocate(mach_task_self(), host_addr, size);
    if (do_strace) {
        fprintf(stderr,
                "  MIG mach_vm_map: copied external %s mapping %p "
                "-> guest 0x%llx size=0x%llx\n",
                label, (void *)(uintptr_t)host_addr,
                (unsigned long long)guest_addr,
                (unsigned long long)size);
    }
    return guest_addr;
}

static bool external_ool_identity_mapping_contains(abi_ulong start,
                                                   abi_ulong size)
{
    for (int i = 0; i < external_ool_identity_mapping_count; i++) {
        abi_ulong map_start = external_ool_identity_mappings[i].start;
        abi_ulong map_size = external_ool_identity_mappings[i].size;

        if (start >= map_start &&
            start - map_start <= map_size &&
            size <= map_size - (start - map_start)) {
            return true;
        }
    }
    return false;
}

static void remember_external_ool_identity_mapping(abi_ulong start,
                                                  abi_ulong size)
{
    if (external_ool_identity_mapping_count >=
        MAX_EXTERNAL_OOL_IDENTITY_MAPPINGS) {
        return;
    }
    external_ool_identity_mappings[external_ool_identity_mapping_count++] =
        (ExternalOolIdentityMapping) {
            .start = start,
            .size = size,
        };
}

static bool guest_range_pages_unmapped(abi_ulong start, abi_ulong size)
{
    unsigned long page_size = qemu_real_host_page_size();
    abi_ulong end = start + size - 1;

    if (end < start || !guest_range_valid_untagged(start, size)) {
        return false;
    }
    start &= ~(abi_ulong)(page_size - 1);
    end |= (abi_ulong)(page_size - 1);
    for (abi_ulong addr = start; addr <= end; addr += page_size) {
        if (page_get_flags(addr) & PAGE_VALID) {
            return false;
        }
        if (addr > end - page_size) {
            break;
        }
    }
    return true;
}

static bool copy_external_ool_identity_to_guest(void *host_addr,
                                                mach_msg_size_t size,
                                                abi_long *guest_addr_out)
{
    uintptr_t host_start = (uintptr_t)host_addr;
    abi_ulong guest_addr = (abi_ulong)host_start;
    unsigned long page_size = qemu_real_host_page_size();
    abi_ulong page_start;
    abi_ulong page_offset;
    abi_ulong map_size;
    abi_long map_ret;
    bool already_mapped;

    /*
     * Some IOKit/IOGPU OOL payloads contain self-referential pointers to the
     * kernel-chosen OOL address.  Preserve low external host OOL addresses as
     * guest-visible addresses when the range is otherwise unused.
     */
    if (!guest_base || host_start >= guest_base ||
        guest_addr < 0x100000000ULL ||
        !guest_range_valid_untagged(guest_addr, size)) {
        return false;
    }
    page_start = guest_addr & ~(abi_ulong)(page_size - 1);
    page_offset = guest_addr - page_start;
    if (size > (abi_ulong)-1 - page_offset ||
        page_offset + size > (abi_ulong)-1 - (page_size - 1)) {
        return false;
    }
    map_size = (page_offset + size + page_size - 1) &
               ~(abi_ulong)(page_size - 1);
    already_mapped = external_ool_identity_mapping_contains(page_start,
                                                            map_size);
    if (!already_mapped && !guest_range_pages_unmapped(page_start, map_size)) {
        return false;
    }
    if (!already_mapped) {
        map_ret = target_mmap(page_start, map_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                              -1, 0);
        if (map_ret != (abi_long)page_start) {
            if (map_ret >= 0) {
                target_munmap(map_ret, map_size);
            }
            return false;
        }
        remember_external_ool_identity_mapping(page_start, map_size);
    }

    memcpy(g2h_untagged(guest_addr), host_addr, size);
    *guest_addr_out = guest_addr;
    if (do_strace) {
        fprintf(stderr,
                "    OOL identity: host %p -> guest 0x%llx size=%u%s\n",
                host_addr, (unsigned long long)guest_addr, size,
                already_mapped ? " update" : "");
    }
    return true;
}

static void relocate_external_ool_pointers(void *guest_buf,
                                           mach_msg_size_t size,
                                           void *host_addr,
                                           abi_ulong guest_addr)
{
    uintptr_t host_start = (uintptr_t)host_addr;
    uintptr_t host_last;
    int relocated = 0;

    if (!guest_buf || !host_addr || size < sizeof(uint64_t)) {
        return;
    }
    host_last = host_start + size - 1;
    if (host_last < host_start) {
        return;
    }

    for (mach_msg_size_t off = 0; off + sizeof(uint64_t) <= size; off += 8) {
        uint64_t value;

        memcpy(&value, (uint8_t *)guest_buf + off, sizeof(value));
        if (value >= host_start && value <= host_last) {
            uint64_t replacement = guest_addr + (value - host_start);

            memcpy((uint8_t *)guest_buf + off, &replacement,
                   sizeof(replacement));
            relocated++;
            if (do_strace) {
                fprintf(stderr,
                    "    OOL relocate: +0x%x 0x%llx -> 0x%llx\n",
                    off, (unsigned long long)value,
                    (unsigned long long)replacement);
            }
        }
    }
    if (do_strace && relocated > 0) {
        fprintf(stderr, "    OOL relocate: patched %d pointer%s for %p "
                "size=%u guest=0x%llx\n",
                relocated, relocated == 1 ? "" : "s", host_addr, size,
                (unsigned long long)guest_addr);
    }
}

static void relocate_external_ool_base_unaligned(void *guest_buf,
                                                 mach_msg_size_t size,
                                                 void *host_addr,
                                                 abi_ulong guest_addr)
{
    uint64_t host_base = (uintptr_t)host_addr;
    uint64_t replacement = guest_addr;
    int relocated = 0;

    if (!guest_buf || !host_addr || size < sizeof(host_base)) {
        return;
    }

    for (mach_msg_size_t off = 0; off + sizeof(host_base) <= size; off++) {
        uint64_t value;

        memcpy(&value, (uint8_t *)guest_buf + off, sizeof(value));
        if (value != host_base) {
            continue;
        }

        memcpy((uint8_t *)guest_buf + off, &replacement, sizeof(replacement));
        relocated++;
        if (do_strace) {
            fprintf(stderr,
                    "    OOL base relocate: +0x%x 0x%llx -> 0x%llx\n",
                    off, (unsigned long long)value,
                    (unsigned long long)replacement);
        }
        off += sizeof(host_base) - 1;
    }

    if (do_strace && relocated > 0) {
        fprintf(stderr, "    OOL base relocate: patched %d pointer%s for %p "
                "size=%u guest=0x%llx\n",
                relocated, relocated == 1 ? "" : "s", host_addr, size,
                (unsigned long long)guest_addr);
    }
}

static int mach_vm_anon_tag_fd(uint64_t flags)
{
    uint32_t alias = (uint32_t)flags & VM_FLAGS_ALIAS_MASK;

    return alias ? (int)alias : -1;
}

static abi_long target_mmap_mach_anywhere_aligned(abi_ulong len,
                                                  abi_ulong mask,
                                                  int prot,
                                                  int flags,
                                                  int fd,
                                                  off_t offset)
{
    abi_ulong page_size = MAX(TARGET_PAGE_SIZE,
                              (abi_ulong)qemu_real_host_page_size());
    abi_ulong page_mask = page_size - 1;
    abi_ulong rounded_len;
    abi_ulong reserve_len;
    abi_long reserve;
    abi_ulong aligned;
    abi_ulong prefix;
    abi_ulong suffix_start;
    abi_ulong reserve_end;

    if (mask <= page_mask) {
        return target_mmap(0, len, prot, flags, fd, offset);
    }

    rounded_len = (len + page_mask) & ~page_mask;
    if (rounded_len < len || rounded_len > UINT64_MAX - mask - page_mask) {
        return -TARGET_ENOMEM;
    }
    reserve_len = (rounded_len + mask + page_mask) & ~page_mask;
    reserve = target_mmap(0, reserve_len, prot, flags, fd, offset);
    if (reserve < 0) {
        return reserve;
    }

    aligned = ((abi_ulong)reserve + mask) & ~mask;
    prefix = aligned - (abi_ulong)reserve;
    suffix_start = aligned + rounded_len;
    reserve_end = (abi_ulong)reserve + reserve_len;

    if (prefix) {
        target_munmap((abi_ulong)reserve, prefix);
    }
    if (suffix_start < reserve_end) {
        target_munmap(suffix_start, reserve_end - suffix_start);
    }

    return aligned;
}

static bool should_shadow_external_ool_identity(mach_msg_id_t msg_id)
{
    /*
     * Only a narrow set of replies is known to carry raw low-address host
     * pointers in OOL payloads.  Shadow those host VAs so any external pointer
     * references remain dereferenceable, while the descriptor itself can still
     * point at a normal guest scratch copy.
     */
    return msg_id == 32154 || msg_id == 40309 || msg_id == 1919706727;
}

typedef kern_return_t (*IOConnectTrap6Func)(mach_port_t, uint32_t,
                                            uintptr_t, uintptr_t, uintptr_t,
                                            uintptr_t, uintptr_t, uintptr_t);

static IOConnectTrap6Func get_host_ioconnect_trap6(void)
{
    static IOConnectTrap6Func fn;
    static bool initialized;

    if (!initialized) {
        void *handle = dlopen(
            "/System/Library/Frameworks/IOKit.framework/IOKit",
            RTLD_LAZY | RTLD_LOCAL);
        if (handle) {
            fn = (IOConnectTrap6Func)dlsym(handle, "IOConnectTrap6");
        }
        initialized = true;
    }
    return fn;
}

static uintptr_t translate_iokit_trap_arg(uintptr_t arg)
{
    if (arg && guest_range_valid_untagged(arg, 1) &&
        (page_get_flags((abi_ulong)arg) & PAGE_VALID)) {
        return (uintptr_t)g2h_untagged((abi_ulong)arg);
    }
    return arg;
}

static bool msg_contains_bytes(const void *buf, size_t size,
                               const char *needle)
{
    const uint8_t *p = buf;
    size_t nlen = strlen(needle);

    if (!buf || nlen == 0 || size < nlen) {
        return false;
    }

    for (size_t i = 0; i <= size - nlen; i++) {
        if (memcmp(p + i, needle, nlen) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_analyticsd_lookup_request(void *msg_buf,
                                         mach_msg_size_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;

    return hdr && hdr->msgh_id == 1073742628 &&
           msg_contains_bytes(msg_buf, send_size, "com.apple.analyticsd");
}

static bool is_cfpreferences_request(void *msg_buf,
                                     mach_msg_size_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;

    return hdr && hdr->msgh_id == 1073741824 &&
           hdr->msgh_local_port != MACH_PORT_NULL &&
           msg_contains_bytes(msg_buf, send_size, "CFPreferences");
}

static bool mach_port_name_is_port_set(mach_port_name_t port)
{
    mach_port_type_t ptype = 0;

    return port != MACH_PORT_NULL &&
           mach_port_type(mach_task_self(), port, &ptype) == KERN_SUCCESS &&
           (ptype & MACH_PORT_TYPE_PORT_SET);
}

static void trace_port_set_receive_status(mach_port_name_t port_set,
                                          const char *where,
                                          uint32_t iteration)
{
    mach_port_name_array_t members = NULL;
    mach_msg_type_number_t member_count = 0;
    kern_return_t kr;

    kr = mach_port_get_set_status(mach_task_self(), port_set, &members,
                                  &member_count);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr,
                "  mach_msg2[vec]: pset 0x%x %s[%u] "
                "get_set_status ret=%d\n",
                port_set, where, iteration, kr);
        return;
    }

    fprintf(stderr,
            "  mach_msg2[vec]: pset 0x%x %s[%u] members=%u\n",
            port_set, where, iteration, member_count);
    for (mach_msg_type_number_t i = 0; i < member_count; i++) {
        mach_port_status_t status = {0};
        mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;

        kr = mach_port_get_attributes(mach_task_self(), members[i],
                                      MACH_PORT_RECEIVE_STATUS,
                                      (mach_port_info_t)&status, &count);
        if (kr != KERN_SUCCESS) {
            fprintf(stderr,
                    "    member[%u]=0x%x status_ret=%d active=%d\n",
                    i, members[i], kr, is_port_active_rcv(members[i]));
            continue;
        }
        fprintf(stderr,
                "    member[%u]=0x%x pset=0x%x qlimit=%u msgcount=%u "
                "srights=%u sorights=%u active=%d\n",
                i, members[i], status.mps_pset, status.mps_qlimit,
                status.mps_msgcount, status.mps_srights,
                status.mps_sorights, is_port_active_rcv(members[i]));
    }

    if (members) {
        vm_deallocate(mach_task_self(), (vm_address_t)members,
                      member_count * sizeof(*members));
    }
}

static kern_return_t ipc_timeout_result(mach_port_name_t rcv_port,
                                        bool strace)
{
    if (mach_port_name_is_port_set(rcv_port)) {
        if (strace) {
            fprintf(stderr,
                "  ipc timeout on port set 0x%x — interrupted\n",
                rcv_port);
        }
        return 0x10004005;  /* MACH_RCV_INTERRUPTED */
    }

    if (!is_cfpreferences_reply_port(rcv_port) &&
        !is_special_reply_port(rcv_port)) {
        if (strace) {
            fprintf(stderr,
                "  ipc timeout on untracked port 0x%x — interrupted\n",
                rcv_port);
        }
        return 0x10004005;  /* MACH_RCV_INTERRUPTED */
    }

    if (rcv_port == ipc_timeout_port) {
        ipc_timeout_count++;
        /* Same port: the streak of "1 timeout per port" is broken. */
        ipc_timeout_single_streak = 0;
    } else {
        /*
         * Port changed.  If the previous port saw only a single timeout
         * before being replaced, count that toward the streak.  This
         * detects the pattern where libdispatch creates a fresh special-
         * reply-port for every retry, preventing ipc_timeout_count from
         * ever exceeding 1 and stalling teardown indefinitely.
         */
        if (ipc_timeout_port != 0 && ipc_timeout_count == 1) {
            ipc_timeout_single_streak++;
        } else {
            ipc_timeout_single_streak = 0;
        }
        ipc_timeout_port = rcv_port;
        ipc_timeout_count = 1;
    }

    bool streak_exhausted =
        ipc_timeout_single_streak >= IPC_RECV_MAX_SINGLE_STREAK;

    if (ipc_timeout_count <= IPC_RECV_MAX_RETRY && !streak_exhausted) {
        if (strace) {
            fprintf(stderr,
                "  ipc timeout %d/%d on port 0x%x — interrupted\n",
                ipc_timeout_count, IPC_RECV_MAX_RETRY, rcv_port);
        }
        /*
         * Return MACH_RCV_INTERRUPTED — makes XPC/dispatch retry the receive.
         * MACH_RCV_TIMED_OUT must NOT be returned — dispatch aborts on it.
         */
        return 0x10004005;  /* MACH_RCV_INTERRUPTED */
    }

    ipc_timeout_port = 0;
    ipc_timeout_count = 0;
    ipc_timeout_single_streak = 0;
    if (strace) {
        fprintf(stderr,
            "  ipc timeout exhausted on port 0x%x — port died%s\n",
            rcv_port,
            streak_exhausted ? " (single-streak limit)" : "");
    }
    forget_cfpreferences_reply_port(rcv_port);
    forget_special_reply_port(rcv_port);
    return 0x10004009;  /* MACH_RCV_PORT_DIED — graceful teardown */
}

static bool reply_port_received_mach_notification(mach_port_name_t rcv_port,
                                                  const void *reply_buf)
{
    const mach_msg_header_t *hdr = reply_buf;

    return hdr &&
           (is_cfpreferences_reply_port(rcv_port) ||
            is_special_reply_port(rcv_port)) &&
           hdr->msgh_id >= MACH_NOTIFY_FIRST &&
           hdr->msgh_id <= MACH_NOTIFY_LAST;
}

static bool receive_port_has_zero_qlimit(mach_port_name_t port)
{
    mach_port_status_t status = {0};
    mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;

    if (mach_port_get_attributes(mach_task_self(), port,
                                 MACH_PORT_RECEIVE_STATUS,
                                 (mach_port_info_t)&status,
                                 &count) != KERN_SUCCESS) {
        return false;
    }

    return status.mps_qlimit == MACH_PORT_QLIMIT_ZERO;
}

static mach_timespec_t timeout_ms_to_mach_timespec(uint64_t timeout_ms)
{
    mach_timespec_t ts;

    ts.tv_sec = timeout_ms / 1000;
    ts.tv_nsec = (timeout_ms % 1000) * 1000000;
    return ts;
}

static uint64_t mach_timespec_to_timeout_ms(unsigned int sec, clock_res_t nsec)
{
    uint64_t timeout_ms = (uint64_t)sec * 1000;

    timeout_ms += ((uint64_t)nsec + 999999) / 1000000;
    return timeout_ms;
}

static kern_return_t semaphore_wait_with_polling(semaphore_t sem,
                                                 uint64_t timeout_ms,
                                                 bool indefinite)
{
    uint64_t remaining = timeout_ms;

    service_pending_workloop_reqs();

    while (indefinite || remaining > 0) {
        uint64_t slice = indefinite || remaining > WORKLOOP_POLL_SLICE_MS
            ? WORKLOOP_POLL_SLICE_MS : remaining;
        kern_return_t ret;

        service_workloop_machport_events();
        service_workq_notification_events();
        ret = semaphore_timedwait(sem, timeout_ms_to_mach_timespec(slice));
        if (ret != KERN_OPERATION_TIMED_OUT) {
            return ret;
        }

        if (!indefinite) {
            if (remaining <= slice) {
                return ret;
            }
            remaining -= slice;
        }

        service_pending_workloop_reqs();
    }

    return KERN_OPERATION_TIMED_OUT;
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

static kern_return_t host_mk_timer_arm_leeway(mach_port_name_t name,
                                              uint64_t flags,
                                              uint64_t expire_time,
                                              uint64_t leeway)
{
    register uint64_t x0 __asm__("x0") = name;
    register uint64_t x1 __asm__("x1") = flags;
    register uint64_t x2 __asm__("x2") = expire_time;
    register uint64_t x3 __asm__("x3") = leeway;
    register int x16 __asm__("x16") = -95;
    __asm__ volatile(
        "svc #0x80"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x16)
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
static bool mig_reply_fits(mach_msg_size_t reply_buf_size, size_t reply_size)
{
    return reply_size <= UINT32_MAX && reply_buf_size >= reply_size;
}

static bool handle_mig_message(void *buf, void *reply_buf,
                               mach_msg_size_t reply_buf_size,
                               uint64_t options, kern_return_t *ret_out)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;
    if (!hdr || !reply_buf) {
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
        if (count > ARRAY_SIZE(info_buf)) {
            count = ARRAY_SIZE(info_buf);
        }
        kern_return_t kr = host_info(mach_host_self(), flavor,
                                     (host_info_t)info_buf, &count);

        /* Pack MIG reply into the caller's receive buffer. */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            mach_msg_type_number_t count;
            int data[64];
        } *reply = reply_buf;
        mach_msg_size_t reply_size = sizeof(mach_msg_header_t) +
                                     sizeof(NDR_record_t) + 8 +
                                     count * sizeof(int);

        if (count > ARRAY_SIZE(reply->data) ||
            !mig_reply_fits(reply_buf_size, reply_size)) {
            return false;
        }

        reply->hdr.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = reply_size;
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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
         * Maps memory into the task's address space. Anonymous mappings
         * are handled with target_mmap(); mappings backed by a memory
         * object are installed with host mach_vm_map() at the matching
         * host address inside the guest reservation.
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
        int max_prot = req->max_protection;
        vm_inherit_t inheritance = req->inheritance;
        memory_object_name_t object = req->object.name;
        mach_vm_offset_t offset = req->offset;
        boolean_t copy = req->copy;
        int anon_fd = mach_vm_anon_tag_fd(flags);

        if (do_strace) {
            uint32_t *words = (uint32_t *)buf;
            fprintf(stderr, "  MIG mach_vm_map request words:");
            for (int wi = 0; wi < 25; wi++) {
                fprintf(stderr, " %08x", words[wi]);
            }
            fprintf(stderr, "\n");
            fprintf(stderr,
                    "  MIG mach_vm_map descriptor: name=0x%x disp=%u "
                    "type=%u count=%u\n",
                    req->object.name, req->object.disposition,
                    req->object.type, req->body.msgh_descriptor_count);
        }

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
        bool used_object = false;
        abi_long reserved_start = 0;
        kern_return_t object_map_kr = KERN_SUCCESS;

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
        if (MACH_PORT_VALID(object)) {
            mach_vm_address_t host_addr;
            kern_return_t kr;
            int map_flags = flags;

            used_object = true;
            if (flags & VM_FLAGS_ANYWHERE) {
                abi_long reserve = target_mmap_mach_anywhere_aligned(
                    size, req->mask, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                    anon_fd, 0);
                if (reserve < 0) {
                    result = -1;
                    goto mach_vm_map_done;
                }
                reserved_start = reserve;
                guest_start = reserved_start;
                host_addr = (mach_vm_address_t)(uintptr_t)
                    g2h_untagged(guest_start);
                map_flags = (flags & ~VM_FLAGS_ANYWHERE) | VM_FLAGS_OVERWRITE;
            } else {
                host_addr = guest_start;
                if (guest_base) {
                    host_addr = (mach_vm_address_t)(uintptr_t)
                        g2h_untagged(guest_start);
                }
            }

            kr = mach_vm_map(mach_task_self(), &host_addr, size,
                             req->mask, map_flags, object, offset, copy,
                             cur_prot, max_prot, inheritance);
            object_map_kr = kr;
            if (kr == KERN_SUCCESS && h2g_valid(host_addr)) {
                result = h2g(host_addr);
            } else {
                if (kr == KERN_SUCCESS) {
                    result = copy_external_mach_mapping_to_guest(
                        host_addr, size, reserved_start, "object");
                    reserved_start = 0;
                } else {
                    result = (abi_long)-1;
                    if (reserved_start) {
                        target_munmap(reserved_start, size);
                        reserved_start = 0;
                    }
                }
                if (result == (abi_long)-1 &&
                    size == 0xb0 && (flags & VM_FLAGS_ANYWHERE) &&
                    MACH_PORT_VALID(cgs_window_memory_object_port) &&
                    cgs_window_memory_object_port != object) {
                    mach_port_name_t retry_object =
                        cgs_window_memory_object_port;
                    abi_long retry_reserve =
                        target_mmap_mach_anywhere_aligned(
                            size, req->mask, PROT_NONE,
                            MAP_PRIVATE | MAP_ANONYMOUS, anon_fd, 0);
                    if (retry_reserve >= 0) {
                        kern_return_t retry_kr;

                        host_addr = (mach_vm_address_t)(uintptr_t)
                            g2h_untagged(retry_reserve);
                        map_flags =
                            (flags & ~VM_FLAGS_ANYWHERE) | VM_FLAGS_OVERWRITE;
                        retry_kr = mach_vm_map(
                            mach_task_self(), &host_addr, size, req->mask,
                            map_flags, retry_object, offset, copy,
                            cur_prot, max_prot, inheritance);
                        if (do_strace) {
                            fprintf(stderr,
                                "  MIG mach_vm_map: retry 0xb0 CGS object "
                                "inline=0x%x saved=0x%x kr=0x%x\n",
                                object, retry_object, retry_kr);
                        }
                        if (retry_kr == KERN_SUCCESS &&
                            h2g_valid(host_addr)) {
                            result = h2g(host_addr);
                            mach_port_deallocate(mach_task_self(),
                                                 retry_object);
                            cgs_window_memory_object_port = MACH_PORT_NULL;
                            object_map_kr = retry_kr;
                        } else if (retry_kr == KERN_SUCCESS) {
                            result = copy_external_mach_mapping_to_guest(
                                host_addr, size, retry_reserve,
                                "CGS object");
                            if (result != (abi_long)-1) {
                                mach_port_deallocate(mach_task_self(),
                                                     retry_object);
                                cgs_window_memory_object_port =
                                    MACH_PORT_NULL;
                                object_map_kr = retry_kr;
                            } else {
                                target_munmap(retry_reserve, size);
                            }
                        } else {
                            target_munmap(retry_reserve, size);
                        }
                    }
                }
                if (result == (abi_long)-1 && size == 0xb0 &&
                    (flags & VM_FLAGS_ANYWHERE)) {
                    result = target_mmap_mach_anywhere_aligned(
                        size, req->mask, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, anon_fd, 0);
                    if (do_strace) {
                        fprintf(stderr,
                                "  MIG mach_vm_map: fallback anonymous "
                                "window state map -> 0x%llx\n",
                                (unsigned long long)result);
                    }
                }
            }
        } else if (host_prot == PROT_NONE && guest_start != 0 &&
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
                                          anon_fd, 0);
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
            if (flags & VM_FLAGS_ANYWHERE) {
                result = target_mmap_mach_anywhere_aligned(
                    size, req->mask, host_prot, mflags, anon_fd, 0);
            } else {
                result = target_mmap(guest_start, size,
                                     host_prot, mflags, anon_fd, 0);
            }

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

mach_vm_map_done:

        if (MACH_PORT_VALID(object) &&
            req->object.disposition == MACH_MSG_TYPE_MOVE_SEND) {
            kern_return_t dealloc_ret =
                mach_port_deallocate(mach_task_self(), object);
            if (do_strace) {
                fprintf(stderr,
                        "  MIG mach_vm_map: consumed moved object send "
                        "right=0x%x ret=%d\n", object, dealloc_ret);
            }
        }

        if (do_strace) {
            fprintf(stderr, "  MIG mach_vm_map: addr=0x%llx size=0x%llx "
                    "flags=0x%x prot=%d object=0x%x kr=0x%x "
                    "%s→ result=0x%llx\n",
                    (unsigned long long)addr, (unsigned long long)size,
                    flags, cur_prot, object, object_map_kr,
                    used_object ? "" : "(anon) ",
                    (unsigned long long)result);
        }

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            uint64_t address;
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

        kern_return_t kr;
        if (result < 0) {
            kr = KERN_NO_SPACE;
            reply->address = 0;
        } else {
            if (used_object) {
                int page_flags = PAGE_VALID;

                if (host_prot & PROT_READ) {
                    page_flags |= PAGE_READ;
                }
                if (host_prot & PROT_WRITE) {
                    page_flags |= PAGE_WRITE;
                }
                if (host_prot & PROT_EXEC) {
                    page_flags |= PAGE_EXEC;
                }
                page_set_flags(result, result + size - 1, page_flags, ~0);
            }
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
    case 4813: {
        /*
         * mach_vm_remap — MIG subsystem mach_vm, routine 13.
         * Remaps an existing range into the current task. Same-task remaps
         * carry guest addresses, so translate them before calling the host
         * kernel.
         *
         * Request (COMPLEX): header(24) + body(4) + port_desc(12) +
         *   NDR(8) + target_address(8) + size(8) + mask(8) + flags(4) +
         *   src_address(8) + copy(4) + inheritance(4) = 92
         * Reply: header(24) + NDR(8) + retcode(4) + target_address(8) +
         *   cur_protection(4) + max_protection(4) = 52
         */
        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t src_task;
            NDR_record_t NDR;
            uint64_t target_address;
            uint64_t size;
            uint64_t mask;
            int flags;
            uint64_t src_address;
            int copy;
            int inheritance;
        } *req = buf;

        mach_vm_address_t target_addr = req->target_address;
        mach_vm_size_t size = req->size;
        int flags = req->flags;
        mach_port_t src_task = req->src_task.name;
        mach_vm_address_t src_addr = req->src_address;
        boolean_t copy = req->copy;
        vm_inherit_t inheritance = req->inheritance;
        mach_vm_address_t host_target = target_addr;
        mach_vm_address_t host_src = src_addr;
        vm_prot_t cur_prot = 0;
        vm_prot_t max_prot = 0;
        kern_return_t kr;
        abi_long result = -1;
        abi_long reserved_start = 0;
        int remap_flags = flags;

        if (src_task == MACH_PORT_NULL) {
            src_task = mach_task_self();
        }

        if (src_task == mach_task_self() && guest_base && src_addr != 0) {
            host_src = (mach_vm_address_t)(uintptr_t)
                g2h_untagged((abi_ulong)src_addr);
        }

        if (flags & VM_FLAGS_ANYWHERE) {
            abi_long reserve = target_mmap(0, size, PROT_NONE,
                                           MAP_PRIVATE | MAP_ANONYMOUS,
                                           -1, 0);
            if (reserve < 0) {
                kr = KERN_NO_SPACE;
                goto mach_vm_remap_done;
            }
            reserved_start = reserve;
            host_target = (mach_vm_address_t)(uintptr_t)
                g2h_untagged((abi_ulong)reserve);
            remap_flags = (flags & ~VM_FLAGS_ANYWHERE) | VM_FLAGS_OVERWRITE;
        } else if (guest_base && target_addr != 0) {
            host_target = (mach_vm_address_t)(uintptr_t)
                g2h_untagged((abi_ulong)target_addr);
        }

        kr = mach_vm_remap(mach_task_self(), &host_target, size,
                           req->mask, remap_flags, src_task, host_src, copy,
                           &cur_prot, &max_prot, inheritance);
        if (kr == KERN_SUCCESS && h2g_valid(host_target)) {
            result = h2g(host_target);
        } else {
            if (reserved_start) {
                target_munmap(reserved_start, size);
            }
            if (kr == KERN_SUCCESS) {
                kr = KERN_NO_SPACE;
            }
        }

mach_vm_remap_done:
        if (do_strace) {
            fprintf(stderr,
                    "  MIG mach_vm_remap: target=0x%llx size=0x%llx "
                    "flags=0x%x src_task=0x%x src=0x%llx copy=%d "
                    "-> kr=%d result=0x%llx cur=%d max=%d\n",
                    (unsigned long long)target_addr,
                    (unsigned long long)size,
                    flags, src_task,
                    (unsigned long long)src_addr,
                    copy, kr,
                    (unsigned long long)result,
                    cur_prot, max_prot);
        }

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            uint64_t target_address;
            int cur_protection;
            int max_protection;
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

        if (kr == KERN_SUCCESS) {
            int page_flags = PAGE_VALID;

            if (cur_prot & VM_PROT_READ) {
                page_flags |= PAGE_READ;
            }
            if (cur_prot & VM_PROT_WRITE) {
                page_flags |= PAGE_WRITE;
            }
            if (cur_prot & VM_PROT_EXECUTE) {
                page_flags |= PAGE_EXEC;
            }

            mmap_lock();
            page_set_flags(result, result + size - 1, page_flags, ~0);
            mmap_unlock();

            reply->target_address = (uint64_t)result;
            reply->cur_protection = cur_prot;
            reply->max_protection = max_prot;
        } else {
            reply->target_address = 0;
            reply->cur_protection = 0;
            reply->max_protection = 0;
        }

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = sizeof(*reply);
        reply->hdr.msgh_remote_port = MACH_PORT_NULL;
        reply->hdr.msgh_local_port = hdr->msgh_local_port;
        reply->hdr.msgh_id = msg_id + 100;  /* 4913 */
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
            } *reply = reply_buf;
            if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
                return false;
            }

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
            } *reply = reply_buf;
            if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
                return false;
            }

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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
        if (count > ARRAY_SIZE(info_buf)) {
            count = ARRAY_SIZE(info_buf);
        }
        kern_return_t kr = task_info(mach_task_self(), flavor,
                                     (task_info_t)info_buf, &count);

        struct __attribute__((packed)) {
            mach_msg_header_t hdr;
            NDR_record_t NDR;
            kern_return_t retval;
            mach_msg_type_number_t count;
            integer_t data[94];
        } *reply = reply_buf;
        mach_msg_size_t reply_size = sizeof(mach_msg_header_t) +
                                     sizeof(NDR_record_t) + 8 +
                                     count * sizeof(integer_t);

        if (count > ARRAY_SIZE(reply->data) ||
            !mig_reply_fits(reply_buf_size, reply_size)) {
            return false;
        }

        reply->hdr.msgh_bits =
            MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply->hdr.msgh_size = reply_size;
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
        } *reply = reply_buf;
        if (!mig_reply_fits(reply_buf_size, sizeof(*reply))) {
            return false;
        }

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
 * fixup_send_ool -- translate OOL descriptors in outgoing complex messages.
 *
 * When the guest sends a complex message, OOL descriptor addresses point
 * into guest address space.  The host kernel's copyin() operates on host
 * virtual addresses, so we add guest_base to each OOL pointer.
 * We also save original guest addresses to restore after the trap.
 */
#define OOL_SAVE_INLINE 16
typedef struct OOLSaveEntry {
    void **addr_ptr;
    void *orig;
    void *dealloc_desc;
    bool dealloc_desc_is_ports;
    boolean_t orig_deallocate;
} OOLSaveEntry;

struct ool_save {
    int count;
    int capacity;
    OOLSaveEntry *entries;
    OOLSaveEntry inline_entries[OOL_SAVE_INLINE];
};

static void ool_save_init(struct ool_save *save)
{
    save->count = 0;
    save->capacity = OOL_SAVE_INLINE;
    save->entries = save->inline_entries;
}

static void ool_save_destroy(struct ool_save *save)
{
    if (save->entries != save->inline_entries) {
        g_free(save->entries);
    }
    save->entries = NULL;
    save->capacity = 0;
    save->count = 0;
}

static void ool_save_remember(struct ool_save *save, void **addr_ptr)
{
    if (save->count == save->capacity) {
        int new_capacity = save->capacity * 2;
        OOLSaveEntry *new_entries;

        if (save->entries == save->inline_entries) {
            new_entries = g_new(OOLSaveEntry, new_capacity);
            memcpy(new_entries, save->entries,
                   save->count * sizeof(*new_entries));
        } else {
            new_entries = g_renew(OOLSaveEntry, save->entries, new_capacity);
        }
        save->entries = new_entries;
        save->capacity = new_capacity;
    }

    save->entries[save->count++] = (OOLSaveEntry) {
        .addr_ptr = addr_ptr,
        .orig = *addr_ptr,
    };
}

static void ool_save_remember_deallocate(struct ool_save *save,
                                         void *desc,
                                         bool is_ports,
                                         boolean_t deallocate)
{
    if (save->count == save->capacity) {
        int new_capacity = save->capacity * 2;
        OOLSaveEntry *new_entries;

        if (save->entries == save->inline_entries) {
            new_entries = g_new(OOLSaveEntry, new_capacity);
            memcpy(new_entries, save->inline_entries,
                   save->count * sizeof(OOLSaveEntry));
            save->entries = new_entries;
        } else {
            new_entries = g_renew(OOLSaveEntry, save->entries, new_capacity);
            save->entries = new_entries;
        }
        save->capacity = new_capacity;
    }

    save->entries[save->count++] = (OOLSaveEntry) {
        .dealloc_desc = desc,
        .dealloc_desc_is_ports = is_ports,
        .orig_deallocate = deallocate,
    };
}

static size_t mach_msg_descriptor_size(mach_msg_descriptor_type_t type)
{
    switch (type) {
    case MACH_MSG_PORT_DESCRIPTOR:
        return sizeof(mach_msg_port_descriptor_t);
    case MACH_MSG_OOL_DESCRIPTOR:
    case MACH_MSG_OOL_VOLATILE_DESCRIPTOR:
        return sizeof(mach_msg_ool_descriptor_t);
    case MACH_MSG_OOL_PORTS_DESCRIPTOR:
        return sizeof(mach_msg_ool_ports_descriptor_t);
#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
    case MACH_MSG_GUARDED_PORT_DESCRIPTOR:
        return sizeof(mach_msg_guarded_port_descriptor_t);
#endif
    default:
        return sizeof(mach_msg_type_descriptor_t);
    }
}

static bool mach_msg_disposition_moves_right(mach_msg_type_name_t disposition)
{
    return disposition == MACH_MSG_TYPE_MOVE_RECEIVE ||
           disposition == MACH_MSG_TYPE_MOVE_SEND ||
           disposition == MACH_MSG_TYPE_MOVE_SEND_ONCE;
}

static bool mach_msg_send_moves_rights(void *msg_buf, mach_msg_size_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;
    mach_msg_body_t *body;
    uint8_t *dp;
    uint8_t *end;

    if (!msg_buf || send_size < sizeof(mach_msg_header_t) ||
        !(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return false;
    }
    if (hdr->msgh_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t) ||
        hdr->msgh_size > send_size) {
        return false;
    }

    body = (mach_msg_body_t *)(hdr + 1);
    dp = (uint8_t *)(body + 1);
    end = (uint8_t *)hdr + hdr->msgh_size;

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        mach_msg_type_descriptor_t *td;
        size_t desc_size;

        if (dp + sizeof(mach_msg_type_descriptor_t) > end) {
            return false;
        }
        td = (mach_msg_type_descriptor_t *)dp;
        desc_size = mach_msg_descriptor_size(td->type);
        if (dp + desc_size > end) {
            return false;
        }

        switch (td->type) {
        case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t *pd =
                (mach_msg_port_descriptor_t *)dp;
            if (mach_msg_disposition_moves_right(pd->disposition)) {
                return true;
            }
            break;
        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op =
                (mach_msg_ool_ports_descriptor_t *)dp;
            if (mach_msg_disposition_moves_right(op->disposition)) {
                return true;
            }
            break;
        }
#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
        case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
            mach_msg_guarded_port_descriptor_t *gpd =
                (mach_msg_guarded_port_descriptor_t *)dp;
            if (mach_msg_disposition_moves_right(gpd->disposition)) {
                return true;
            }
            break;
        }
#endif
        default:
            break;
        }
        dp += desc_size;
    }

    return false;
}

static void remember_analyticsd_reply_ports(void *reply_buf,
                                            mach_msg_size_t reply_buf_size,
                                            bool strace)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)reply_buf;
    mach_msg_body_t *body;
    uint8_t *dp;
    uint8_t *end;

    if (!reply_buf || reply_buf_size < sizeof(*hdr) ||
        hdr->msgh_size < sizeof(*hdr) + sizeof(*body) ||
        hdr->msgh_size > reply_buf_size ||
        !(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return;
    }

    body = (mach_msg_body_t *)(hdr + 1);
    dp = (uint8_t *)(body + 1);
    end = (uint8_t *)hdr + hdr->msgh_size;

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        mach_msg_type_descriptor_t *td;
        size_t desc_size;

        if (dp + sizeof(*td) > end) {
            return;
        }
        td = (mach_msg_type_descriptor_t *)dp;
        desc_size = mach_msg_descriptor_size(td->type);
        if (dp + desc_size > end) {
            return;
        }

        switch (td->type) {
        case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t *pd =
                (mach_msg_port_descriptor_t *)dp;
            remember_analyticsd_service_port(pd->name, strace);
            break;
        }
#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
        case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
            mach_msg_guarded_port_descriptor_t *gpd =
                (mach_msg_guarded_port_descriptor_t *)dp;
            remember_analyticsd_service_port(gpd->name, strace);
            break;
        }
#endif
        default:
            break;
        }

        dp += desc_size;
    }
}

static void fixup_send_ool(void *msg_buf, uint32_t send_size,
                            struct ool_save *save)
{
    save->count = 0;
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;

    if (!guest_base) {
        return;
    }
    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return;
    }
    if (send_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        return;
    }

    mach_msg_body_t *body = (mach_msg_body_t *)(hdr + 1);
    uint8_t *dp = (uint8_t *)(body + 1);
    uint8_t *end = (uint8_t *)hdr + send_size;

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        if (dp + sizeof(mach_msg_type_descriptor_t) > end) break;
        mach_msg_type_descriptor_t *td = (mach_msg_type_descriptor_t *)dp;
        size_t desc_size = mach_msg_descriptor_size(td->type);
        if (dp + desc_size > end) break;

        switch (td->type) {
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool = (mach_msg_ool_descriptor_t *)dp;
            if (ool->deallocate) {
                ool_save_remember_deallocate(save, ool, false,
                                             ool->deallocate);
                ool->deallocate = false;
            }
            if (ool->address) {
                ool_save_remember(save, (void **)&ool->address);
                ool->address = (void *)((uintptr_t)ool->address +
                                        (uintptr_t)guest_base);
            }
            dp += sizeof(mach_msg_ool_descriptor_t);
            break;
        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op =
                (mach_msg_ool_ports_descriptor_t *)dp;
            if (op->deallocate) {
                ool_save_remember_deallocate(save, op, true,
                                             op->deallocate);
                op->deallocate = false;
            }
            if (op->address) {
                ool_save_remember(save, (void **)&op->address);
                op->address = (void *)((uintptr_t)op->address +
                                       (uintptr_t)guest_base);
            }
            dp += sizeof(mach_msg_ool_ports_descriptor_t);
            break;
        }
        case MACH_MSG_PORT_DESCRIPTOR:
            dp += sizeof(mach_msg_port_descriptor_t);
            break;
        default:
            dp += desc_size;
            break;
        }
    }
}

static void restore_send_ool(struct ool_save *save)
{
    for (int i = 0; i < save->count; i++) {
        if (save->entries[i].addr_ptr) {
            *save->entries[i].addr_ptr = save->entries[i].orig;
        }
        if (save->entries[i].dealloc_desc) {
            if (save->entries[i].dealloc_desc_is_ports) {
                mach_msg_ool_ports_descriptor_t *op =
                    save->entries[i].dealloc_desc;
                op->deallocate = save->entries[i].orig_deallocate;
            } else {
                mach_msg_ool_descriptor_t *ool =
                    save->entries[i].dealloc_desc;
                ool->deallocate = save->entries[i].orig_deallocate;
            }
        }
    }
}

static void debug_log_send_descriptors(void *msg_buf, uint32_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;
    mach_msg_body_t *body;
    uint8_t *dp;
    uint8_t *end;

    if (!do_strace || !msg_buf) {
        return;
    }
    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return;
    }
    if (hdr->msgh_id != 1999646836 &&
        hdr->msgh_id != 1073741824 &&
        hdr->msgh_id != 1073742031 &&
        hdr->msgh_id != 1073742125 &&
        hdr->msgh_id != 1073742628 &&
        hdr->msgh_id != 40209) {
        return;
    }
    if (send_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        return;
    }

    body = (mach_msg_body_t *)(hdr + 1);
    dp = (uint8_t *)(body + 1);
    end = (uint8_t *)hdr + send_size;

    fprintf(stderr,
            "  send descs: msg_id=%u count=%u send_size=%u\n",
            hdr->msgh_id, body->msgh_descriptor_count, send_size);

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        mach_msg_type_descriptor_t *td;

        if (dp + sizeof(mach_msg_type_descriptor_t) > end) {
            fprintf(stderr, "    desc[%u]: truncated\n", i);
            break;
        }
        td = (mach_msg_type_descriptor_t *)dp;
        size_t desc_size = mach_msg_descriptor_size(td->type);
        if (dp + desc_size > end) {
            fprintf(stderr, "    desc[%u]: truncated type=%u\n", i, td->type);
            break;
        }

        switch (td->type) {
        case MACH_MSG_PORT_DESCRIPTOR: {
            mach_msg_port_descriptor_t *pd =
                (mach_msg_port_descriptor_t *)dp;
            mach_port_type_t ptype = 0;
            kern_return_t pret =
                mach_port_type(mach_task_self(), pd->name, &ptype);
            fprintf(stderr,
                    "    SEND PORT desc[%u]: name=0x%x disp=%u "
                    "ptype_ret=%d ptype=0x%x\n",
                    i, pd->name, pd->disposition, pret, ptype);
            dp += sizeof(mach_msg_port_descriptor_t);
            break;
        }
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool =
                (mach_msg_ool_descriptor_t *)dp;
            fprintf(stderr,
                    "    SEND OOL desc[%u]: addr=%p size=%u copy=%u\n",
                    i, ool->address, ool->size, ool->copy);
            if (hdr->msgh_id == 40209 && ool->address && ool->size <= 64) {
                const uint8_t *bytes = ool->address;
                fprintf(stderr, "      SEND OOL data:");
                for (mach_msg_size_t bi = 0; bi < ool->size; bi++) {
                    fprintf(stderr, " %02x", bytes[bi]);
                }
                fprintf(stderr, "\n");
            }
            dp += sizeof(mach_msg_ool_descriptor_t);
            break;
        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op =
                (mach_msg_ool_ports_descriptor_t *)dp;
            fprintf(stderr,
                    "    SEND OOL_PORTS desc[%u]: addr=%p count=%u disp=%u\n",
                    i, op->address, op->count, op->disposition);
            if (hdr->msgh_id == 40209 && op->address && op->count <= 16) {
                const mach_port_t *ports = op->address;
                for (mach_msg_size_t pi = 0; pi < op->count; pi++) {
                    mach_port_type_t ptype = 0;
                    kern_return_t pret = mach_port_type(mach_task_self(),
                                                        ports[pi], &ptype);
                    fprintf(stderr,
                            "      SEND OOL_PORTS[%u]: name=0x%x "
                            "ptype_ret=%d ptype=0x%x\n",
                            pi, ports[pi], pret, ptype);
                }
            }
            dp += sizeof(mach_msg_ool_ports_descriptor_t);
            break;
        }
#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
        case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
            mach_msg_guarded_port_descriptor_t *gpd =
                (mach_msg_guarded_port_descriptor_t *)dp;
            mach_port_type_t ptype = 0;
            kern_return_t pret =
                mach_port_type(mach_task_self(), gpd->name, &ptype);
            fprintf(stderr,
                    "    SEND GUARDED_PORT desc[%u]: name=0x%x disp=%u "
                    "guard=0x%llx flags=0x%x ptype_ret=%d ptype=0x%x\n",
                    i, gpd->name, gpd->disposition,
                    (unsigned long long)gpd->context, gpd->flags,
                    pret, ptype);
            dp += sizeof(mach_msg_guarded_port_descriptor_t);
            break;
        }
#endif
        default:
            fprintf(stderr, "    SEND desc[%u]: type=%u\n", i, td->type);
            dp += desc_size;
            break;
        }
    }
}

static void debug_log_send_strings(void *msg_buf, uint32_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;
    const unsigned char *p = (const unsigned char *)msg_buf;

    if (!do_strace || !msg_buf) {
        return;
    }
    if (hdr->msgh_id != 1073741824 &&
        hdr->msgh_id != 1073742031 &&
        hdr->msgh_id != 1073742125 &&
        hdr->msgh_id != 1073742628) {
        return;
    }

    for (uint32_t i = 0; i < send_size; ) {
        uint32_t start = i;

        while (i < send_size && p[i] >= 0x20 && p[i] <= 0x7e) {
            i++;
        }
        if (i > start + 3) {
            fprintf(stderr, "  send str msg=%p id=%u @%u: %.*s\n",
                    msg_buf, hdr->msgh_id, start, (int)(i - start),
                    p + start);
        }
        if (i == start) {
            i++;
        }
    }
}

static bool msg_has_bytes(const uint8_t *buf, uint32_t len,
                          const char *needle)
{
    size_t needle_len = strlen(needle);

    if (needle_len == 0 || needle_len > len) {
        return false;
    }
    for (uint32_t i = 0; i + needle_len <= len; i++) {
        if (!memcmp(buf + i, needle, needle_len)) {
            return true;
        }
    }
    return false;
}

static bool xpc_lookup_u64_value_offset(uint8_t *buf, uint32_t len,
                                        const char *key, uint32_t *value_off)
{
    size_t key_len = strlen(key) + 1;
    size_t padded_key_len = (key_len + 3) & ~(size_t)3;

    for (uint32_t i = 0; i + padded_key_len + 12 <= len; i++) {
        if (!memcmp(buf + i, key, key_len) &&
            !memcmp(buf + i + padded_key_len, "\x00\x40\x00\x00", 4)) {
            *value_off = i + padded_key_len + 4;
            return true;
        }
    }
    return false;
}

static bool normalize_launchservices_lookup(void *msg_buf, uint32_t send_size)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)msg_buf;
    uint8_t *buf = msg_buf;
    uint32_t handle_off = 0;
    uint32_t type_off = 0;
    uint64_t type = 0;
    uint64_t default_handle = 0;
    uint64_t default_lookup_type = 7;

    if (!msg_buf || send_size < sizeof(*hdr) || hdr->msgh_size > send_size ||
        hdr->msgh_id != 1073742628) {
        return false;
    }
    if (!msg_has_bytes(buf, send_size, "com.apple.lsd.mapdb") &&
        !msg_has_bytes(buf, send_size, "com.apple.lsd.modifydb")) {
        return false;
    }
    if (!xpc_lookup_u64_value_offset(buf, send_size, "handle", &handle_off) ||
        !xpc_lookup_u64_value_offset(buf, send_size, "type", &type_off)) {
        return false;
    }

    memcpy(&type, buf + type_off, sizeof(type));
    if (type != 2) {
        return false;
    }

    /*
     * Guest libxpc is allowed to set a target UID because we synthesize its
     * per-user launchd entitlement.  The forwarded lookup, however, is made
     * by the host QEMU process, whose real audit token lacks that entitlement.
     * LaunchServices accepts the default bootstrap lookup for these services,
     * so translate the per-user request to the default-domain form before it
     * reaches host launchd.
     */
    memcpy(buf + handle_off, &default_handle, sizeof(default_handle));
    memcpy(buf + type_off, &default_lookup_type, sizeof(default_lookup_type));
    if (do_strace) {
        fprintf(stderr,
                "  normalized LaunchServices lookup to default domain\n");
    }
    return true;
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
static void fixup_mig_reply_port(mach_port_name_t name,
                                 mach_msg_type_name_t disposition,
                                 mach_port_name_t receive_set,
                                 uint32_t index,
                                 const char *kind,
                                 bool notification_msg)
{
    mach_port_type_t ptype = 0;
    kern_return_t ptype_ret =
        mach_port_type(mach_task_self(), name, &ptype);
    bool moved_receive = disposition == MACH_MSG_TYPE_MOVE_RECEIVE;

    if (!notification_msg &&
        moved_receive &&
        ptype_ret == KERN_SUCCESS && (ptype & MACH_PORT_TYPE_RECEIVE)) {
        mach_port_limits_t limits = {
            .mpl_qlimit = MACH_PORT_QLIMIT_SMALL,
        };
        kern_return_t lret =
            mach_port_set_attributes(mach_task_self(), name,
                                     MACH_PORT_LIMITS_INFO,
                                     (mach_port_info_t)&limits,
                                     MACH_PORT_LIMITS_INFO_COUNT);
        if (do_strace) {
            fprintf(stderr,
                "    port_set_limits: name=0x%x qlimit=%u ret=%d\n",
                name, limits.mpl_qlimit, lret);
        }
    }
    if (!notification_msg &&
        moved_receive &&
        ptype_ret == KERN_SUCCESS &&
        (ptype & MACH_PORT_TYPE_RECEIVE) &&
        receive_set != MACH_PORT_NULL) {
        mach_port_type_t set_type = 0;
        kern_return_t set_ret =
            mach_port_type(mach_task_self(), receive_set, &set_type);
        if (set_ret == KERN_SUCCESS &&
            (set_type & MACH_PORT_TYPE_PORT_SET)) {
            kern_return_t ins_ret =
                mach_port_insert_member(mach_task_self(), name, receive_set);
            if (do_strace) {
                fprintf(stderr,
                    "    auto_insert_member: port=0x%x set=0x%x ret=%d\n",
                    name, receive_set, ins_ret);
            }
        }
    }
    if (do_strace) {
        fprintf(stderr,
            "  %s desc[%u]: name=0x%x disp=%u type=0x%x%s\n",
            kind, index, name, disposition, ptype,
            notification_msg ? " notification" : "");
    }
}

static bool host_ool_range_to_guest(void *host_addr, mach_msg_size_t size,
                                    abi_ulong *guest_addr);
static void mark_guest_ool_mapping(abi_ulong guest_addr, mach_msg_size_t size);
static kern_return_t release_host_ool_mapping(void *host_addr,
                                              mach_msg_size_t size);

kern_return_t fixup_mig_reply_ool(void *reply_buf,
                                  mach_msg_size_t reply_buf_size,
                                  mach_port_name_t receive_set)
{
    mach_msg_header_t *hdr = (mach_msg_header_t *)reply_buf;
    mach_msg_size_t msg_size;
    mach_msg_body_t *body;
    uint8_t *dp;
    uint8_t *end;

    if (!guest_base) {
        return KERN_SUCCESS;  /* no translation needed */
    }
    if (reply_buf_size < sizeof(mach_msg_header_t)) {
        return KERN_INVALID_ARGUMENT;
    }

    msg_size = hdr->msgh_size;
    if (msg_size < sizeof(mach_msg_header_t) || msg_size > reply_buf_size) {
        if (do_strace) {
            fprintf(stderr,
                "  OOL fixup: invalid reply size msg=%u rcv=%u id=%u\n",
                msg_size, reply_buf_size, hdr->msgh_id);
        }
        return KERN_INVALID_ARGUMENT;
    }
    if (!(hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        return KERN_SUCCESS;  /* no descriptors */
    }
    if (msg_size < sizeof(mach_msg_header_t) + sizeof(mach_msg_body_t)) {
        return KERN_INVALID_ARGUMENT;
    }

    body = (mach_msg_body_t *)(hdr + 1);
    dp = (uint8_t *)(body + 1);
    end = (uint8_t *)hdr + msg_size;

    if (do_strace && body->msgh_descriptor_count > 0) {
        fprintf(stderr, "  OOL fixup: msg_id=%u desc_count=%u msg_size=%u\n",
                hdr->msgh_id, body->msgh_descriptor_count, hdr->msgh_size);
    }

    for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
        mach_msg_type_descriptor_t *td;
        size_t desc_size;

        if (dp + sizeof(mach_msg_type_descriptor_t) > end) {
            if (do_strace) {
                fprintf(stderr, "    DESC[%u] truncated: msg_id=%u "
                        "msg_size=%u off=%zu remaining=%zu need=%zu\n",
                        i, hdr->msgh_id, hdr->msgh_size,
                        (size_t)(dp - (uint8_t *)hdr),
                        (size_t)(end - dp),
                        sizeof(mach_msg_type_descriptor_t));
            }
            return KERN_INVALID_ARGUMENT;
        }
        td = (mach_msg_type_descriptor_t *)dp;
        desc_size = mach_msg_descriptor_size(td->type);
        if (do_strace) {
            size_t remaining = (size_t)(end - dp);
            size_t raw_len = MIN(remaining, (size_t)16);

            fprintf(stderr, "    DESC[%u] raw: msg_id=%u msg_size=%u off=%zu "
                    "remaining=%zu type=%u desc_size=%zu bytes:",
                    i, hdr->msgh_id, hdr->msgh_size,
                    (size_t)(dp - (uint8_t *)hdr), remaining, td->type,
                    desc_size);
            for (size_t bi = 0; bi < raw_len; bi++) {
                fprintf(stderr, " %02x", dp[bi]);
            }
            fprintf(stderr, "\n");
        }
        if (dp + desc_size > end) {
            if (do_strace) {
                fprintf(stderr, "    DESC[%u] overruns message: msg_id=%u "
                        "msg_size=%u off=%zu remaining=%zu desc_size=%zu "
                        "type=%u\n",
                        i, hdr->msgh_id, hdr->msgh_size,
                        (size_t)(dp - (uint8_t *)hdr),
                        (size_t)(end - dp), desc_size, td->type);
            }
            return KERN_INVALID_ARGUMENT;
        }

        switch (td->type) {
        case MACH_MSG_OOL_DESCRIPTOR:
        case MACH_MSG_OOL_VOLATILE_DESCRIPTOR: {
            mach_msg_ool_descriptor_t *ool = (mach_msg_ool_descriptor_t *)dp;
            void *host_addr = ool->address;
            mach_msg_size_t size = ool->size;

            if (do_strace) {
                fprintf(stderr,
                    "    OOL[%u] desc: addr=%p size=%u dealloc=%u copy=%u "
                    "type=%u\n",
                    i, host_addr, size, ool->deallocate, ool->copy,
                    ool->type);
            }
            if (host_addr && size > 0) {
                abi_long guest_addr;
                abi_ulong existing_guest_addr;

                if (host_ool_range_to_guest(host_addr, size,
                                            &existing_guest_addr)) {
                    mark_guest_ool_mapping(existing_guest_addr, size);
                    ool->address = (void *)(uintptr_t)existing_guest_addr;
                    if (do_strace) {
                        fprintf(stderr,
                            "    OOL[%u]: donated host %p -> guest 0x%llx "
                            "size=%u\n",
                            i, host_addr,
                            (unsigned long long)existing_guest_addr, size);
                    }
                } else {
                    kern_return_t dealloc_ret;
                    abi_long identity_guest_addr;

                    if (should_shadow_external_ool_identity(hdr->msgh_id)) {
                        (void)copy_external_ool_identity_to_guest(
                            host_addr, size, &identity_guest_addr);
                    }
                    guest_addr = target_mmap(0, size, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0);
                    if (guest_addr < 0) {
                        return KERN_RESOURCE_SHORTAGE;
                    }
                    void *guest_buf = g2h_untagged(guest_addr);
                    memcpy(guest_buf, host_addr, size);
                    if (hdr->msgh_id == 34103) {
                        relocate_external_ool_base_unaligned(guest_buf, size,
                                                             host_addr,
                                                             guest_addr);
                    }
                    relocate_external_ool_pointers(guest_buf, size, host_addr,
                                                   guest_addr);
                    dealloc_ret = release_host_ool_mapping(host_addr, size);
                    if (dealloc_ret != KERN_SUCCESS && do_strace) {
                        fprintf(stderr,
                            "    OOL[%u]: mach_vm_deallocate(%p,%u) -> %d\n",
                            i, host_addr, size, dealloc_ret);
                    }
                    ool->address = (void *)(uintptr_t)guest_addr;
                    if (do_strace) {
                        fprintf(stderr,
                            "    OOL[%u]: host %p -> guest 0x%llx size=%u\n",
                            i, host_addr, (unsigned long long)guest_addr,
                            size);
                        if (hdr->msgh_id == 40309 && size <= 32) {
                            uint8_t *bytes = g2h_untagged(guest_addr);
                            fprintf(stderr, "      data:");
                            for (mach_msg_size_t bi = 0; bi < size; bi++) {
                                fprintf(stderr, " %02x", bytes[bi]);
                            }
                            fprintf(stderr, "\n");
                        }
                    }
                }
            }
            dp += sizeof(mach_msg_ool_descriptor_t);
            break;
        }
        case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
            mach_msg_ool_ports_descriptor_t *op =
                (mach_msg_ool_ports_descriptor_t *)dp;
            void *host_addr = op->address;
            mach_msg_size_t count = op->count;

            if (do_strace) {
                fprintf(stderr,
                    "    OOL_PORTS[%u] desc: addr=%p count=%u disp=%u "
                    "dealloc=%u copy=%u type=%u\n",
                    i, host_addr, count, op->disposition, op->deallocate,
                    op->copy, op->type);
            }
            if (host_addr && count > 0) {
                mach_msg_size_t size;
                abi_long guest_addr;
                abi_ulong existing_guest_addr;

                if (count > UINT32_MAX / sizeof(mach_port_t)) {
                    return KERN_RESOURCE_SHORTAGE;
                }
                size = count * sizeof(mach_port_t);
                if (host_ool_range_to_guest(host_addr, size,
                                            &existing_guest_addr)) {
                    mark_guest_ool_mapping(existing_guest_addr, size);
                    op->address = (void *)(uintptr_t)existing_guest_addr;
                    if (do_strace) {
                        fprintf(stderr,
                            "    OOL_PORTS[%u]: donated host %p -> guest "
                            "0x%llx count=%u\n",
                            i, host_addr,
                            (unsigned long long)existing_guest_addr, count);
                    }
                } else {
                    kern_return_t dealloc_ret;

                    guest_addr = target_mmap(0, size, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS,
                                             -1, 0);
                    if (guest_addr < 0) {
                        return KERN_RESOURCE_SHORTAGE;
                    }
                    memcpy(g2h_untagged(guest_addr), host_addr, size);
                    dealloc_ret = release_host_ool_mapping(host_addr, size);
                    if (dealloc_ret != KERN_SUCCESS && do_strace) {
                        fprintf(stderr,
                            "    OOL_PORTS[%u]: "
                            "mach_vm_deallocate(%p,%u) -> %d\n",
                            i, host_addr, size, dealloc_ret);
                    }
                    op->address = (void *)(uintptr_t)guest_addr;
                    if (do_strace) {
                        fprintf(stderr,
                            "    OOL_PORTS[%u]: host %p -> guest "
                            "0x%llx count=%u\n",
                            i, host_addr, (unsigned long long)guest_addr,
                            count);
                    }
                }
            } else if (do_strace) {
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
            if (hdr->msgh_id == 30363 && i == 0) {
                remember_cgs_window_memory_object_port(pd->name);
                if (do_strace) {
                    fprintf(stderr,
                        "    CGSWindowConstruct memory object port=0x%x\n",
                        pd->name);
                }
            }
            fixup_mig_reply_port(
                pd->name, pd->disposition, receive_set, i, "PORT",
                hdr->msgh_id >= MACH_NOTIFY_FIRST &&
                hdr->msgh_id <= MACH_NOTIFY_LAST);
            dp += sizeof(mach_msg_port_descriptor_t);
            break;
        }
#ifdef MACH_MSG_GUARDED_PORT_DESCRIPTOR
        case MACH_MSG_GUARDED_PORT_DESCRIPTOR: {
            mach_msg_guarded_port_descriptor_t *gpd =
                (mach_msg_guarded_port_descriptor_t *)dp;
            fixup_mig_reply_port(
                gpd->name, gpd->disposition, receive_set, i, "GUARDED_PORT",
                hdr->msgh_id >= MACH_NOTIFY_FIRST &&
                hdr->msgh_id <= MACH_NOTIFY_LAST);
            dp += sizeof(mach_msg_guarded_port_descriptor_t);
            break;
        }
#endif
        default:
            if (do_strace) {
                fprintf(stderr,
                    "  UNKNOWN desc[%u]: type=%u\n", i, td->type);
            }
            dp += desc_size;
            break;
        }
    }

    return KERN_SUCCESS;
}

static bool host_ool_range_to_guest(void *host_addr, mach_msg_size_t size,
                                    abi_ulong *guest_addr)
{
    uintptr_t host_start = (uintptr_t)host_addr;
    uintptr_t host_last;

    if (!host_addr || size == 0) {
        return false;
    }
    host_last = host_start + size - 1;
    if (host_last < host_start ||
        (guest_base != 0 && host_start < guest_base) ||
        !h2g_valid(host_start) || !h2g_valid(host_last)) {
        return false;
    }

    *guest_addr = h2g(host_start);
    return true;
}

static void mark_guest_ool_mapping(abi_ulong guest_addr, mach_msg_size_t size)
{
    mmap_lock();
    page_set_flags(guest_addr, guest_addr + size - 1,
                   PAGE_VALID | PAGE_READ | PAGE_WRITE, ~0);
    mmap_unlock();
}

static kern_return_t release_host_ool_mapping(void *host_addr,
                                              mach_msg_size_t size)
{
    return mach_vm_deallocate(mach_task_self(),
                              (mach_vm_address_t)(uintptr_t)host_addr,
                              (mach_vm_size_t)size);
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
#define MACH_TRAP_TASK_NAME_FOR_PID             (-44)
#define MACH_TRAP_TASK_FOR_PID                  (-45)
#define MACH_TRAP_PID_FOR_TASK                  (-46)
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
#define MACH_TRAP_MK_TIMER_ARM_LEEWAY           (-95)
#define MACH_TRAP_IOKIT_USER_CLIENT             (-100)

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
        remember_special_reply_port((mach_port_name_t)ret, do_strace);
        break;

    case MACH_TRAP_IOKIT_USER_CLIENT:
        /*
         * iokit_user_client_trap backs IOConnectTrap0..6.  These are fast
         * driver-specific calls, so forward through host IOKit and translate
         * guest-pointer-looking scalar arguments into host addresses.
         */
        {
            IOConnectTrap6Func fn = get_host_ioconnect_trap6();
            uintptr_t p1 = translate_iokit_trap_arg((uintptr_t)arg3);
            uintptr_t p2 = translate_iokit_trap_arg((uintptr_t)arg4);
            uintptr_t p3 = translate_iokit_trap_arg((uintptr_t)arg5);
            uintptr_t p4 = translate_iokit_trap_arg((uintptr_t)arg6);
            uintptr_t p5 = translate_iokit_trap_arg((uintptr_t)arg7);
            uintptr_t p6 = translate_iokit_trap_arg((uintptr_t)arg8);

            if (!fn) {
                ret = KERN_NOT_SUPPORTED;
            } else {
                ret = fn((mach_port_t)arg1, (uint32_t)arg2,
                         p1, p2, p3, p4, p5, p6);
            }
            if (do_strace) {
                fprintf(stderr,
                        "  iokit_user_client_trap: conn=0x%x index=%u "
                        "ret=0x%llx\n",
                        (mach_port_t)arg1, (uint32_t)arg2,
                        (unsigned long long)ret);
            }
        }
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
            int anon_fd = mach_vm_anon_tag_fd(flags);
            abi_ulong guest_start;

            if (flags & VM_FLAGS_ANYWHERE) {
                guest_start = 0;
            } else {
                guest_start = (abi_ulong)addr;
                mflags |= MAP_FIXED;
            }

            abi_long result = target_mmap(guest_start, (abi_ulong)arg3,
                                           PROT_READ | PROT_WRITE,
                                           mflags, anon_fd, 0);
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
        if (external_ool_identity_mapping_contains((abi_ulong)arg2,
                                                   (abi_ulong)arg3)) {
            if (do_strace) {
                fprintf(stderr,
                        "  vm_deallocate: preserving external OOL identity "
                        "0x%llx size=0x%llx\n",
                        (unsigned long long)(abi_ulong)arg2,
                        (unsigned long long)(abi_ulong)arg3);
            }
            ret = KERN_SUCCESS;
            break;
        }
        if (target_munmap((abi_ulong)arg2, (abi_ulong)arg3) == 0) {
            ret = KERN_SUCCESS;
        } else {
            ret = KERN_INVALID_ADDRESS;
        }
        break;

    case MACH_TRAP_VM_PROTECT:
        /*
         * _kernelrpc_mach_vm_protect_trap(target, addr, size, set_max, prot)
         */
        {
            abi_ulong guest_addr = (abi_ulong)arg2;
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
            int anon_fd = mach_vm_anon_tag_fd(flags);

            int host_prot = 0;
            if (cur_prot & VM_PROT_READ)    host_prot |= PROT_READ;
            if (cur_prot & VM_PROT_WRITE)   host_prot |= PROT_WRITE;
            if (cur_prot & VM_PROT_EXECUTE) host_prot |= PROT_EXEC;

            int mflags = MAP_PRIVATE | MAP_ANONYMOUS;
            abi_ulong guest_start;
            if (flags & VM_FLAGS_ANYWHERE) {
                guest_start = (abi_ulong)addr;
            } else {
                guest_start = (abi_ulong)addr;
                mflags |= MAP_FIXED;
            }

            abi_long result;
            if (flags & VM_FLAGS_ANYWHERE) {
                result = target_mmap_mach_anywhere_aligned(
                    size, (abi_ulong)arg4, host_prot, mflags, anon_fd, 0);
            } else {
                result = target_mmap(guest_start, size,
                                     host_prot, mflags, anon_fd, 0);
            }
            if (result < 0) {
                ret = KERN_NO_SPACE;
            } else {
                addr = (mach_vm_address_t)result;
                if (do_strace) {
                    fprintf(stderr, "  vm_map_trap: at 0x%llx size=0x%zx "
                            "prot=%d tag=%u\n",
                            (unsigned long long)addr, size, host_prot,
                            (unsigned)((uint32_t)flags >> 24));
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
                mach_port_name_t name = (mach_port_name_t)arg2;
                mach_port_type_t ptype = 0;

                if (is_port_active_rcv(name) &&
                    defer_active_rcv_port_op(
                        DEFER_ACTIVE_RCV_PORT_DEALLOCATE, name, 0, 0,
                        do_strace)) {
                    ret = KERN_SUCCESS;
                } else if (is_workq_notification_port(name) &&
                           mach_port_type(mach_task_self(), name, &ptype) ==
                               KERN_SUCCESS &&
                           (ptype & MACH_PORT_TYPE_RECEIVE)) {
                    if (do_strace) {
                        fprintf(stderr,
                                "  port_deallocate: preserving notification "
                                "receive port 0x%x ptype=0x%x\n",
                                name, ptype);
                    }
                    ret = KERN_SUCCESS;
                } else {
                    ret = mach_port_deallocate(mach_task_self(), name);
                }
            } else if (trap_num == MACH_TRAP_PORT_ALLOCATE) {
                /*
                 * _kernelrpc_mach_port_allocate_trap
                 * arg1=task, arg2=right, arg3=guest name_ptr
                 */
                mach_port_name_t name;
                ret = mach_port_allocate(mach_task_self(),
                                         (mach_port_right_t)arg2,
                                         &name);
                if (do_strace) {
                    fprintf(stderr,
                            "  port_allocate: right=%llu -> name=0x%x ret=%ld\n",
                            (unsigned long long)arg2, name, (long)ret);
                }
                if (ret == KERN_SUCCESS && arg3) {
                    memcpy(g2h_untagged(arg3), &name, sizeof(name));
                }
                if (ret == KERN_SUCCESS) {
                    forget_cfpreferences_reply_port(name);
                    forget_special_reply_port(name);
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
                if (do_strace) {
                    fprintf(stderr,
                            "  port_insert_right: name=0x%llx poly=0x%llx "
                            "disp=%llu ret=%ld\n",
                            (unsigned long long)arg2,
                            (unsigned long long)arg3,
                            (unsigned long long)arg4, (long)ret);
                }
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
                if (do_strace) {
                    fprintf(stderr,
                            "  port_construct: flags=0x%x mpl_qlimit=%u "
                            "ctx=0x%llx -> name=0x%x ret=%ld\n",
                            opts.flags, opts.mpl.mpl_qlimit,
                            (unsigned long long)arg3, name, (long)ret);
                }
                if (ret == KERN_SUCCESS && arg4) {
                    memcpy(g2h_untagged(arg4), &name, sizeof(name));
                }
                if (ret == KERN_SUCCESS) {
                    forget_cfpreferences_reply_port(name);
                    forget_special_reply_port(name);
                }
            } else if (trap_num == MACH_TRAP_PORT_DESTRUCT) {
                mach_port_name_t name = (mach_port_name_t)arg2;
                mach_port_delta_t srdelta = (mach_port_delta_t)arg3;
                mach_port_context_t guard = (mach_port_context_t)arg4;
                mach_port_type_t ptype = 0;

                if (is_port_active_rcv(name) &&
                    defer_active_rcv_port_op(
                        DEFER_ACTIVE_RCV_PORT_DESTRUCT, name, srdelta,
                        guard, do_strace)) {
                    ret = KERN_SUCCESS;
                } else if (is_workq_notification_port(name) &&
                           mach_port_type(mach_task_self(), name, &ptype) ==
                               KERN_SUCCESS &&
                           (ptype & MACH_PORT_TYPE_RECEIVE)) {
                    if (do_strace) {
                        fprintf(stderr,
                                "  port_destruct: preserving notification "
                                "receive port 0x%x ptype=0x%x\n",
                                name, ptype);
                    }
                    ret = KERN_SUCCESS;
                } else {
                    ret = mach_port_destruct(mach_task_self(), name,
                                             srdelta, guard);
                }
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
                if (ret == KERN_SUCCESS) {
                    record_workq_notification_port((mach_port_t)arg5,
                                                   (mach_port_t)arg2,
                                                   (mach_msg_id_t)arg3);
                }
                if (do_strace) {
                    fprintf(stderr, "  port_request_notification: "
                            "name=0x%llx msgid=%llu sync=%llu "
                            "notify=0x%llx poly=%llu prev=0x%x ret=%ld\n",
                            (unsigned long long)arg2,
                            (unsigned long long)arg3,
                            (unsigned long long)arg4,
                            (unsigned long long)arg5,
                            (unsigned long long)arg6,
                            previous, (long)ret);
                }
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
                if (do_strace) {
                    fprintf(stderr,
                            "  port_insert_member: member=0x%llx set=0x%llx "
                            "ret=%ld\n",
                            (unsigned long long)arg2,
                            (unsigned long long)arg3, (long)ret);
                }
            } else if (trap_num == MACH_TRAP_PORT_EXTRACT_MEMBER) {
                ret = mach_port_extract_member(mach_task_self(),
                                               (mach_port_name_t)arg2,
                                               (mach_port_name_t)arg3);
                if (do_strace) {
                    fprintf(stderr,
                            "  port_extract_member: member=0x%llx set=0x%llx "
                            "ret=%ld\n",
                            (unsigned long long)arg2,
                            (unsigned long long)arg3, (long)ret);
                }
            } else if (trap_num == MACH_TRAP_PORT_MOVE_MEMBER) {
                ret = mach_port_move_member(mach_task_self(),
                                            (mach_port_name_t)arg2,
                                            (mach_port_name_t)arg3);
                if (do_strace) {
                    fprintf(stderr,
                            "  port_move_member: member=0x%llx set=0x%llx "
                            "ret=%ld\n",
                            (unsigned long long)arg2,
                            (unsigned long long)arg3, (long)ret);
                }
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

    case MACH_TRAP_TASK_NAME_FOR_PID:
        ret = KERN_FAILURE;
        break;

    case MACH_TRAP_TASK_FOR_PID:
        ret = KERN_FAILURE;
        break;

    case MACH_TRAP_PID_FOR_TASK:
        {
            int pid = -1;

            ret = pid_for_task((mach_port_name_t)arg1, &pid);
            if (ret == KERN_SUCCESS && arg2) {
                memcpy(g2h_untagged(arg2), &pid, sizeof(pid));
            }
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
                        if (nentries >= 2) {
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
                        } else {
                            fprintf(stderr,
                                "    vec[0]: data=0x%llx rcv=0x%llx "
                                "ssz=%u rsz=%u | snd_count=%u "
                                "nentries=%d\n",
                                vec[0].msgv_data, vec[0].msgv_rcv_addr,
                                vec[0].msgv_send_size, vec[0].msgv_rcv_size,
                                (uint32_t)((uint64_t)arg3 >> 32), nentries);
                        }
                    }
                }

                /* MIG handling for vector messages */
                kern_return_t mig_ret;
                void *msg_buf =
                    (void *)(uintptr_t)vec[0].msgv_data;
                void *vec_reply_buf = NULL;
                mach_msg_size_t vec_reply_size = vec[0].msgv_rcv_size;
                if (vec_reply_size) {
                    vec_reply_buf = vec[0].msgv_rcv_addr ?
                        (void *)(uintptr_t)vec[0].msgv_rcv_addr : msg_buf;
                }
                if (msg_buf && handle_mig_message(msg_buf, vec_reply_buf,
                                                  vec_reply_size, options,
                                                  &mig_ret)) {
                    ret = mig_ret;
                } else {
                    /* Translate guest addresses in MIG requests */
                    struct ool_save ool_sv;
                    bool vec_analyticsd_lookup = false;
                    ool_save_init(&ool_sv);
                    if (msg_buf && (options & 0x1)) {
                        fixup_mig_request_addrs(msg_buf,
                            vec[0].msgv_send_size);
                        fixup_send_ool(msg_buf,
                            vec[0].msgv_send_size, &ool_sv);
                        normalize_launchservices_lookup(msg_buf,
                            vec[0].msgv_send_size);
                        vec_analyticsd_lookup = is_analyticsd_lookup_request(
                            msg_buf, vec[0].msgv_send_size);
                        debug_log_send_descriptors(msg_buf,
                            vec[0].msgv_send_size);
                        debug_log_send_strings(msg_buf,
                            vec[0].msgv_send_size);
                        if (is_cfpreferences_request(
                                msg_buf, vec[0].msgv_send_size)) {
                            mach_msg_header_t *hdr = msg_buf;
                            remember_cfpreferences_reply_port(
                                hdr->msgh_local_port, do_strace);
                        }
                    }

                    uint64_t vec_opts = options;
                    uint64_t vec_tmout = (uint64_t)arg8;
                    bool vec_added_tmout = false;
                    bool vec_poll_receive = false;
                    mach_port_name_t vec_rcv_port = MACH_PORT_NULL;

#define OPT_SEND   0x1
#define OPT_RCV    0x2
#define OPT_TMOUT  0x100
                    bool vec_has_send = (vec_opts & OPT_SEND) != 0;
                    bool vec_has_receive = (vec_opts & OPT_RCV) != 0;
                    bool vec_split_send_receive =
                        vec_has_send && vec_has_receive &&
                        !(vec_opts & (MACH64_SEND_KOBJECT_CALL |
                                      MACH64_SEND_MQ_CALL));
                    vec_split_send_receive = false;
                    bool vec_slice_receive =
                        vec_has_receive && (!vec_has_send ||
                                            vec_split_send_receive);
                    if (vec_opts & OPT_RCV) {
                        vec_rcv_port =
                            (uint32_t)((uint64_t)arg6 >> 32);
                        mark_active_rcv_port(vec_rcv_port);
                        service_pending_workloop_reqs();
                    }
                    if (vec_slice_receive) {
                        if (!(vec_opts & OPT_TMOUT)) {
                            vec_opts |= OPT_TMOUT;
                            vec_tmout =
                                (is_cfpreferences_reply_port(vec_rcv_port) ||
                                 is_special_reply_port(vec_rcv_port))
                                ? CFPREFERENCES_REPLY_TIMEOUT_MS
                                : IPC_RECV_TIMEOUT_MS;
                            vec_added_tmout = true;
                        }
                        vec_poll_receive = vec_added_tmout ||
                            vec_tmout >= WORKLOOP_POLL_SLICE_MS;
                    }
#undef OPT_SEND
#undef OPT_RCV
#undef OPT_TMOUT

                    if (vec_poll_receive) {
                        uint64_t remaining = vec_tmout;
                        uint64_t recv_opts = vec_opts;
                        uint32_t pset_trace_iteration = 0;
                        bool trace_pset = do_strace &&
                            mach_port_name_is_port_set(vec_rcv_port);

                        if (vec_split_send_receive) {
                            uint64_t send_opts = vec_opts & ~0x102ULL;

                            service_workloop_machport_events();
                            service_workq_notification_events();
                            ret = host_mach_msg2_trap(host_data, send_opts,
                                                      (uint64_t)arg3,
                                                      (uint64_t)arg4,
                                                      (uint64_t)arg5,
                                                      (uint64_t)arg6,
                                                      (uint64_t)arg7,
                                                      (uint64_t)arg8);
                            if (ret != KERN_SUCCESS) {
                                goto vec_after_receive;
                            }
                            recv_opts = vec_opts & ~0x1ULL;
                        }

                        if (trace_pset) {
                            trace_port_set_receive_status(vec_rcv_port,
                                                          "enter", 0);
                        }

                        while (1) {
                            uint64_t slice = remaining > WORKLOOP_POLL_SLICE_MS
                                ? WORKLOOP_POLL_SLICE_MS : remaining;

                            if (trace_pset && pset_trace_iteration > 0 &&
                                (pset_trace_iteration % 10) == 0) {
                                trace_port_set_receive_status(
                                    vec_rcv_port, "slice",
                                    pset_trace_iteration);
                            }
                            service_workloop_machport_events();
                            service_workq_notification_events();
                            ret = host_mach_msg2_trap(host_data, recv_opts,
                                                      (uint64_t)arg3,
                                                      (uint64_t)arg4,
                                                      (uint64_t)arg5,
                                                      (uint64_t)arg6,
                                                      (uint64_t)arg7,
                                                      slice);
                            if (ret != 0x10004003) {
                                if (trace_pset) {
                                    trace_port_set_receive_status(
                                        vec_rcv_port,
                                        ret == KERN_SUCCESS ? "return" :
                                                             "exit",
                                        pset_trace_iteration);
                                }
                                break;
                            }
                            pset_trace_iteration++;
                            if (remaining <= slice) {
                                uint32_t rcv_name =
                                    (uint32_t)((uint64_t)arg6 >> 32);
                                if (has_deferred_active_rcv_port_op(rcv_name)) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2[vec]: active receive "
                                            "port 0x%x was torn down\n",
                                            rcv_name);
                                    }
                                    ret = 0x10004009;
                                    break;
                                }
                                if (vec_added_tmout) {
                                    if (mach_port_name_is_port_set(rcv_name)) {
                                        ret = ipc_timeout_result(rcv_name,
                                                                 do_strace);
                                        break;
                                    }
                                    ret = ipc_timeout_result(rcv_name,
                                                             do_strace);
                                } else {
                                    ret = 0x10004003;
                                }
                                break;
                            }
                            remaining -= slice;
                            service_pending_workloop_reqs();
                        }
                    } else {
                        if (vec_opts & 0x2) {
                            service_workloop_machport_events();
                            service_workq_notification_events();
                        }
                        ret = host_mach_msg2_trap(host_data, vec_opts,
                                                  (uint64_t)arg3,
                                                  (uint64_t)arg4,
                                                  (uint64_t)arg5,
                                                  (uint64_t)arg6,
                                                  (uint64_t)arg7,
                                                  vec_tmout);
                    }
vec_after_receive:
                    if (ret == KERN_SUCCESS && (vec_opts & 0x2) &&
                        reply_port_received_mach_notification(vec_rcv_port,
                                                              vec_reply_buf)) {
                        mach_msg_header_t *nh = vec_reply_buf;
                        if (do_strace) {
                            fprintf(stderr,
                                "  mach_msg2[vec]: reply port 0x%x received "
                                "Mach notification id=%u -> PORT_DIED\n",
                                vec_rcv_port, nh->msgh_id);
                        }
                        ret = 0x10004009;
                    }
                    unmark_active_rcv_port(vec_rcv_port);
                    flush_deferred_active_rcv_port_ops(vec_rcv_port,
                                                       do_strace);
                    if ((vec_opts & 0x2) && ret != 0x10004005) {
                        forget_cfpreferences_reply_port(vec_rcv_port);
                        forget_special_reply_port(vec_rcv_port);
                    }

                    if (ret == MACH_SEND_TIMED_OUT && msg_buf &&
                        (vec_opts & 0x1)) {
                        mach_msg_header_t *retry_hdr =
                            (mach_msg_header_t *)msg_buf;
                        if (false && mach_msg_send_moves_rights(
                                msg_buf, vec[0].msgv_send_size)) {
                            service_pending_workloop_reqs();
                            service_workloop_machport_events();
                            service_workq_notification_events();
                            if (do_strace) {
                                fprintf(stderr,
                                    "  mach_msg2[vec]: preserving "
                                    "MACH_SEND_TIMED_OUT for move-right "
                                    "message id=%u port 0x%x\n",
                                    retry_hdr->msgh_id,
                                    retry_hdr->msgh_remote_port);
                            }
                        } else {
                            mach_port_type_t retry_ptype = 0;
                            kern_return_t ptype_rc =
                                mach_port_type(mach_task_self(),
                                               retry_hdr->msgh_remote_port,
                                               &retry_ptype);
                            if (ptype_rc == KERN_SUCCESS &&
                                (retry_ptype & MACH_PORT_TYPE_RECEIVE) &&
                                receive_port_has_zero_qlimit(
                                    retry_hdr->msgh_remote_port)) {
                                if (vec_opts & MACH_SEND_NOTIFY) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2[vec]: preserving "
                                            "MACH_SEND_TIMED_OUT for notify "
                                            "port 0x%x\n",
                                            retry_hdr->msgh_remote_port);
                                    }
                                } else {
                                    mach_port_limits_t retry_limits = {
                                        .mpl_qlimit = MACH_PORT_QLIMIT_SMALL,
                                    };
                                    kern_return_t retry_lret =
                                        mach_port_set_attributes(
                                            mach_task_self(),
                                            retry_hdr->msgh_remote_port,
                                            MACH_PORT_LIMITS_INFO,
                                            (mach_port_info_t)&retry_limits,
                                            MACH_PORT_LIMITS_INFO_COUNT);
                                    service_pending_workloop_reqs();
                                    service_workloop_machport_events();
                                    service_workq_notification_events();
                                    ret = host_mach_msg2_trap(
                                        host_data, vec_opts,
                                        (uint64_t)arg3, (uint64_t)arg4,
                                        (uint64_t)arg5, (uint64_t)arg6,
                                        (uint64_t)arg7, vec_tmout);
                                    if (do_strace && ret == KERN_SUCCESS) {
                                        fprintf(stderr,
                                            "  mach_msg2[vec]: local-send "
                                            "retry succeeded for port 0x%x "
                                            "qlimit_ret=%d\n",
                                            retry_hdr->msgh_remote_port,
                                            retry_lret);
                                    }
                                }
                             } else if (ptype_rc == KERN_SUCCESS &&
                                        (retry_ptype & MACH_PORT_TYPE_SEND) &&
                                        !(retry_ptype & MACH_PORT_TYPE_RECEIVE) &&
                                        vec_tmout == 0) {
                                if (vec_opts & MACH_SEND_NOTIFY) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2[vec]: preserving "
                                            "MACH_SEND_TIMED_OUT for notify "
                                            "external port 0x%x\n",
                                            retry_hdr->msgh_remote_port);
                                    }
                                } else {
                            /*
                             * Send-only (external) port with zero timeout.
                             * The remote service may not have started its
                             * receive loop yet, or its queue is temporarily
                             * full due to a circular dependency in the XPC
                             * bootstrap chain.  Retry with escalating
                             * timeouts, servicing workloop events between
                             * attempts so the host service can make progress.
                             *
                             * Service workq notifications while retrying so
                             * SEND_POSSIBLE can wake the dispatch_mach owner.
                                 * Duplicate readiness is gated in syscall.c, so
                                 * this no longer races a storm of resenders.
                                 */
                            /*
                             * Check-in messages get a much longer retry
                             * budget.  The remote daemon (e.g. cfprefsd)
                             * may need several seconds to finish launching
                             * or to drain earlier requests from its service
                             * port.  The earlier 1.85 s budget was often
                              * too short.  The longer budget matches what a
                              * real blocking send (no MACH_SEND_TIMEOUT)
                              * would tolerate.
                             */
                            static const int ext_retry_ms[] = {
                                50, 100, 200, 500, 1000
                            };
                            static const int ext_checkin_retry_ms[] = {
                                50, 100, 200, 500, 1000,
                                2000, 3000, 5000
                            };
                            bool is_checkin = retry_hdr->msgh_id ==
                                DISPATCH_MACH_CHECKIN_MSGID;
                            const int *retry_table = is_checkin
                                ? ext_checkin_retry_ms : ext_retry_ms;
                            int retry_count = is_checkin
                                ? (int)(sizeof(ext_checkin_retry_ms) /
                                        sizeof(ext_checkin_retry_ms[0]))
                                : (int)(sizeof(ext_retry_ms) /
                                        sizeof(ext_retry_ms[0]));
                            for (int ri = 0; ri < retry_count; ri++) {
                                service_pending_workloop_reqs();
                                service_workloop_machport_events();
                                service_workq_notification_events();
                                ret = host_mach_msg2_trap(
                                    host_data, vec_opts,
                                    (uint64_t)arg3, (uint64_t)arg4,
                                    (uint64_t)arg5, (uint64_t)arg6,
                                    (uint64_t)arg7,
                                    (uint64_t)retry_table[ri]);
                                if (do_strace) {
                                    fprintf(stderr,
                                        "  mach_msg2[vec]: ext-send "
                                        "retry[%d] %s for port 0x%x "
                                        "tmout=%dms\n",
                                        ri,
                                        ret == KERN_SUCCESS
                                            ? "succeeded" : "TIMED_OUT",
                                        retry_hdr->msgh_remote_port,
                                        retry_table[ri]);
                                }
                                 if (ret == MACH_SEND_TIMED_OUT) {
                                     queue_workq_send_possible_notification(
                                         retry_hdr->msgh_remote_port);
                                     service_workloop_machport_events();
                                     service_workq_notification_events();
                                 }
                                if (ret != 0x10000004) {
                                    break;
                                }
                            }
                            /*
                             * Service workq notification events once after
                             * the retry loop so any SEND_POSSIBLE that
                             * arrived while we were retrying is delivered
                             * to the appropriate workq thread.
                             */
                             service_workloop_machport_events();
                              service_workq_notification_events();
                               if (ret == MACH_SEND_TIMED_OUT && do_strace) {
                                   fprintf(stderr,
                                           "  mach_msg2[vec]: preserving "
                                           "MACH_SEND_TIMED_OUT for external "
                                           "port 0x%x\n",
                                           retry_hdr->msgh_remote_port);
                               }
                                }
                          }
                      }
                    }

                    if (do_strace && ret != KERN_SUCCESS) {
                        mach_msg_header_t *shdr =
                            (mach_msg_header_t *)msg_buf;
                        fprintf(stderr,
                            "  mach_msg2[vec] FAILED: ret=0x%x\n",
                            (unsigned)ret);
                        if (shdr && (options & 0x1)) {
                            mach_port_type_t ptype = 0;
                            kern_return_t pret =
                                mach_port_type(mach_task_self(),
                                               shdr->msgh_remote_port,
                                               &ptype);
                            mach_port_status_t st = {0};
                            mach_msg_type_number_t st_count =
                                MACH_PORT_RECEIVE_STATUS_COUNT;
                            kern_return_t sret = KERN_INVALID_NAME;
                            mach_port_seqno_t peek_seq = 0;
                            mach_msg_size_t peek_size = 0;
                            mach_msg_id_t peek_id = 0;
                            mach_msg_type_number_t peek_cnt = 0;
                            kern_return_t peek_ret = KERN_INVALID_NAME;
                            if (pret == KERN_SUCCESS &&
                                (ptype & MACH_PORT_TYPE_RECEIVE)) {
                                sret = mach_port_get_attributes(
                                    mach_task_self(), shdr->msgh_remote_port,
                                    MACH_PORT_RECEIVE_STATUS,
                                    (mach_port_info_t)&st, &st_count);
                                peek_ret = mach_port_peek(
                                    mach_task_self(), shdr->msgh_remote_port,
                                    MACH_RCV_TRAILER_NULL, &peek_seq,
                                    &peek_size, &peek_id, NULL, &peek_cnt);
                            }
                            fprintf(stderr,
                                "  send remote=0x%x local=0x%x id=%u "
                                "ptype_ret=%d ptype=0x%x st_ret=%d "
                                "pset=%u qlimit=%u msgcount=%u srights=%u "
                                "sorights=%u peek_ret=%d peek_seq=%u "
                                "peek_size=%u peek_id=%u\n",
                                shdr->msgh_remote_port,
                                shdr->msgh_local_port,
                                shdr->msgh_id, pret, ptype, sret,
                                st.mps_pset, st.mps_qlimit, st.mps_msgcount,
                                st.mps_srights, st.mps_sorights, peek_ret,
                                peek_seq, peek_size, peek_id);
                        }
                    }
                    /* Translate OOL descriptors in the reply */
                    if (ret == KERN_SUCCESS && (options & 0x2)) {
                        if (vec_reply_buf) {
                            kern_return_t fix_ret = fixup_mig_reply_ool(
                                vec_reply_buf, vec_reply_size,
                                (mach_port_name_t)((uint64_t)arg6 >> 32));
                            if (fix_ret != KERN_SUCCESS) {
                                ret = fix_ret;
                            }
                        }
                        if (ret == KERN_SUCCESS && vec_analyticsd_lookup &&
                            vec_reply_buf) {
                            remember_analyticsd_reply_ports(vec_reply_buf,
                                vec_reply_size, do_strace);
                        }
                    }
                    /* Restore OOL descriptor addresses in send buffer */
                    restore_send_ool(&ool_sv);
                    ool_save_destroy(&ool_sv);
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
                mach_msg_size_t direct_reply_size =
                    (mach_msg_size_t)(uint32_t)((uint64_t)arg7);
                mach_msg_size_t direct_send_size =
                    (mach_msg_size_t)(uint32_t)((uint64_t)arg3 >> 32);
                if (handle_mig_message(host_data, host_data,
                                       direct_reply_size, options,
                                       &mig_ret)) {
                    ret = mig_ret;
                } else {
                    /* Translate guest addresses in MIG requests */
                    struct ool_save ool_sv;
                    bool direct_analyticsd_lookup = false;
                    mach_msg_header_t *direct_shdr = NULL;
                    mach_msg_size_t direct_orig_msgh_size = 0;
                    bool direct_patched_msgh_size = false;
                    ool_save_init(&ool_sv);
                    if (host_data && (options & 0x1)) {
                        mach_msg_header_t *shdr =
                            (mach_msg_header_t *)host_data;
                        direct_shdr = shdr;
                        if (direct_send_size == 0) {
                            direct_send_size = shdr->msgh_size;
                        }
                        if (direct_send_size != 0 &&
                            shdr->msgh_size != direct_send_size) {
                            direct_orig_msgh_size = shdr->msgh_size;
                            shdr->msgh_size = direct_send_size;
                            direct_patched_msgh_size = true;
                        }
                        fixup_mig_request_addrs(host_data,
                            direct_send_size);
                        fixup_send_ool(host_data,
                            direct_send_size, &ool_sv);
                        normalize_launchservices_lookup(host_data,
                            direct_send_size);
                        direct_analyticsd_lookup =
                            is_analyticsd_lookup_request(host_data,
                                                         direct_send_size);
                        debug_log_send_descriptors(host_data,
                            direct_send_size);
                        debug_log_send_strings(host_data,
                            direct_send_size);
                        if (do_strace && shdr->msgh_id == 3207 &&
                            direct_send_size >= 40) {
                            uint32_t *words = (uint32_t *)host_data;
                            fprintf(stderr,
                                "  mach_port_get_refs req: name=0x%x "
                                "right=%u\n", words[8], words[9]);
                        }
                        if (is_cfpreferences_request(host_data,
                                                     direct_send_size)) {
                            remember_cfpreferences_reply_port(
                                shdr->msgh_local_port, do_strace);
                        }
                    }

                    uint64_t trap_options = options;
                    uint64_t trap_timeout = (uint64_t)arg8;
                    bool added_timeout = false;
                    bool poll_receive = false;
                    mach_port_name_t direct_rcv_port = MACH_PORT_NULL;

#define OPT_SEND   0x1
#define OPT_RCV    0x2
#define OPT_TMOUT  0x100
                    bool has_send = (trap_options & OPT_SEND) != 0;
                    bool has_receive = (trap_options & OPT_RCV) != 0;
                    bool split_send_receive = has_send && has_receive &&
                        !(trap_options & (MACH64_SEND_KOBJECT_CALL |
                                          MACH64_SEND_MQ_CALL));
                    split_send_receive = false;
                    bool slice_receive =
                        has_receive && (!has_send || split_send_receive);
                    if (trap_options & OPT_RCV) {
                        direct_rcv_port =
                            (uint32_t)((uint64_t)arg6 >> 32);
                        mark_active_rcv_port(direct_rcv_port);
                        service_pending_workloop_reqs();
                    }
                    if (slice_receive) {
                        if (!(trap_options & OPT_TMOUT)) {
                            trap_options |= OPT_TMOUT;
                            trap_timeout =
                                (is_cfpreferences_reply_port(direct_rcv_port) ||
                                 is_special_reply_port(direct_rcv_port))
                                ? CFPREFERENCES_REPLY_TIMEOUT_MS
                                : IPC_RECV_TIMEOUT_MS;
                            added_timeout = true;
                        }
                        poll_receive = added_timeout ||
                            trap_timeout >= WORKLOOP_POLL_SLICE_MS;
                    }
#undef OPT_SEND
#undef OPT_RCV
#undef OPT_TMOUT

                    if (poll_receive) {
                        uint64_t remaining = trap_timeout;
                        uint64_t recv_options = trap_options;

                        if (split_send_receive) {
                            uint64_t send_options = trap_options & ~0x102ULL;

                            service_workloop_machport_events();
                            service_workq_notification_events();
                            ret = host_mach_msg2_trap(host_data, send_options,
                                                      (uint64_t)arg3,
                                                      (uint64_t)arg4,
                                                      (uint64_t)arg5,
                                                      (uint64_t)arg6,
                                                      (uint64_t)arg7,
                                                      (uint64_t)arg8);
                            if (ret != KERN_SUCCESS) {
                                goto direct_after_receive;
                            }
                            recv_options = trap_options & ~0x1ULL;
                        }

                        while (1) {
                            uint64_t slice = remaining > WORKLOOP_POLL_SLICE_MS
                                ? WORKLOOP_POLL_SLICE_MS : remaining;

                            service_workloop_machport_events();
                            service_workq_notification_events();
                            ret = host_mach_msg2_trap(host_data, recv_options,
                                                      (uint64_t)arg3,
                                                      (uint64_t)arg4,
                                                      (uint64_t)arg5,
                                                      (uint64_t)arg6,
                                                      (uint64_t)arg7,
                                                      slice);
                            if (ret != 0x10004003) {
                                break;
                            }
                            if (remaining <= slice) {
                                uint32_t rcv_name =
                                    (uint32_t)((uint64_t)arg6 >> 32);
                                if (has_deferred_active_rcv_port_op(rcv_name)) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2: active receive port "
                                            "0x%x was torn down\n", rcv_name);
                                    }
                                    ret = 0x10004009;
                                    break;
                                }
                                if (added_timeout) {
                                    if (mach_port_name_is_port_set(rcv_name)) {
                                        ret = ipc_timeout_result(rcv_name,
                                                                 do_strace);
                                        break;
                                    }
                                    ret = ipc_timeout_result(rcv_name,
                                                             do_strace);
                                } else {
                                    ret = 0x10004003;
                                }
                                break;
                            }
                            remaining -= slice;
                            service_pending_workloop_reqs();
                        }
                    } else {
                        if (trap_options & 0x2) {
                            service_workloop_machport_events();
                            service_workq_notification_events();
                        }
                        ret = host_mach_msg2_trap(host_data, trap_options,
                                                  (uint64_t)arg3,
                                                  (uint64_t)arg4,
                                                  (uint64_t)arg5,
                                                  (uint64_t)arg6,
                                                  (uint64_t)arg7,
                                                  trap_timeout);
                    }
direct_after_receive:
                    if (ret == KERN_SUCCESS && (trap_options & 0x2) &&
                        reply_port_received_mach_notification(direct_rcv_port,
                                                              host_data)) {
                        mach_msg_header_t *nh = host_data;
                        if (do_strace) {
                            fprintf(stderr,
                                "  mach_msg2: reply port 0x%x received Mach "
                                "notification id=%u -> PORT_DIED\n",
                                direct_rcv_port, nh->msgh_id);
                        }
                        ret = 0x10004009;
                    }
                    unmark_active_rcv_port(direct_rcv_port);
                    flush_deferred_active_rcv_port_ops(direct_rcv_port,
                                                       do_strace);
                    if ((trap_options & 0x2) && ret != 0x10004005) {
                        forget_cfpreferences_reply_port(direct_rcv_port);
                        forget_special_reply_port(direct_rcv_port);
                    }

                    if (ret == MACH_SEND_TIMED_OUT && host_data &&
                        (trap_options & 0x1)) {
                        mach_msg_header_t *retry_hdr =
                            (mach_msg_header_t *)host_data;
                        if (false && mach_msg_send_moves_rights(
                                host_data, retry_hdr->msgh_size)) {
                            service_pending_workloop_reqs();
                            service_workloop_machport_events();
                            service_workq_notification_events();
                            if (do_strace) {
                                fprintf(stderr,
                                    "  mach_msg2: preserving "
                                    "MACH_SEND_TIMED_OUT for move-right "
                                    "message id=%u port 0x%x\n",
                                    retry_hdr->msgh_id,
                                    retry_hdr->msgh_remote_port);
                            }
                        } else {
                            mach_port_type_t retry_ptype = 0;
                            kern_return_t ptype_rc =
                                mach_port_type(mach_task_self(),
                                               retry_hdr->msgh_remote_port,
                                               &retry_ptype);
                            if (ptype_rc == KERN_SUCCESS &&
                                (retry_ptype & MACH_PORT_TYPE_RECEIVE) &&
                                receive_port_has_zero_qlimit(
                                    retry_hdr->msgh_remote_port)) {
                                if (trap_options & MACH_SEND_NOTIFY) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2: preserving "
                                            "MACH_SEND_TIMED_OUT for notify "
                                            "port 0x%x\n",
                                            retry_hdr->msgh_remote_port);
                                    }
                                } else {
                                    mach_port_limits_t retry_limits = {
                                        .mpl_qlimit = MACH_PORT_QLIMIT_SMALL,
                                    };
                                    kern_return_t retry_lret =
                                        mach_port_set_attributes(
                                            mach_task_self(),
                                            retry_hdr->msgh_remote_port,
                                            MACH_PORT_LIMITS_INFO,
                                            (mach_port_info_t)&retry_limits,
                                            MACH_PORT_LIMITS_INFO_COUNT);
                                    service_pending_workloop_reqs();
                                    service_workloop_machport_events();
                                    service_workq_notification_events();
                                    ret = host_mach_msg2_trap(
                                        host_data, trap_options,
                                        (uint64_t)arg3, (uint64_t)arg4,
                                        (uint64_t)arg5, (uint64_t)arg6,
                                        (uint64_t)arg7, trap_timeout);
                                    if (do_strace && ret == KERN_SUCCESS) {
                                        fprintf(stderr,
                                            "  mach_msg2: local-send retry "
                                            "succeeded for port 0x%x "
                                            "qlimit_ret=%d\n",
                                            retry_hdr->msgh_remote_port,
                                            retry_lret);
                                    }
                                }
                             } else if (ptype_rc == KERN_SUCCESS &&
                                        (retry_ptype & MACH_PORT_TYPE_SEND) &&
                                        !(retry_ptype & MACH_PORT_TYPE_RECEIVE) &&
                                        trap_timeout == 0) {
                                if (trap_options & MACH_SEND_NOTIFY) {
                                    if (do_strace) {
                                        fprintf(stderr,
                                            "  mach_msg2: preserving "
                                            "MACH_SEND_TIMED_OUT for notify "
                                            "external port 0x%x\n",
                                            retry_hdr->msgh_remote_port);
                                    }
                                } else {
                            /*
                             * Send-only (external) port with zero timeout.
                             * Same bounded retry as the vector path.
                             */
                            static const int ext_retry_ms[] = {
                                50, 100, 200, 500, 1000
                            };
                            static const int ext_checkin_retry_ms[] = {
                                50, 100, 200, 500, 1000,
                                2000, 3000, 5000
                            };
                            bool is_checkin = retry_hdr->msgh_id ==
                                DISPATCH_MACH_CHECKIN_MSGID;
                            const int *retry_table = is_checkin
                                ? ext_checkin_retry_ms : ext_retry_ms;
                            int retry_count = is_checkin
                                ? (int)(sizeof(ext_checkin_retry_ms) /
                                        sizeof(ext_checkin_retry_ms[0]))
                                : (int)(sizeof(ext_retry_ms) /
                                        sizeof(ext_retry_ms[0]));
                            for (int ri = 0; ri < retry_count; ri++) {
                                service_pending_workloop_reqs();
                                service_workloop_machport_events();
                                service_workq_notification_events();
                                ret = host_mach_msg2_trap(
                                    host_data, trap_options,
                                    (uint64_t)arg3, (uint64_t)arg4,
                                    (uint64_t)arg5, (uint64_t)arg6,
                                    (uint64_t)arg7,
                                    (uint64_t)retry_table[ri]);
                                if (do_strace) {
                                    fprintf(stderr,
                                        "  mach_msg2: ext-send "
                                        "retry[%d] %s for port 0x%x "
                                        "tmout=%dms\n",
                                        ri,
                                        ret == KERN_SUCCESS
                                            ? "succeeded" : "TIMED_OUT",
                                        retry_hdr->msgh_remote_port,
                                        retry_table[ri]);
                                }
                                 if (ret == MACH_SEND_TIMED_OUT) {
                                     queue_workq_send_possible_notification(
                                         retry_hdr->msgh_remote_port);
                                     service_workloop_machport_events();
                                     service_workq_notification_events();
                                 }
                                if (ret != 0x10000004) {
                                    break;
                                }
                            }
                            service_workloop_machport_events();
                             service_workq_notification_events();
                              if (ret == MACH_SEND_TIMED_OUT && do_strace) {
                                  fprintf(stderr,
                                          "  mach_msg2: preserving "
                                          "MACH_SEND_TIMED_OUT for external "
                                          "port 0x%x\n",
                                          retry_hdr->msgh_remote_port);
                              }
                                }
                         }
                     }
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
                        if (rhdr->msgh_id == 3307 &&
                            rhdr->msgh_size >= 40) {
                            uint32_t *words = (uint32_t *)host_data;
                            fprintf(stderr,
                                "  mach_port_get_refs reply: ret=0x%x "
                                "refs=%u\n", words[8], words[9]);
                        }
                        if (rhdr->msgh_id == 40309 &&
                            rhdr->msgh_size >= 112) {
                            uint32_t *words = (uint32_t *)host_data;
                            fprintf(stderr,
                                "  CGSNewWindow reply words:");
                            for (int wi = 0; wi < 28; wi++) {
                                fprintf(stderr, " %08x", words[wi]);
                            }
                            fprintf(stderr, "\n");
                        }
                        if (rhdr->msgh_id == 30363 &&
                            rhdr->msgh_size >= 68) {
                            uint32_t *words = (uint32_t *)host_data;
                            fprintf(stderr,
                                "  CGSWindowConstruct reply words:");
                            for (int wi = 0; wi < 17; wi++) {
                                fprintf(stderr, " %08x", words[wi]);
                            }
                            fprintf(stderr, "\n");
                        }
                    }
                    if (do_strace && ret != KERN_SUCCESS) {
                        fprintf(stderr,
                            "  mach_msg2 FAILED: ret=0x%x\n",
                            (unsigned)ret);
                        if (host_data) {
                            mach_msg_header_t *hdr =
                                (mach_msg_header_t *)host_data;
                            mach_port_type_t ptype = 0;
                            kern_return_t pret =
                                mach_port_type(mach_task_self(),
                                               hdr->msgh_remote_port,
                                               &ptype);
                            mach_port_status_t st = {0};
                            mach_msg_type_number_t st_count =
                                MACH_PORT_RECEIVE_STATUS_COUNT;
                            kern_return_t sret = KERN_INVALID_NAME;
                            if (pret == KERN_SUCCESS &&
                                (ptype & MACH_PORT_TYPE_RECEIVE)) {
                                sret = mach_port_get_attributes(
                                    mach_task_self(), hdr->msgh_remote_port,
                                    MACH_PORT_RECEIVE_STATUS,
                                    (mach_port_info_t)&st, &st_count);
                            }
                            fprintf(stderr,
                                "  reply: bits=0x%x size=%u "
                                "remote=0x%x local=0x%x id=%u "
                                "ptype_ret=%d ptype=0x%x st_ret=%d "
                                "pset=%u qlimit=%u msgcount=%u srights=%u "
                                "sorights=%u\n",
                                hdr->msgh_bits, hdr->msgh_size,
                                hdr->msgh_remote_port,
                                hdr->msgh_local_port,
                                hdr->msgh_id, pret, ptype, sret,
                                st.mps_pset, st.mps_qlimit, st.mps_msgcount,
                                st.mps_srights, st.mps_sorights);
                        }
                    }
                    /* Translate OOL descriptors in the reply */
                    if (ret == KERN_SUCCESS && host_data &&
                        (options & 0x2)) {
                        kern_return_t fix_ret = fixup_mig_reply_ool(
                            host_data, direct_reply_size,
                            (mach_port_name_t)((uint64_t)arg6 >> 32));
                        if (fix_ret != KERN_SUCCESS) {
                            ret = fix_ret;
                        }
                        if (ret == KERN_SUCCESS && direct_analyticsd_lookup) {
                            remember_analyticsd_reply_ports(host_data,
                                direct_reply_size, do_strace);
                        }
                    }
                    /* Restore OOL descriptor addresses in send buffer */
                    if (direct_patched_msgh_size &&
                        !(ret == KERN_SUCCESS && (options & 0x2))) {
                        direct_shdr->msgh_size = direct_orig_msgh_size;
                    }
                    restore_send_ool(&ool_sv);
                    ool_save_destroy(&ool_sv);
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
            ret = semaphore_wait_with_polling((semaphore_t)arg1, 0, true);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_WAIT_SIGNAL) {
            ret = semaphore_wait_signal((semaphore_t)arg1,
                                        (semaphore_t)arg2);
        } else if (trap_num == MACH_TRAP_SEMAPHORE_TIMEDWAIT) {
            ret = semaphore_wait_with_polling((semaphore_t)arg1,
                                              mach_timespec_to_timeout_ms(
                                                  (unsigned int)arg2,
                                                  (clock_res_t)arg3),
                                              false);
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
        if (do_strace) {
            fprintf(stderr, "  mk_timer_create -> port=0x%lx\n",
                    (unsigned long)ret);
        }
        break;

    case MACH_TRAP_MK_TIMER_DESTROY:
        /* mk_timer_destroy(name) */
        ret = host_mk_timer_destroy((mach_port_name_t)arg1);
        if (do_strace) {
            fprintf(stderr, "  mk_timer_destroy(0x%lx) -> %ld\n",
                    (unsigned long)arg1, (long)ret);
        }
        break;

    case MACH_TRAP_MK_TIMER_ARM:
        /* mk_timer_arm(name, expire_time) */
        if (do_strace) {
            fprintf(stderr, "  mk_timer_arm(0x%lx, %llu)\n",
                    (unsigned long)arg1,
                    (unsigned long long)arg2);
        }
        ret = host_mk_timer_arm((mach_port_name_t)arg1, (uint64_t)arg2);
        if (do_strace) {
            fprintf(stderr, "  mk_timer_arm -> %ld\n", (long)ret);
        }
        break;

    case MACH_TRAP_MK_TIMER_ARM_LEEWAY:
        /* mk_timer_arm_leeway(name, flags, expire_time, leeway) */
        if (do_strace) {
            fprintf(stderr, "  mk_timer_arm_leeway(0x%lx, 0x%llx, %llu, %llu)\n",
                    (unsigned long)arg1,
                    (unsigned long long)arg2,
                    (unsigned long long)arg3,
                    (unsigned long long)arg4);
        }
        ret = host_mk_timer_arm_leeway((mach_port_name_t)arg1,
                                       (uint64_t)arg2,
                                       (uint64_t)arg3,
                                       (uint64_t)arg4);
        if (do_strace) {
            fprintf(stderr, "  mk_timer_arm_leeway -> %ld\n", (long)ret);
        }
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
