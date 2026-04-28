/*
 *  macOS system call implementation
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include <sys/random.h>
#include <sys/sysctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <poll.h>
#include <mach/mach.h>
#include <mach/notify.h>
#include <mach/mach_vm.h>
#include <mach/mach_time.h>
#include "qemu.h"
#include "user/guest-host.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"
#include "exec/mmap-lock.h"
#include "user/page-protection.h"

/* csops is a private syscall, declare it here */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
#define CS_OPS_DER_ENTITLEMENTS_BLOB 16

static const uint8_t qemu_macos_user_der_entitlements[] = {
    0xfa, 0xde, 0x71, 0x72, 0x00, 0x00, 0x00, 0xd9,
    0x31, 0x81, 0xce, 0x30, 0x32, 0x0c, 0x2d, 'c',
    'o', 'm', '.', 'a', 'p', 'p', 'l', 'e', '.', 'p',
    'r', 'i', 'v', 'a', 't', 'e', '.', 'x', 'p', 'c',
    '.', 'l', 'a', 'u', 'n', 'c', 'h', 'd', '.', 'p',
    'e', 'r', '-', 'u', 's', 'e', 'r', '-', 'l', 'o',
    'o', 'k', 'u', 'p', 0x01, 0x01, 0x01, 0x30, 0x24,
    0x0c, 0x1f, 'c', 'o', 'm', '.', 'a', 'p', 'p',
    'l', 'e', '.', 's', 'e', 'c', 'u', 'r', 'i', 't',
    'y', '.', 'c', 's', '.', 'a', 'l', 'l', 'o', 'w',
    '-', 'j', 'i', 't', 0x01, 0x01, 0x01, 0x30, 0x3b,
    0x0c, 0x36, 'c', 'o', 'm', '.', 'a', 'p', 'p',
    'l', 'e', '.', 's', 'e', 'c', 'u', 'r', 'i', 't',
    'y', '.', 'c', 's', '.', 'a', 'l', 'l', 'o', 'w',
    '-', 'u', 'n', 's', 'i', 'g', 'n', 'e', 'd', '-',
    'e', 'x', 'e', 'c', 'u', 't', 'a', 'b', 'l', 'e',
    '-', 'm', 'e', 'm', 'o', 'r', 'y', 0x01, 0x01,
    0x01, 0x30, 0x35, 0x0c, 0x30, 'c', 'o', 'm', '.',
    'a', 'p', 'p', 'l', 'e', '.', 's', 'e', 'c', 'u',
    'r', 'i', 't', 'y', '.', 'c', 's', '.', 'd', 'i',
    's', 'a', 'b', 'l', 'e', '-', 'l', 'i', 'b', 'r',
    'a', 'r', 'y', '-', 'v', 'a', 'l', 'i', 'd', 'a',
    't', 'i', 'o', 'n', 0x01, 0x01, 0x01,
};

/*
 * Private kevent_qos_s structure (not in public headers).
 * Used by kevent_qos (syscall 374) and kevent_id (syscall 375).
 */
struct kevent_qos_s {
    uint64_t ident;
    int16_t  filter;
    uint16_t flags;
    int32_t  qos;
    uint64_t udata;
    uint32_t fflags;
    uint32_t xflags;
    int64_t  data;
    uint64_t ext[4];
};

#define KEVENT_FLAG_WORKQ      0x0020
#define KEVENT_FLAG_WORKLOOP   0x0100

/*
 * Raw syscall helpers for kevent_qos and kevent_id.
 * The libc syscall() wrapper on ARM64 may not correctly pass 8 real
 * arguments (9 total including syscall number) through the variadic
 * interface.  Use inline assembly to ensure all 8 args go into X0-X7.
 */
#if defined(__aarch64__)
static long raw_kevent_qos(int kq, void *cl, int nchanges,
                           void *el, int nevents,
                           void *d_out, void *d_avail,
                           unsigned int flags)
{
    register long x0 __asm__("x0") = kq;
    register long x1 __asm__("x1") = (long)cl;
    register long x2 __asm__("x2") = nchanges;
    register long x3 __asm__("x3") = (long)el;
    register long x4 __asm__("x4") = nevents;
    register long x5 __asm__("x5") = (long)d_out;
    register long x6 __asm__("x6") = (long)d_avail;
    register long x7 __asm__("x7") = flags;
    register long x16 __asm__("x16") = SYS_kevent_qos;

    __asm__ volatile(
        "svc #0x80\n"
        "bcc 1f\n"
        "neg x0, x0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4),
          "r"(x5), "r"(x6), "r"(x7), "r"(x16)
        : "memory", "cc"
    );
    return x0;
}

static long raw_kevent_id(uint64_t id, void *cl, int nchanges,
                          void *el, int nevents,
                          void *d_out, void *d_avail,
                          unsigned int flags)
{
    register long x0 __asm__("x0") = (long)id;
    register long x1 __asm__("x1") = (long)cl;
    register long x2 __asm__("x2") = nchanges;
    register long x3 __asm__("x3") = (long)el;
    register long x4 __asm__("x4") = nevents;
    register long x5 __asm__("x5") = (long)d_out;
    register long x6 __asm__("x6") = (long)d_avail;
    register long x7 __asm__("x7") = flags;
    register long x16 __asm__("x16") = SYS_kevent_id;

    __asm__ volatile(
        "svc #0x80\n"
        "bcc 1f\n"
        "neg x0, x0\n"
        "1:\n"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x4),
          "r"(x5), "r"(x6), "r"(x7), "r"(x16)
        : "memory", "cc"
    );
    return x0;
}
#else
/* Fallback for non-ARM64 (not expected to be used) */
#define raw_kevent_qos(kq,cl,nc,el,ne,do_,da,fl) \
    syscall(SYS_kevent_qos,(kq),(cl),(nc),(el),(ne),(do_),(da),(fl))
#define raw_kevent_id(id,cl,nc,el,ne,do_,da,fl) \
    syscall(SYS_kevent_id,(id),(cl),(nc),(el),(ne),(do_),(da),(fl))
#endif

/*
 * Workqueue kqueue fd.  libdispatch calls kevent_qos with fd=-1 and
 * KEVENT_FLAG_WORKQ; the real kernel routes those to the per-process
 * workqueue kqueue.  We emulate this with a normal kqueue fd.
 */
static int workq_kqueue_fd = -1;

static int get_workq_kqueue(void)
{
    if (workq_kqueue_fd < 0) {
        workq_kqueue_fd = kqueue();
    }
    return workq_kqueue_fd;
}

/*
 * EVFILT_MACHPORT uses ext[0] as a pointer to a receive buffer and
 * ext[1] as the buffer size.  Since guest_base != 0 for dynamic
 * binaries, we must translate these guest pointers to host addresses
 * before passing to the kernel, and restore the guest values
 * afterward so libdispatch sees its own addresses.
 */
#define EVFILT_MACHPORT (-8)
#define EVFILT_TIMER_PRIVATE (-7)
#define EVFILT_USER_PRIVATE (-10)
#define EVFILT_WORKLOOP_PRIVATE (-17)
#define NOTE_WL_THREAD_REQUEST 0x00000001
#define NOTE_WL_SYNC_WAIT      0x00000004
#define NOTE_WL_SYNC_WAKE      0x00000008
#define NOTE_WL_UPDATE_QOS     0x00000010
#define NOTE_WL_END_OWNERSHIP  0x00000020
#define NOTE_WL_DISCOVER_OWNER 0x00000080
#define NOTE_WL_IGNORE_ESTALE  0x00000100
#define NOTE_WL_SYNC_IPC       0x80000000
#define EV_EXTIDX_WL_ADDR      1
#define EV_EXTIDX_WL_MASK      2
#define EV_EXTIDX_WL_VALUE     3

static int refresh_workloop_state_update(struct kevent_qos_s *kev)
{
    uint64_t addr;
    uint64_t mask;
    uint64_t expected;
    uint64_t current;

    if (kev->filter != EVFILT_WORKLOOP_PRIVATE) {
        return 0;
    }

    addr = kev->ext[EV_EXTIDX_WL_ADDR];
    mask = kev->ext[EV_EXTIDX_WL_MASK];
    if (!addr) {
        return 0;
    }
    if (!guest_range_valid_untagged(addr, sizeof(current))) {
        return EFAULT;
    }

    expected = kev->ext[EV_EXTIDX_WL_VALUE];
    current = *(uint64_t *)g2h_untagged(addr);
    kev->ext[EV_EXTIDX_WL_VALUE] = current;

    if (mask && ((current & mask) != (expected & mask))) {
        return ESTALE;
    }
    return 0;
}

static void kevent_translate_machport_ptrs(struct kevent_qos_s *kev,
                                           int count, bool to_host)
{
    for (int i = 0; i < count; i++) {
        if (kev[i].filter == EVFILT_MACHPORT && kev[i].ext[0]) {
            if (to_host) {
                kev[i].ext[0] = (uint64_t)(uintptr_t)
                    g2h_untagged((abi_ptr)kev[i].ext[0]);
            } else {
                kev[i].ext[0] = h2g((void *)(uintptr_t)kev[i].ext[0]);
            }
        }
    }
}

/*
 * Workqueue thread support.
 *
 * macOS GCD (libdispatch) needs real threads to process async work.
 * When dispatch_async is called, libdispatch registers kevent_qos
 * events and requests threads via workq_kernreturn.  We create host
 * threads using pthread_create, each running its own QEMU cpu_loop
 * with a cloned CPU state.
 *
 * bsdthread_register saves the wqthread and threadstart callbacks.
 * bsdthread_create spawns a thread calling threadstart.
 * workq_kernreturn(WQOPS_QUEUE_REQTHREADS) spawns workqueue threads
 * calling wqthread.
 */
#include "tcg/startup.h"
#include "qemu/guest-random.h"

static abi_ulong saved_threadstart;  /* from bsdthread_register arg1 */
static abi_ulong saved_wqthread;     /* from bsdthread_register arg2 */
static abi_ulong saved_pthsize;      /* from bsdthread_register arg3 */
static uint32_t saved_tsd_offset;    /* from registration data +24 */
static uint32_t saved_mach_thread_self_offset; /* registration data +32 */
static pthread_mutex_t workq_lock = PTHREAD_MUTEX_INITIALIZER;

#define WQ_STACK_SIZE    (512 * 1024)  /* 512 KB per workqueue thread */

#define WQOPS_THREAD_RETURN            0x004
#define WQOPS_QUEUE_NEWSPISUPP         0x010
#define WQOPS_QUEUE_REQTHREADS         0x020
#define WQOPS_QUEUE_REQTHREADS2        0x030
#define WQOPS_THREAD_KEVENT_RETURN     0x040
#define WQOPS_SET_EVENT_MANAGER_PRIORITY 0x080
#define WQOPS_THREAD_WORKLOOP_RETURN   0x100
#define WQOPS_SHOULD_NARROW            0x200
#define WQOPS_SETUP_DISPATCH           0x400

/* WQ flags passed to wqthread */
#define WQ_FLAG_THREAD_PRIO_QOS        0x00004000
#define WQ_FLAG_THREAD_OVERCOMMIT      0x00010000
#define WQ_FLAG_THREAD_REUSE           0x00020000
#define WQ_FLAG_THREAD_NEWSPI          0x00040000
#define WQ_FLAG_THREAD_KEVENT          0x00080000
#define WQ_FLAG_THREAD_EVENT_MANAGER   0x00100000
#define WQ_FLAG_THREAD_TSD_BASE_SET    0x00200000
#define WQ_FLAG_THREAD_WORKLOOP        0x00400000

/* Flags passed back to libpthread's _pthread_start. */
#define PTHREAD_START_TSD_BASE_SET     0x10000000

/*
 * libdispatch encodes the source type as the first field of direct unotes.
 * For EVFILT_MACHPORT, only source types with a non-NULL dst_merge_msg want
 * a prereceived Mach message buffer; plain DISPATCH_SOURCE_TYPE_MACH_RECV
 * expects a readiness event and crashes if handed a prereceived message.
 */
typedef struct guest_dispatch_source_type {
    uint64_t dst_kind;
    int8_t dst_filter;
    uint8_t dst_action;
    uint8_t dst_bits;
    uint8_t dst_timer_flags;
    uint16_t dst_flags;
    uint16_t dst_data;
    uint32_t dst_fflags;
    uint32_t dst_mask;
    uint32_t dst_size;
    uint32_t dst_pad;
    uint64_t dst_create;
    uint64_t dst_update_mux;
    uint64_t dst_merge_evt;
    uint64_t dst_merge_msg;
} guest_dispatch_source_type;

/*
 * Workloop → port mapping.  When kevent_id registers a MACHPORT on a
 * workloop, we record the (workloop_id, port) pair so the monitor thread
 * can deliver MACHPORT events as workloop-thread events.
 */
#define MAX_WORKLOOP_PORTS 64
#define MAX_STASHED_WORKLOOP_EVENTS 16
typedef struct {
    uint64_t workloop_id;
    mach_port_t port;
    struct kevent_qos_s template_kev;
    bool has_template;
    bool sync_wake_inflight;
    bool readiness_inflight;
    mach_port_seqno_t readiness_seqno;
    mach_port_msgcount_t readiness_msgcount;
    struct kevent_qos_s stashed_events[MAX_STASHED_WORKLOOP_EVENTS];
    int stashed_count;
} workloop_port_entry;

static workloop_port_entry workloop_ports[MAX_WORKLOOP_PORTS];
static int workloop_port_count = 0;
static pthread_mutex_t workloop_port_lock = PTHREAD_MUTEX_INITIALIZER;

#define MAX_NOTIFICATION_PORTS 64
static mach_port_t notification_ports[MAX_NOTIFICATION_PORTS];
static mach_port_t notification_watched_ports[MAX_NOTIFICATION_PORTS];
static mach_msg_id_t notification_msgids[MAX_NOTIFICATION_PORTS];
static bool notification_send_possible_pending[MAX_NOTIFICATION_PORTS];
static int notification_port_count = 0;
static pthread_mutex_t notification_port_lock = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    mach_port_t port;
    struct kevent_qos_s template_kev;
    bool has_template;
    bool synthetic;
} workq_machport_entry;

#define MAX_WORKQ_MACHPORTS 64
static workq_machport_entry workq_machports[MAX_WORKQ_MACHPORTS];
static int workq_machport_count = 0;
static pthread_mutex_t workq_machport_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Global active-receive port guard.  When a guest thread is inside a
 * mach_msg2 receive on a port, that port is registered here so that
 * *all* threads' prereceive paths skip it.  Without this, a
 * service_pending_workloop_reqs() call on a different thread (e.g.
 * __semwait_signal) can steal the reply message the receiver is waiting
 * for, causing an eventual IPC timeout and port-died teardown.
 */
#define MAX_ACTIVE_RCV_PORTS 128
#define MAX_ACTIVE_RCV_GROUPS 16
#define MAX_ACTIVE_RCV_GROUP_PORTS 64

typedef struct ActiveRcvPort {
    mach_port_t port;
    unsigned int refs;
} ActiveRcvPort;

typedef struct ActiveRcvGroup {
    mach_port_t root;
    mach_port_t ports[MAX_ACTIVE_RCV_GROUP_PORTS];
    int count;
} ActiveRcvGroup;

static ActiveRcvPort active_rcv_ports[MAX_ACTIVE_RCV_PORTS];
static int active_rcv_count;
static ActiveRcvGroup active_rcv_groups[MAX_ACTIVE_RCV_GROUPS];
static int active_rcv_group_count;
static pthread_mutex_t active_rcv_lock = PTHREAD_MUTEX_INITIALIZER;

static void active_rcv_collect_ports(mach_port_t port, mach_port_t *ports,
                                     int *count, int max_count)
{
    mach_port_type_t ptype = 0;
    mach_port_name_array_t members = NULL;
    mach_msg_type_number_t member_count = 0;

    if (port == MACH_PORT_NULL || max_count <= 0) {
        return;
    }

    ports[(*count)++] = port;
    if (*count >= max_count ||
        mach_port_type(mach_task_self(), port, &ptype) != KERN_SUCCESS ||
        !(ptype & MACH_PORT_TYPE_PORT_SET)) {
        return;
    }

    if (mach_port_get_set_status(mach_task_self(), port, &members,
                                 &member_count) != KERN_SUCCESS) {
        return;
    }

    for (mach_msg_type_number_t i = 0; i < member_count && *count < max_count;
         i++) {
        bool seen = false;

        for (int j = 0; j < *count; j++) {
            if (ports[j] == members[i]) {
                seen = true;
                break;
            }
        }
        if (!seen) {
            ports[(*count)++] = members[i];
        }
    }

    if (members) {
        vm_deallocate(mach_task_self(), (vm_address_t)members,
                      member_count * sizeof(*members));
    }
}

static void active_rcv_add_locked(mach_port_t port)
{
    for (int i = 0; i < active_rcv_count; i++) {
        if (active_rcv_ports[i].port == port) {
            active_rcv_ports[i].refs++;
            return;
        }
    }
    if (active_rcv_count < MAX_ACTIVE_RCV_PORTS) {
        active_rcv_ports[active_rcv_count].port = port;
        active_rcv_ports[active_rcv_count].refs = 1;
        active_rcv_count++;
    }
}

static void active_rcv_remove_locked(mach_port_t port)
{
    for (int i = 0; i < active_rcv_count; i++) {
        if (active_rcv_ports[i].port != port) {
            continue;
        }
        if (active_rcv_ports[i].refs > 1) {
            active_rcv_ports[i].refs--;
        } else {
            active_rcv_ports[i] = active_rcv_ports[--active_rcv_count];
        }
        return;
    }
}

void mark_active_rcv_port(mach_port_t port)
{
    mach_port_t ports[MAX_ACTIVE_RCV_GROUP_PORTS];
    int count = 0;

    active_rcv_collect_ports(port, ports, &count, ARRAY_SIZE(ports));
    if (count == 0) {
        return;
    }

    pthread_mutex_lock(&active_rcv_lock);
    for (int i = 0; i < count; i++) {
        active_rcv_add_locked(ports[i]);
    }
    if (active_rcv_group_count < MAX_ACTIVE_RCV_GROUPS) {
        ActiveRcvGroup *group = &active_rcv_groups[active_rcv_group_count++];

        group->root = port;
        group->count = count;
        memcpy(group->ports, ports, count * sizeof(ports[0]));
    }
    pthread_mutex_unlock(&active_rcv_lock);
}

void unmark_active_rcv_port(mach_port_t port)
{
    mach_port_t fallback_ports[MAX_ACTIVE_RCV_GROUP_PORTS];
    int fallback_count = 0;
    ActiveRcvGroup group;
    bool found_group = false;

    if (port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&active_rcv_lock);
    for (int i = active_rcv_group_count - 1; i >= 0; i--) {
        if (active_rcv_groups[i].root == port) {
            group = active_rcv_groups[i];
            active_rcv_groups[i] =
                active_rcv_groups[--active_rcv_group_count];
            found_group = true;
            break;
        }
    }
    if (found_group) {
        for (int i = 0; i < group.count; i++) {
            active_rcv_remove_locked(group.ports[i]);
        }
    }
    pthread_mutex_unlock(&active_rcv_lock);

    if (!found_group) {
        active_rcv_collect_ports(port, fallback_ports, &fallback_count,
                                 ARRAY_SIZE(fallback_ports));
        pthread_mutex_lock(&active_rcv_lock);
        for (int i = 0; i < fallback_count; i++) {
            active_rcv_remove_locked(fallback_ports[i]);
        }
        pthread_mutex_unlock(&active_rcv_lock);
    }
}

bool is_port_active_rcv(mach_port_t port)
{
    if (port == MACH_PORT_NULL) {
        return false;
    }
    bool found = false;
    pthread_mutex_lock(&active_rcv_lock);
    for (int i = 0; i < active_rcv_count; i++) {
        if (active_rcv_ports[i].port == port) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&active_rcv_lock);
    return found;
}

/* Forward declaration */
static void deliver_kevents_to_thread(struct kevent_qos_s *events,
                                      int nevents);
static void deliver_workloop_events_to_thread(uint64_t workloop_id,
                                              struct kevent_qos_s *events,
                                              int nevents);
static bool has_exact_parked_workloop_thread(uint64_t workloop_id);
static bool has_parked_workloop_thread(uint64_t workloop_id);
bool is_workq_notification_port(mach_port_t port);
static void register_workq_notification_template(mach_port_t port);
static void service_workq_notification_events_filtered(bool synthetic_only);
static int prereceive_machport_drain(struct kevent_qos_s *template_kev,
                                     struct kevent_qos_s *out_events,
                                     int max_events);
static int prereceive_machport_drain_timeout(
    struct kevent_qos_s *template_kev,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms);
static int prereceive_machport_drain_port_timeout(
    const struct kevent_qos_s *template_kev,
    mach_port_t port,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms);
static int drain_notification_machport_events(
    struct kevent_qos_s *template_kev,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms);
static int stash_workloop_port_events(mach_port_t port,
                                      const struct kevent_qos_s *events,
                                      int nevents);
static void cache_workloop_req_template(uint64_t wl_id,
                                        const struct kevent_qos_s *ev);
static void set_workloop_sync_wake_inflight(uint64_t wl_id, bool inflight);
static void clear_pending_workloop_req(uint64_t wl_id);
static int take_stashed_workloop_events(uint64_t wl_id,
                                        struct kevent_qos_s *out_events,
                                        int max_events);
static int prepare_workloop_events(uint64_t wl_id,
                                   bool prepend_thread_req,
                                   const struct kevent_qos_s *fallback_ev,
                                   struct kevent_qos_s *out_events,
                                   int max_events,
                                   bool allow_active_prereceive);
static int prepare_workloop_events_ex(uint64_t wl_id,
                                      bool prepend_thread_req,
                                      const struct kevent_qos_s *fallback_ev,
                                      struct kevent_qos_s *out_events,
                                      int max_events,
                                      bool allow_active_prereceive,
                                      bool park_only_fallback);
static void kqos_to_k64(const struct kevent_qos_s *src,
                        struct kevent64_s *dst);
static abi_ulong prereceive_one_msg_timeout(mach_port_t port,
                                            mach_msg_size_t hint,
                                            uint32_t receive_flags,
                                            mach_msg_timeout_t timeout_ms,
                                            mach_msg_size_t *received_size_out);

/*
 * Pending workloop thread requests.  Instead of immediately creating
 * workloop threads on kevent_id (which crashes framework-internal
 * workloops), we defer the creation.  The thread is created only when
 * __semwait_signal detects the main thread is blocked waiting for
 * serial queue work.
 */
#define MAX_PENDING_WL 128
#define WORKLOOP_ACTIVE_STALE_NS (100ULL * 1000 * 1000)
typedef struct {
    uint64_t workloop_id;
    struct kevent_qos_s template_event;
    bool has_template;
    struct kevent_qos_s event;
    bool active;
    bool zero_wake;
} pending_workloop_req;

static pending_workloop_req pending_wl_reqs[MAX_PENDING_WL];
static int pending_wl_count = 0;
static pthread_mutex_t pending_wl_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t active_workloop_ids[MAX_PENDING_WL];
static uint64_t active_workloop_since_ns[MAX_PENDING_WL];
static int active_workloop_count = 0;
static pthread_mutex_t active_workloop_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t pending_sync_wake_ids[MAX_PENDING_WL];
static int pending_sync_wake_count = 0;
static pthread_mutex_t pending_sync_wake_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t workloop_monotonic_time_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static bool mark_workloop_active(uint64_t wl_id)
{
    if (!wl_id) {
        return true;
    }

    pthread_mutex_lock(&active_workloop_lock);
    for (int i = 0; i < active_workloop_count; i++) {
        if (active_workloop_ids[i] == wl_id) {
            pthread_mutex_unlock(&active_workloop_lock);
            return false;
        }
    }
    if (active_workloop_count < MAX_PENDING_WL) {
        active_workloop_ids[active_workloop_count] = wl_id;
        active_workloop_since_ns[active_workloop_count] =
            workloop_monotonic_time_ns();
        active_workloop_count++;
    }
    pthread_mutex_unlock(&active_workloop_lock);
    return true;
}

static void clear_workloop_active(uint64_t wl_id)
{
    if (!wl_id) {
        return;
    }

    pthread_mutex_lock(&active_workloop_lock);
    for (int i = 0; i < active_workloop_count; i++) {
        if (active_workloop_ids[i] == wl_id) {
            active_workloop_ids[i] =
                active_workloop_ids[--active_workloop_count];
            active_workloop_since_ns[i] =
                active_workloop_since_ns[active_workloop_count];
            break;
        }
    }
    pthread_mutex_unlock(&active_workloop_lock);
}

static bool clear_stale_workloop_active(uint64_t wl_id, const char *where)
{
    bool cleared = false;
    uint64_t now_ns;

    if (!wl_id) {
        return false;
    }

    now_ns = workloop_monotonic_time_ns();
    pthread_mutex_lock(&active_workloop_lock);
    for (int i = 0; i < active_workloop_count; i++) {
        if (active_workloop_ids[i] == wl_id &&
            now_ns - active_workloop_since_ns[i] >= WORKLOOP_ACTIVE_STALE_NS) {
            uint64_t age_ms =
                (now_ns - active_workloop_since_ns[i]) / 1000000ULL;

            active_workloop_ids[i] =
                active_workloop_ids[--active_workloop_count];
            active_workloop_since_ns[i] =
                active_workloop_since_ns[active_workloop_count];
            cleared = true;
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: clearing stale active "
                        "owner after %llums in %s\n",
                        (unsigned long long)wl_id,
                        (unsigned long long)age_ms, where);
            }
            break;
        }
    }
    pthread_mutex_unlock(&active_workloop_lock);
    return cleared;
}

static bool is_workloop_active(uint64_t wl_id)
{
    bool active = false;

    if (!wl_id) {
        return false;
    }

    pthread_mutex_lock(&active_workloop_lock);
    for (int i = 0; i < active_workloop_count; i++) {
        if (active_workloop_ids[i] == wl_id) {
            active = true;
            break;
        }
    }
    pthread_mutex_unlock(&active_workloop_lock);
    return active;
}

static void record_workloop_sync_wake(uint64_t wl_id, const char *where)
{
    if (!wl_id) {
        return;
    }

    pthread_mutex_lock(&pending_sync_wake_lock);
    for (int i = 0; i < pending_sync_wake_count; i++) {
        if (pending_sync_wake_ids[i] == wl_id) {
            pthread_mutex_unlock(&pending_sync_wake_lock);
            return;
        }
    }
    if (pending_sync_wake_count < MAX_PENDING_WL) {
        pending_sync_wake_ids[pending_sync_wake_count++] = wl_id;
        if (do_strace) {
            fprintf(stderr, "  workloop wl=0x%llx: recorded sync wake from %s\n",
                    (unsigned long long)wl_id, where);
        }
    }
    pthread_mutex_unlock(&pending_sync_wake_lock);
}

static bool consume_workloop_sync_wake(uint64_t wl_id)
{
    if (!wl_id) {
        return false;
    }

    pthread_mutex_lock(&pending_sync_wake_lock);
    for (int i = 0; i < pending_sync_wake_count; i++) {
        if (pending_sync_wake_ids[i] == wl_id) {
            pending_sync_wake_ids[i] =
                pending_sync_wake_ids[--pending_sync_wake_count];
            pthread_mutex_unlock(&pending_sync_wake_lock);
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: consumed pending "
                        "sync wake\n", (unsigned long long)wl_id);
            }
            return true;
        }
    }
    pthread_mutex_unlock(&pending_sync_wake_lock);
    return false;
}

static void defer_active_workloop_events(uint64_t wl_id,
                                         struct kevent_qos_s *events,
                                         int nevents)
{
    for (int i = 0; events && i < nevents; i++) {
        if (events[i].filter == EVFILT_MACHPORT) {
            stash_workloop_port_events((mach_port_t)events[i].ident,
                                       &events[i], 1);
        } else if (events[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                   (events[i].fflags & NOTE_WL_THREAD_REQUEST)) {
            cache_workloop_req_template(wl_id, &events[i]);
        }
    }
}

static pending_workloop_req *find_pending_workloop_req_locked(uint64_t wl_id)
{
    for (int i = 0; i < pending_wl_count; i++) {
        if (pending_wl_reqs[i].workloop_id == wl_id) {
            return &pending_wl_reqs[i];
        }
    }
    return NULL;
}

static pending_workloop_req *ensure_pending_workloop_req_locked(uint64_t wl_id)
{
    pending_workloop_req *entry = find_pending_workloop_req_locked(wl_id);

    if (entry) {
        return entry;
    }
    if (pending_wl_count >= MAX_PENDING_WL) {
        if (do_strace) {
            fprintf(stderr, "  workloop wl=0x%llx: pending request table full "
                    "(%d entries)\n", (unsigned long long)wl_id,
                    pending_wl_count);
        }
        return NULL;
    }

    entry = &pending_wl_reqs[pending_wl_count++];
    memset(entry, 0, sizeof(*entry));
    entry->workloop_id = wl_id;
    return entry;
}

static void refresh_workloop_req_value(struct kevent_qos_s *ev)
{
    if (ev->ext[1]) {
        if (!guest_range_valid_untagged((abi_ulong)ev->ext[1],
                                        sizeof(uint64_t))) {
            if (do_strace) {
                fprintf(stderr, "  workloop THREAD_REQUEST WL_ADDR 0x%llx "
                        "is invalid; keeping WL_VALUE=0x%llx\n",
                        (unsigned long long)ev->ext[1],
                        (unsigned long long)ev->ext[3]);
            }
            return;
        }
        uint64_t *dq_state_p = (uint64_t *)g2h_untagged(ev->ext[1]);
        ev->ext[3] = *dq_state_p;
    }
}

static void refresh_workloop_delivery_values(struct kevent_qos_s *events,
                                             int nevents)
{
    for (int i = 0; events && i < nevents; i++) {
        if (events[i].filter == EVFILT_WORKLOOP_PRIVATE &&
            (events[i].fflags & NOTE_WL_THREAD_REQUEST)) {
            refresh_workloop_req_value(&events[i]);
        }
    }
}

static void cache_workloop_req_template(uint64_t wl_id,
                                        const struct kevent_qos_s *ev)
{
    pending_workloop_req *entry;

    pthread_mutex_lock(&pending_wl_lock);
    entry = ensure_pending_workloop_req_locked(wl_id);
    if (entry) {
        if (entry->zero_wake) {
            /*
             * XNU keeps a single live THREAD_REQUEST knote per workloop and
             * touches it in place as qos/fflags/ext state evolves.  Mirror
             * that by refreshing the standing zero-wake request with the
             * latest kevent_id THREAD_REQUEST payload while keeping the
             * request itself pending until real work arrives.
             */
            entry->event = *ev;
        }
        entry->template_event = *ev;
        entry->has_template = true;
    }
    pthread_mutex_unlock(&pending_wl_lock);
}

static bool lookup_workloop_req_template(uint64_t wl_id,
                                            struct kevent_qos_s *out_ev)
{
    bool found = false;

    pthread_mutex_lock(&pending_wl_lock);
    for (int i = pending_wl_count - 1; i >= 0; i--) {
        if (pending_wl_reqs[i].workloop_id == wl_id &&
            pending_wl_reqs[i].has_template) {
            *out_ev = pending_wl_reqs[i].template_event;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&pending_wl_lock);

    if (found) {
        refresh_workloop_req_value(out_ev);
    }
    return found;
}

static bool take_active_workloop_req(uint64_t wl_id,
                                     struct kevent_qos_s *out_ev)
{
    bool found = false;

    pthread_mutex_lock(&pending_wl_lock);
    for (int i = pending_wl_count - 1; i >= 0; i--) {
        if (pending_wl_reqs[i].workloop_id == wl_id &&
            pending_wl_reqs[i].active &&
            !pending_wl_reqs[i].zero_wake) {
            *out_ev = pending_wl_reqs[i].event;
            pending_wl_reqs[i].active = false;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&pending_wl_lock);

    if (found) {
        refresh_workloop_req_value(out_ev);
    }
    return found;
}

static int prepend_workloop_req_event(uint64_t wl_id,
                                      const struct kevent_qos_s *fallback_ev,
                                      struct kevent_qos_s *events,
                                      int nevents,
                                      int max_events)
{
    struct kevent_qos_s wl_ev;

    if (nevents <= 0 || nevents >= max_events) {
        return nevents;
    }

    if (fallback_ev) {
        wl_ev = *fallback_ev;
        refresh_workloop_req_value(&wl_ev);
    } else if (!take_active_workloop_req(wl_id, &wl_ev)) {
        return nevents;
    }
    (void)wl_ev;

    if (do_strace) {
        fprintf(stderr, "  workloop wl=0x%llx: consumed THREAD_REQUEST "
                "while delivering %d MACHPORT event(s)\n",
                (unsigned long long)wl_id, nevents);
    }
    return nevents;
}

static bool take_zero_wake_workloop_req(uint64_t wl_id,
                                        struct kevent_qos_s *out_ev)
{
    bool found = false;

    pthread_mutex_lock(&pending_wl_lock);
    for (int i = pending_wl_count - 1; i >= 0; i--) {
        if (pending_wl_reqs[i].workloop_id == wl_id &&
            pending_wl_reqs[i].zero_wake) {
            *out_ev = pending_wl_reqs[i].event;
            pending_wl_reqs[i].zero_wake = false;
            /*
             * Also clear active — the thread request is fulfilled now.
             * Without this, service_pending_workloop_reqs() would later
             * process this entry as a non-zero-wake request and deliver
             * a bare THREAD_REQUEST fallback.
             */
            pending_wl_reqs[i].active = false;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&pending_wl_lock);

    if (found) {
        refresh_workloop_req_value(out_ev);
    }
    return found;
}

static bool template_needs_prereceived_msg(const struct kevent_qos_s *template_kev)
{
    abi_ulong du_addr = (abi_ulong)template_kev->udata;
    abi_ulong dst_addr;
    const guest_dispatch_source_type *dst;

    if (!du_addr || (du_addr & 1) ||
        !guest_range_valid_untagged(du_addr, sizeof(uint64_t))) {
        return false;
    }

    dst_addr = *(uint64_t *)g2h_untagged(du_addr);
    if (!dst_addr ||
        !guest_range_valid_untagged(dst_addr, sizeof(*dst))) {
        return false;
    }

    dst = (const guest_dispatch_source_type *)g2h_untagged(dst_addr);
    if (do_strace) {
        fprintf(stderr, "  machport template ident=0x%llx udata=0x%llx "
                "dst=0x%llx dst_filter=%d fflags=0x%x merge_msg=0x%llx\n",
                (unsigned long long)template_kev->ident,
                (unsigned long long)template_kev->udata,
                (unsigned long long)dst_addr, dst->dst_filter,
                template_kev->fflags,
                (unsigned long long)dst->dst_merge_msg);
    }
    return dst->dst_merge_msg != 0;
}

static void debug_log_machport_template(const struct kevent_qos_s *template_kev)
{
    (void)template_needs_prereceived_msg(template_kev);
}

static uint16_t machport_runtime_event_flags(uint16_t flags)
{
    /*
     * Replay the kernel/runtime delivery shape, not the latest guest rearm
     * changelist. Workloop rearms often replace EV_ADD with bookkeeping bits,
     * but delivered MACHPORT events still need the active dispatch shape that
     * libdispatch saw on the first delivery.
     */
    flags &= ~(uint16_t)(EV_DELETE | EV_DISABLE | EV_ONESHOT |
                         EV_UDATA_SPECIFIC | EV_VANISHED);
    flags |= EV_ADD | EV_ENABLE | EV_DISPATCH;
    return flags;
}

static bool machport_has_pending_message(mach_port_t port)
{
    mach_port_status_t status;
    mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;
    kern_return_t kr;

    kr = mach_port_get_attributes(mach_task_self(), port,
                                  MACH_PORT_RECEIVE_STATUS,
                                   (mach_port_info_t)&status, &count);
    return kr == KERN_SUCCESS && status.mps_msgcount > 0;
}

static bool machport_get_receive_status(mach_port_t port,
                                        mach_port_status_t *status)
{
    mach_msg_type_number_t count = MACH_PORT_RECEIVE_STATUS_COUNT;

    return mach_port_get_attributes(mach_task_self(), port,
                                    MACH_PORT_RECEIVE_STATUS,
                                    (mach_port_info_t)status,
                                    &count) == KERN_SUCCESS;
}

static void release_prereceived_workloop_event(struct kevent_qos_s *event)
{
    if (event->filter == EVFILT_MACHPORT && event->ext[0] && event->ext[1]) {
        mmap_lock();
        target_munmap((abi_ulong)event->ext[0], (abi_ulong)event->ext[1]);
        mmap_unlock();
    }
}

static bool is_mach_notification_msg(const mach_msg_header_t *hdr)
{
    return hdr->msgh_id >= MACH_NOTIFY_FIRST &&
        hdr->msgh_id <= MACH_NOTIFY_LAST;
}

static bool workloop_event_is_mach_notification(
    const struct kevent_qos_s *event)
{
    mach_msg_header_t *gh;

    if (event->filter != EVFILT_MACHPORT ||
        event->fflags != 0 ||
        !event->ext[0]) {
        return false;
    }
    if (!guest_range_valid_untagged((abi_ulong)event->ext[0],
                                    sizeof(mach_msg_header_t))) {
        if (do_strace) {
            fprintf(stderr, "  workloop MACHPORT 0x%llx: prereceived "
                    "message pointer 0x%llx is invalid\n",
                    (unsigned long long)event->ident,
                    (unsigned long long)event->ext[0]);
        }
        return false;
    }

    gh = (mach_msg_header_t *)g2h_untagged((abi_ulong)event->ext[0]);
    return is_mach_notification_msg(gh);
}

static bool workq_notification_accepts_msgid(mach_port_t port,
                                             mach_msg_id_t msgid)
{
    bool accepts = false;

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_ports[i] == port &&
            notification_msgids[i] == msgid) {
            accepts = true;
            break;
        }
    }
    pthread_mutex_unlock(&notification_port_lock);
    return accepts;
}

static int filter_workq_notification_events(mach_port_t port,
                                            struct kevent_qos_s *events,
                                            int nevents)
{
    int out = 0;

    for (int i = 0; i < nevents; i++) {
        if (workloop_event_is_mach_notification(&events[i])) {
            mach_msg_header_t *gh =
                (mach_msg_header_t *)g2h_untagged((abi_ulong)events[i].ext[0]);

            if (!workq_notification_accepts_msgid(port, gh->msgh_id)) {
                if (do_strace) {
                    fprintf(stderr, "  workq notification port 0x%x: "
                            "dropping unexpected Mach notification id=%u\n",
                            (unsigned)port, gh->msgh_id);
                }
                release_prereceived_workloop_event(&events[i]);
                continue;
            }
        }
        if (out != i) {
            events[out] = events[i];
        }
        out++;
    }

    return out;
}

static int filter_workloop_notification_events(struct kevent_qos_s *events,
                                               int nevents)
{
    int out = 0;

    for (int i = 0; i < nevents; i++) {
        if (workloop_event_is_mach_notification(&events[i])) {
            if (do_strace) {
                mach_msg_header_t *gh =
                    (mach_msg_header_t *)g2h_untagged((abi_ulong)events[i].ext[0]);
                fprintf(stderr, "  workloop wl MACHPORT 0x%llx: dropping Mach "
                        "notification id=%u\n",
                        (unsigned long long)events[i].ident, gh->msgh_id);
            }
            release_prereceived_workloop_event(&events[i]);
            continue;
        }
        if (out != i) {
            events[out] = events[i];
        }
        out++;
    }

    return out;
}

static void store_pending_workloop_req(uint64_t wl_id,
                                       const struct kevent_qos_s *ev,
                                       bool zero_wake)
{
    pending_workloop_req *entry;
    bool was_zero_wake = false;

    pthread_mutex_lock(&pending_wl_lock);
    entry = ensure_pending_workloop_req_locked(wl_id);
    if (entry) {
        was_zero_wake = entry->zero_wake;
        entry->event = *ev;
        if (!zero_wake) {
            entry->template_event = *ev;
            entry->has_template = true;
            entry->active = true;
            entry->zero_wake = false;
        } else {
            entry->zero_wake = true;
            entry->active = false;
        }
        if (do_strace) {
            fprintf(stderr, "  queued workloop request wl=0x%llx "
                    "filter=%d fflags=0x%x zero=%d\n",
                    (unsigned long long)wl_id, ev->filter, ev->fflags,
                    zero_wake);
            if (was_zero_wake && !zero_wake) {
                fprintf(stderr, "  workloop wl=0x%llx: replacing returned "
                        "zero-wake THREAD_REQUEST with active request\n",
                        (unsigned long long)wl_id);
            }
        }
    }
    pthread_mutex_unlock(&pending_wl_lock);
}

static void add_pending_workloop_req(uint64_t wl_id,
                                     const struct kevent_qos_s *ev)
{
    cache_workloop_req_template(wl_id, ev);

    pthread_mutex_lock(&pending_wl_lock);
    /* If already pending → this is a repeat request → service immediately */
    for (int i = 0; i < pending_wl_count; i++) {
        if (pending_wl_reqs[i].workloop_id == wl_id
            && pending_wl_reqs[i].active) {
            pending_wl_reqs[i].active = false;
            pthread_mutex_unlock(&pending_wl_lock);

            /*
             * Use the NEW event (from this call), not the saved one.
             * The dq_state may have changed since the first request.
             */
            struct kevent_qos_s fresh_ev = *ev;
            refresh_workloop_req_value(&fresh_ev);

            if (do_strace) {
                fprintf(stderr, "    WORKLOOP THREAD_REQ wl=0x%llx"
                        " -> repeat, creating thread now\n",
                        (unsigned long long)wl_id);
            }
            struct kevent_qos_s events[16];
            int nevents = prepare_workloop_events(wl_id, true, &fresh_ev,
                                                  events,
                                                  ARRAY_SIZE(events), false);
            if (nevents > 0) {
                deliver_workloop_events_to_thread(wl_id, events, nevents);
            } else {
                store_pending_workloop_req(wl_id, &fresh_ev, true);
            }
            return;
        }
    }
    /* First request — defer */
    pthread_mutex_unlock(&pending_wl_lock);
    store_pending_workloop_req(wl_id, ev, false);
}

static bool workloop_has_machport_template(uint64_t wl_id)
{
    bool found = false;

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].workloop_id == wl_id &&
            workloop_ports[i].has_template) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);
    return found;
}

static void clear_pending_workloop_req(uint64_t wl_id)
{
    pthread_mutex_lock(&pending_wl_lock);
    for (int i = 0; i < pending_wl_count; i++) {
        if (pending_wl_reqs[i].workloop_id == wl_id) {
            pending_wl_reqs[i].active = false;
        }
    }
    pthread_mutex_unlock(&pending_wl_lock);
}

void service_pending_workloop_reqs(void)
{
    pthread_mutex_lock(&pending_wl_lock);
    for (int i = 0; i < pending_wl_count; i++) {
        pending_workloop_req req;
        struct kevent_qos_s ev;
        uint64_t wl_id;

        if (!pending_wl_reqs[i].active) {
            continue;
        }

        /*
         * In XNU, a workloop's NOTE_WL_THREAD_REQUEST persists on the
         * kernel workloop until a knote fires and the thread is actually
         * dispatched with real work.  Zero-wake requests represent this
         * persistent thread request — skip them here and let
         * take_zero_wake_workloop_req() pair them with MACHPORT events
         * when those events are delivered via the monitor, polling, or
         * kevent_id paths.  Processing them here would consume the
         * request with a 100ms prereceive that almost always finds
         * nothing, losing the persistent thread request.
         */
        if (pending_wl_reqs[i].zero_wake) {
            continue;
        }

        req = pending_wl_reqs[i];
        pending_wl_reqs[i].active = false;
        pthread_mutex_unlock(&pending_wl_lock);

        ev = req.event;
        wl_id = req.workloop_id;
        refresh_workloop_req_value(&ev);

        if (do_strace) {
            fprintf(stderr, "  semwait: servicing pending workloop "
                    "wl=0x%llx\n", (unsigned long long)wl_id);
        }
        struct kevent_qos_s events[16];
        int nevents = prepare_workloop_events(wl_id, true, &ev, events,
                                               ARRAY_SIZE(events), false);
        if (nevents == 0) {
            if (!(ev.fflags & NOTE_WL_SYNC_WAIT) &&
                !workloop_has_machport_template(wl_id)) {
                events[0] = ev;
                deliver_workloop_events_to_thread(wl_id, events, 1);
                pthread_mutex_lock(&pending_wl_lock);
                continue;
            }
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: preserving pending "
                        "THREAD_REQUEST until real work arrives\n",
                        (unsigned long long)wl_id);
            }
            store_pending_workloop_req(wl_id, &ev, true);
            pthread_mutex_lock(&pending_wl_lock);
            continue;
        }
        deliver_workloop_events_to_thread(wl_id, events, nevents);

        pthread_mutex_lock(&pending_wl_lock);
    }
    pthread_mutex_unlock(&pending_wl_lock);
}

static void add_workloop_port(uint64_t wl_id,
                              const struct kevent_qos_s *kev)
{
    mach_port_t port = (mach_port_t)kev->ident;
    bool drop_synthetic = false;

    pthread_mutex_lock(&workloop_port_lock);
    /* Update existing entry for this port */
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port) {
            workloop_ports[i].workloop_id = wl_id;
            workloop_ports[i].template_kev = *kev;
            workloop_ports[i].has_template = true;
            if (kev->flags & (EV_ADD | EV_ENABLE)) {
                workloop_ports[i].readiness_inflight = false;
            }
            pthread_mutex_unlock(&workloop_port_lock);
            drop_synthetic = true;
            goto done;
        }
    }
    if (workloop_port_count < MAX_WORKLOOP_PORTS) {
        workloop_ports[workloop_port_count].workloop_id = wl_id;
        workloop_ports[workloop_port_count].port = port;
        workloop_ports[workloop_port_count].template_kev = *kev;
        workloop_ports[workloop_port_count].has_template = true;
        workloop_ports[workloop_port_count].readiness_inflight = false;
        workloop_ports[workloop_port_count].readiness_seqno = 0;
        workloop_ports[workloop_port_count].readiness_msgcount = 0;
        workloop_port_count++;
        drop_synthetic = true;
    }
    pthread_mutex_unlock(&workloop_port_lock);

done:
    if (!drop_synthetic) {
        return;
    }

    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (workq_machports[i].port == port &&
            workq_machports[i].synthetic) {
            workq_machports[i] = workq_machports[--workq_machport_count];
            break;
        }
    }
    pthread_mutex_unlock(&workq_machport_lock);
}

static void remove_workq_machport_template(mach_port_t port)
{
    bool removed = false;

    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (workq_machports[i].port == port) {
            workq_machports[i] = workq_machports[--workq_machport_count];
            removed = true;
            break;
        }
    }
    pthread_mutex_unlock(&workq_machport_lock);

    if (do_strace && removed) {
        fprintf(stderr, "  removed workq MACHPORT template ident=0x%x\n",
                (unsigned)port);
    }
}

static void unregister_workq_notification_port(mach_port_t port)
{
    bool removed = false;

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_ports[i] == port) {
            int last = --notification_port_count;
            notification_ports[i] = notification_ports[last];
            notification_watched_ports[i] = notification_watched_ports[last];
            notification_msgids[i] = notification_msgids[last];
            notification_send_possible_pending[i] =
                notification_send_possible_pending[last];
            removed = true;
            break;
        }
    }
    pthread_mutex_unlock(&notification_port_lock);

    if (do_strace && removed) {
        fprintf(stderr, "  unregistered notification MACHPORT ident=0x%x\n",
                (unsigned)port);
    }
}

static void unregister_workq_kqueue_machport(mach_port_t port)
{
    struct kevent64_s k64;
    int kq = get_workq_kqueue();

    memset(&k64, 0, sizeof(k64));
    k64.ident = port;
    k64.filter = EVFILT_MACHPORT;
    k64.flags = EV_DELETE;

    int rc = kevent64(kq, &k64, 1, NULL, 0, 0, NULL);
    if (do_strace && rc < 0 && errno != ENOENT) {
        fprintf(stderr, "  workq_kqueue_unregister: MACHPORT ident=0x%x "
                "failed errno=%d\n", (unsigned)port, errno);
    }
}

static void remove_workloop_port(mach_port_t port)
{
    struct kevent_qos_s stashed[MAX_STASHED_WORKLOOP_EVENTS];
    int stashed_count = 0;
    bool removed = false;
    uint64_t wl_id = 0;

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port) {
            wl_id = workloop_ports[i].workloop_id;
            stashed_count = workloop_ports[i].stashed_count;
            if (stashed_count > 0) {
                memcpy(stashed, workloop_ports[i].stashed_events,
                       stashed_count * sizeof(stashed[0]));
            }
            workloop_ports[i] = workloop_ports[--workloop_port_count];
            removed = true;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);

    for (int i = 0; i < stashed_count; i++) {
        release_prereceived_workloop_event(&stashed[i]);
    }

    if (do_strace && removed) {
        fprintf(stderr, "  workloop wl=0x%llx: removed MACHPORT ident=0x%x\n",
                (unsigned long long)wl_id, (unsigned)port);
    }

    if (removed) {
        unregister_workq_kqueue_machport(port);
    }
    remove_workq_machport_template(port);
    unregister_workq_notification_port(port);
}

static int stash_workloop_port_events(mach_port_t port,
                                      const struct kevent_qos_s *events,
                                      int nevents)
{
    int stashed = 0;

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port != port) {
            continue;
        }

        stashed = MIN(nevents, MAX_STASHED_WORKLOOP_EVENTS -
                               workloop_ports[i].stashed_count);
        if (stashed > 0) {
            memcpy(&workloop_ports[i].stashed_events[workloop_ports[i].stashed_count],
                   events, stashed * sizeof(events[0]));
            workloop_ports[i].stashed_count += stashed;
        }
        break;
    }
    pthread_mutex_unlock(&workloop_port_lock);

    for (int i = stashed; i < nevents; i++) {
        release_prereceived_workloop_event((struct kevent_qos_s *)&events[i]);
    }

    return stashed;
}

static void set_workloop_sync_wake_inflight(uint64_t wl_id, bool inflight)
{
    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].workloop_id == wl_id) {
            workloop_ports[i].sync_wake_inflight = inflight;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);
}

static void clear_workloop_readiness_inflight(uint64_t wl_id)
{
    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (wl_id == 0 || workloop_ports[i].workloop_id == wl_id) {
            workloop_ports[i].readiness_inflight = false;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);
}

static int take_stashed_workloop_events(uint64_t wl_id,
                                        struct kevent_qos_s *out_events,
                                        int max_events)
{
    int total = 0;
    int delivery_limit = MIN(max_events, 1);

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count && total < delivery_limit; i++) {
        int take;

        if (workloop_ports[i].workloop_id != wl_id ||
            workloop_ports[i].stashed_count == 0) {
            continue;
        }

        take = MIN(workloop_ports[i].stashed_count, delivery_limit - total);
        memcpy(&out_events[total], workloop_ports[i].stashed_events,
               take * sizeof(out_events[0]));
        total += take;

        if (take < workloop_ports[i].stashed_count) {
            memmove(workloop_ports[i].stashed_events,
                    &workloop_ports[i].stashed_events[take],
                    (workloop_ports[i].stashed_count - take) *
                    sizeof(workloop_ports[i].stashed_events[0]));
        }
        workloop_ports[i].stashed_count -= take;
    }
    pthread_mutex_unlock(&workloop_port_lock);

    if (total > 0) {
        if (do_strace) {
            for (int i = 0; i < total; i++) {
                if (workloop_event_is_mach_notification(&out_events[i])) {
                    mach_msg_header_t *gh =
                        (mach_msg_header_t *)g2h_untagged(
                            (abi_ulong)out_events[i].ext[0]);
                    fprintf(stderr, "  workloop wl=0x%llx: unstashed Mach "
                            "notification id=%u from port 0x%llx\n",
                            (unsigned long long)wl_id, gh->msgh_id,
                            (unsigned long long)out_events[i].ident);
                }
            }
        }
        set_workloop_sync_wake_inflight(wl_id, false);
    }

    return total;
}

static uint64_t find_workloop_for_port(mach_port_t port)
{
    uint64_t wl_id = 0;
    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port) {
            wl_id = workloop_ports[i].workloop_id;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);
    return wl_id;
}

static bool workloop_template_is_readiness_only(
    const struct kevent_qos_s *template_kev)
{
    return template_kev->filter == EVFILT_MACHPORT &&
           (template_kev->flags & EV_DISPATCH) &&
           !is_workq_notification_port((mach_port_t)template_kev->ident) &&
           !template_needs_prereceived_msg(template_kev);
}

static bool suppress_workloop_readiness_delivery(
    const struct kevent_qos_s *template_kev)
{
    mach_port_t port = (mach_port_t)template_kev->ident;
    mach_port_status_t status = {0};
    bool suppress = false;

    if (!workloop_template_is_readiness_only(template_kev) ||
        !machport_get_receive_status(port, &status)) {
        return false;
    }

    if (status.mps_msgcount == 0) {
        pthread_mutex_lock(&workloop_port_lock);
        for (int i = 0; i < workloop_port_count; i++) {
            if (workloop_ports[i].port == port) {
                workloop_ports[i].readiness_inflight = false;
                break;
            }
        }
        pthread_mutex_unlock(&workloop_port_lock);
        return false;
    }

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port &&
            workloop_ports[i].readiness_inflight &&
            workloop_ports[i].readiness_seqno == status.mps_seqno &&
            workloop_ports[i].readiness_msgcount == status.mps_msgcount) {
            suppress = true;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);

    if (do_strace && suppress) {
        fprintf(stderr, "  workloop MACHPORT 0x%x: suppressing duplicate "
                "readiness event seq=%u msgcount=%u\n",
                (unsigned)port, status.mps_seqno, status.mps_msgcount);
    }
    return suppress;
}

static bool mark_workloop_readiness_delivered(
    const struct kevent_qos_s *template_kev)
{
    mach_port_t port = (mach_port_t)template_kev->ident;
    mach_port_status_t status = {0};
    bool marked = false;

    if (!workloop_template_is_readiness_only(template_kev) ||
        !machport_get_receive_status(port, &status) ||
        status.mps_msgcount == 0) {
        return false;
    }

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port) {
            workloop_ports[i].readiness_inflight = true;
            workloop_ports[i].readiness_seqno = status.mps_seqno;
            workloop_ports[i].readiness_msgcount = status.mps_msgcount;
            marked = true;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);

    if (do_strace && marked) {
        fprintf(stderr, "  workloop MACHPORT 0x%x: marked readiness event "
                "in flight seq=%u msgcount=%u\n",
                (unsigned)port, status.mps_seqno, status.mps_msgcount);
    }
    return marked;
}

typedef enum WorkloopMachportState {
    WORKLOOP_MACHPORT_LIVE,
    WORKLOOP_MACHPORT_NO_RIGHTS,
    WORKLOOP_MACHPORT_DEAD_NAME,
} WorkloopMachportState;

static WorkloopMachportState workloop_machport_state(mach_port_t port)
{
    mach_port_type_t ptype = 0;
    kern_return_t kr;

    kr = mach_port_type(mach_task_self(), port, &ptype);
    if (kr != KERN_SUCCESS) {
        if (do_strace) {
            fprintf(stderr, "  workloop: mach_port_type(0x%x) failed: %d\n",
                    (unsigned)port, kr);
        }
        return WORKLOOP_MACHPORT_LIVE;
    }

    if (ptype & MACH_PORT_TYPE_DEAD_NAME) {
        return WORKLOOP_MACHPORT_DEAD_NAME;
    }
    if (ptype == 0) {
        return WORKLOOP_MACHPORT_NO_RIGHTS;
    }
    return WORKLOOP_MACHPORT_LIVE;
}

static void suppress_dead_workloop_machport_fallback(uint64_t wl_id,
                                                     mach_port_t port,
                                                     const char *where,
                                                     WorkloopMachportState state)
{
    set_workloop_sync_wake_inflight(wl_id, false);
    if (state == WORKLOOP_MACHPORT_DEAD_NAME) {
        clear_pending_workloop_req(wl_id);
    }
    if (do_strace) {
        fprintf(stderr, "  workloop wl=0x%llx: machport template 0x%x "
                "is %s — suppressing %s fallback\n",
                (unsigned long long)wl_id, (unsigned)port,
                state == WORKLOOP_MACHPORT_DEAD_NAME ? "dead" : "released",
                where);
    }
}

static int snapshot_workloop_machport_templates(uint64_t wl_id,
                                                workloop_port_entry *snapshot,
                                                int max_snapshot)
{
    int count = 0;

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = workloop_port_count - 1; i >= 0 && count < max_snapshot; i--) {
        if (workloop_ports[i].workloop_id == wl_id &&
            workloop_ports[i].has_template) {
            snapshot[count++] = workloop_ports[i];
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);
    return count;
}

static int stash_active_workloop_notification_events(
    uint64_t wl_id, const workloop_port_entry *entry, const char *where)
{
    struct kevent_qos_s drained[16];
    struct kevent_qos_s template_kev = entry->template_kev;
    int got;
    int stashed;

    if (!is_workq_notification_port(entry->port) ||
        is_port_active_rcv(entry->port)) {
        return 0;
    }

    got = drain_notification_machport_events(&template_kev, drained,
                                             ARRAY_SIZE(drained), 0);
    if (got <= 0) {
        return 0;
    }

    stashed = stash_workloop_port_events(entry->port, drained, got);
    if (do_strace) {
        fprintf(stderr, "  workloop wl=0x%llx: stashed %d active-owner "
                "notification event(s) on 0x%x from %s\n",
                (unsigned long long)wl_id, stashed, (unsigned)entry->port,
                where);
    }
    return stashed;
}

static int stash_active_workloop_notifications(uint64_t wl_id,
                                               const char *where)
{
    workloop_port_entry templates[MAX_WORKLOOP_PORTS];
    int template_count;
    int total = 0;

    template_count = snapshot_workloop_machport_templates(
        wl_id, templates, ARRAY_SIZE(templates));
    for (int i = 0; i < template_count; i++) {
        total += stash_active_workloop_notification_events(wl_id,
                                                           &templates[i],
                                                           where);
    }
    return total;
}

static int prepare_workloop_events_ex(uint64_t wl_id,
                                      bool prepend_thread_req,
                                      const struct kevent_qos_s *fallback_ev,
                                      struct kevent_qos_s *out_events,
                                      int max_events,
                                      bool allow_active_prereceive,
                                      bool park_only_fallback)
{
    int got;
    int total = 0;
    bool saw_dead_template = false;
    bool saw_live_empty_template = false;
    workloop_port_entry templates[MAX_WORKLOOP_PORTS];
    int template_count;

    if (!allow_active_prereceive && is_workloop_active(wl_id) &&
        !clear_stale_workloop_active(wl_id, "prepare")) {
        stash_active_workloop_notifications(wl_id, "prepare");
        if (do_strace) {
            fprintf(stderr, "  workloop wl=0x%llx: active owner present, "
                    "deferring prereceive\n", (unsigned long long)wl_id);
        }
        return 0;
    }

    got = take_stashed_workloop_events(wl_id, out_events, max_events);
    if (got > 0) {
        struct kevent_qos_s zero_wake_ev;

        if (take_zero_wake_workloop_req(wl_id, &zero_wake_ev)) {
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: consumed returned "
                        "THREAD_REQUEST for %d stashed MACHPORT event(s)\n",
                (unsigned long long)wl_id, got);
            }
        }
        if (got > 0 && prepend_thread_req) {
            got = prepend_workloop_req_event(wl_id, fallback_ev, out_events, got,
                                             max_events);
        }
        if (do_strace) {
            fprintf(stderr, "  workloop wl=0x%llx: using %d stashed "
                    "MACHPORT event(s)\n",
                    (unsigned long long)wl_id, got);
        }
        return got;
    }

    template_count = snapshot_workloop_machport_templates(
        wl_id, templates, ARRAY_SIZE(templates));
    for (int i = 0; i < template_count && total < max_events; i++) {
        struct kevent_qos_s machport_kev = templates[i].template_kev;
        bool notification_port =
            is_workq_notification_port((mach_port_t)machport_kev.ident);

        if (is_port_active_rcv((mach_port_t)machport_kev.ident)) {
            /*
             * Another thread is doing mach_msg2 receive on this port;
             * prereceiving here would steal its reply message.  Keep
             * scanning: the same workloop can have other ready ports.
             */
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: MACHPORT 0x%x "
                        "has active receiver; skipping prereceive\n",
                        (unsigned long long)wl_id,
                        (unsigned)machport_kev.ident);
            }
            continue;
        }
        if (suppress_workloop_readiness_delivery(&machport_kev)) {
            continue;
        }
        if (notification_port) {
            got = drain_notification_machport_events(
                &machport_kev, &out_events[total], max_events - total, 100);
        } else {
            got = prereceive_machport_drain(
                &machport_kev, &out_events[total], max_events - total);
        }
        if (got > 0) {
            if (!notification_port) {
                got = filter_workloop_notification_events(&out_events[total],
                                                          got);
            }
            if (got > 0) {
                set_workloop_sync_wake_inflight(wl_id, false);
                mark_workloop_readiness_delivered(&machport_kev);
                total += got;
            }
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: using %d "
                        "prereceived MACHPORT event(s) from 0x%x\n",
                        (unsigned long long)wl_id, got,
                        (unsigned)machport_kev.ident);
            }
            continue;
        }

        /*
         * prereceive_machport_drain returned 0: the port queue was empty.
         * If the port is also dead (no rights remain), suppress the fallback
         * THREAD_REQUEST delivery — returning it would cause an infinite
         * sync-wake spin where cleanup handlers park, get woken with just a
         * THREAD_REQUEST, do nothing useful, and re-park indefinitely.
         */
        WorkloopMachportState state =
            workloop_machport_state((mach_port_t)machport_kev.ident);
        if (state != WORKLOOP_MACHPORT_LIVE) {
            saw_dead_template = true;
            suppress_dead_workloop_machport_fallback(
                wl_id, (mach_port_t)machport_kev.ident, "THREAD_REQUEST",
                state);
        } else {
            saw_live_empty_template = true;
        }
    }

    if (total > 0) {
        struct kevent_qos_s zero_wake_ev;

        if (take_zero_wake_workloop_req(wl_id, &zero_wake_ev)) {
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: consumed returned "
                        "THREAD_REQUEST for %d prereceived MACHPORT event(s)\n",
                        (unsigned long long)wl_id, total);
            }
        }
        if (prepend_thread_req) {
            total = prepend_workloop_req_event(wl_id, fallback_ev, out_events,
                                               total,
                                               max_events);
        }
        return total;
    }

    if (saw_dead_template && !saw_live_empty_template) {
        return 0;
    }

    if (fallback_ev && do_strace) {
        fprintf(stderr, "  workloop wl=0x%llx: preserving THREAD_REQUEST "
                "until real MACHPORT work arrives\n",
                (unsigned long long)wl_id);
    }
    return 0;
}

static int prepare_workloop_events(uint64_t wl_id,
                                   bool prepend_thread_req,
                                   const struct kevent_qos_s *fallback_ev,
                                   struct kevent_qos_s *out_events,
                                   int max_events,
                                   bool allow_active_prereceive)
{
    return prepare_workloop_events_ex(wl_id, prepend_thread_req, fallback_ev,
                                      out_events, max_events,
                                      allow_active_prereceive, true);
}

static bool workq_notification_port_has_real_template(mach_port_t port)
{
    bool found = false;

    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (workq_machports[i].port == port &&
            workq_machports[i].has_template &&
            !workq_machports[i].synthetic) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&workq_machport_lock);

    if (found) {
        return true;
    }

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port &&
            workloop_ports[i].has_template) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&workloop_port_lock);

    return found;
}

static void synthesize_workq_notification_template(mach_port_t port)
{
    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (workq_machports[i].port == port) {
            if (!workq_machports[i].has_template) {
                memset(&workq_machports[i].template_kev, 0,
                       sizeof(workq_machports[i].template_kev));
                workq_machports[i].template_kev.ident = port;
                workq_machports[i].template_kev.filter = EVFILT_MACHPORT;
                workq_machports[i].template_kev.flags = EV_ADD | EV_ENABLE |
                    EV_DISPATCH | EV_UDATA_SPECIFIC | EV_VANISHED;
                workq_machports[i].has_template = true;
                workq_machports[i].synthetic = true;
            }
            pthread_mutex_unlock(&workq_machport_lock);
            return;
        }
    }

    if (workq_machport_count < MAX_WORKQ_MACHPORTS) {
        workq_machports[workq_machport_count].port = port;
        memset(&workq_machports[workq_machport_count].template_kev, 0,
               sizeof(workq_machports[workq_machport_count].template_kev));
        workq_machports[workq_machport_count].template_kev.ident = port;
        workq_machports[workq_machport_count].template_kev.filter =
            EVFILT_MACHPORT;
        workq_machports[workq_machport_count].template_kev.flags =
            EV_ADD | EV_ENABLE | EV_DISPATCH |
            EV_UDATA_SPECIFIC | EV_VANISHED;
        workq_machports[workq_machport_count].has_template = true;
        workq_machports[workq_machport_count].synthetic = true;
        workq_machport_count++;
    }
    pthread_mutex_unlock(&workq_machport_lock);
}

void record_workq_notification_port(mach_port_t port, mach_port_t watched_port,
                                    mach_msg_id_t msgid)
{
    if (port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_ports[i] == port) {
            if (watched_port != MACH_PORT_NULL) {
                notification_watched_ports[i] = watched_port;
            }
            notification_msgids[i] = msgid;
            pthread_mutex_unlock(&notification_port_lock);
            return;
        }
    }
    if (notification_port_count < MAX_NOTIFICATION_PORTS) {
        notification_ports[notification_port_count] = port;
        notification_watched_ports[notification_port_count] = watched_port;
        notification_msgids[notification_port_count] = msgid;
        notification_send_possible_pending[notification_port_count] = false;
        notification_port_count++;
    }
    pthread_mutex_unlock(&notification_port_lock);
    if (do_strace) {
        fprintf(stderr,
                "  record_workq_notification_port: port=0x%x watches=0x%x "
                "msgid=%d (manual poll)\n",
                port, watched_port, msgid);
    }

    if (workq_notification_port_has_real_template(port)) {
        register_workq_notification_template(port);
        return;
    }

    synthesize_workq_notification_template(port);
    if (do_strace) {
        fprintf(stderr, "  synthesized notify MACHPORT template ident=0x%x "
                "for manual polling\n", (unsigned)port);
    }
}

void queue_workq_send_possible_notification(mach_port_t watched_port)
{
    int queued = 0;

    if (watched_port == MACH_PORT_NULL) {
        return;
    }

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_watched_ports[i] == watched_port &&
            notification_msgids[i] == MACH_NOTIFY_SEND_POSSIBLE) {
            notification_send_possible_pending[i] = true;
            queued++;
        }
    }
    pthread_mutex_unlock(&notification_port_lock);

    if (do_strace && queued > 0) {
        fprintf(stderr, "  queued SEND_POSSIBLE notification for port 0x%x "
                "(%d target%s)\n", watched_port, queued,
                queued == 1 ? "" : "s");
    }
}

bool is_workq_notification_port(mach_port_t port)
{
    bool found = false;

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_ports[i] == port) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&notification_port_lock);
    return found;
}

static int take_synthetic_send_possible_events(
    const struct kevent_qos_s *template_kev,
    struct kevent_qos_s *out_events,
    int max_events)
{
    mach_port_t notify_port = (mach_port_t)template_kev->ident;
    mach_port_t watched_port = MACH_PORT_NULL;
    bool pending = false;
    mach_msg_size_t msg_size =
        (mach_msg_size_t)offsetof(mach_send_possible_notification_t, trailer);
    mach_msg_size_t alloc_size = msg_size + MAX_TRAILER_SIZE;
    abi_long guest_buf_ret;
    abi_ulong guest_buf;
    mach_send_possible_notification_t *msg;

    if (max_events <= 0) {
        return 0;
    }

    pthread_mutex_lock(&notification_port_lock);
    for (int i = 0; i < notification_port_count; i++) {
        if (notification_ports[i] == notify_port &&
            notification_msgids[i] == MACH_NOTIFY_SEND_POSSIBLE &&
            notification_send_possible_pending[i]) {
            notification_send_possible_pending[i] = false;
            watched_port = notification_watched_ports[i];
            pending = true;
            break;
        }
    }
    pthread_mutex_unlock(&notification_port_lock);

    if (!pending) {
        return 0;
    }

    mmap_lock();
    guest_buf_ret = target_mmap(0, alloc_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();
    if (guest_buf_ret < 0) {
        return 0;
    }

    guest_buf = (abi_ulong)guest_buf_ret;
    memset(g2h_untagged(guest_buf), 0, alloc_size);
    msg = (mach_send_possible_notification_t *)g2h_untagged(guest_buf);
    msg->not_header.msgh_bits =
        MACH_MSGH_BITS(0, MACH_MSG_TYPE_MOVE_SEND_ONCE);
    msg->not_header.msgh_size = msg_size;
    msg->not_header.msgh_remote_port = MACH_PORT_NULL;
    msg->not_header.msgh_local_port = notify_port;
    msg->not_header.msgh_voucher_port = MACH_PORT_NULL;
    msg->not_header.msgh_id = MACH_NOTIFY_SEND_POSSIBLE;
    msg->NDR = NDR_record;
    msg->not_port = watched_port;
    mach_msg_audit_trailer_t *trailer =
        (mach_msg_audit_trailer_t *)((uint8_t *)msg + ((msg_size + 3) & ~3U));
    trailer->msgh_trailer_type = MACH_MSG_TRAILER_FORMAT_0;
    trailer->msgh_trailer_size = sizeof(*trailer);

    out_events[0] = *template_kev;
    out_events[0].flags = machport_runtime_event_flags(out_events[0].flags);
    out_events[0].fflags = 0;
    out_events[0].data = msg_size;
    out_events[0].ext[0] = (uint64_t)guest_buf;
    out_events[0].ext[1] = alloc_size;
    out_events[0].ext[2] = 0;
    out_events[0].ext[3] = 0;

    if (do_strace) {
        fprintf(stderr, "  synthesized SEND_POSSIBLE notify port 0x%x "
                "watched=0x%x -> guest 0x%llx\n",
                notify_port, watched_port, (unsigned long long)guest_buf);
    }

    return 1;
}

static int drain_notification_machport_events(
    struct kevent_qos_s *template_kev,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms)
{
    int got = take_synthetic_send_possible_events(template_kev, out_events,
                                                  max_events);

    if (got > 0) {
        return filter_workq_notification_events((mach_port_t)template_kev->ident,
                                                out_events, got);
    }

    got = prereceive_machport_drain_timeout(template_kev, out_events,
                                            max_events, timeout_ms);
    return filter_workq_notification_events((mach_port_t)template_kev->ident,
                                            out_events, got);
}

static void save_workq_machport_template(const struct kevent_qos_s *kev)
{
    mach_port_t port = (mach_port_t)kev->ident;

    debug_log_machport_template(kev);

    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (workq_machports[i].port == port) {
            workq_machports[i].template_kev = *kev;
            workq_machports[i].has_template = true;
            workq_machports[i].synthetic = false;
            pthread_mutex_unlock(&workq_machport_lock);
            return;
        }
    }
    if (workq_machport_count < MAX_WORKQ_MACHPORTS) {
        workq_machports[workq_machport_count].port = port;
        workq_machports[workq_machport_count].template_kev = *kev;
        workq_machports[workq_machport_count].has_template = true;
        workq_machports[workq_machport_count].synthetic = false;
        workq_machport_count++;
    }
    pthread_mutex_unlock(&workq_machport_lock);
}

static void register_workq_notification_template(mach_port_t port)
{
    if (do_strace) {
        fprintf(stderr, "  register notify MACHPORT ident=0x%x: "
                "manual polling only\n", (unsigned)port);
    }
}

void service_workloop_machport_events(void)
{
    workloop_port_entry snapshot[MAX_WORKLOOP_PORTS];
    int snapshot_count = 0;

    pthread_mutex_lock(&workloop_port_lock);
    for (int i = 0; i < workloop_port_count; i++) {
        if (!workloop_ports[i].has_template) {
            continue;
        }
        snapshot[snapshot_count++] = workloop_ports[i];
    }
    pthread_mutex_unlock(&workloop_port_lock);

    for (int i = 0; i < snapshot_count; i++) {
        struct kevent_qos_s drained[16];
        bool parked;
        bool notification_port;
        int got;

        notification_port = is_workq_notification_port(snapshot[i].port);
        if (is_port_active_rcv(snapshot[i].port)) {
            if (notification_port) {
                got = take_synthetic_send_possible_events(
                    &snapshot[i].template_kev, drained, ARRAY_SIZE(drained));
                if (got > 0) {
                    got = filter_workq_notification_events(
                        snapshot[i].port, drained, got);
                }
                if (got > 0) {
                    if (do_strace) {
                        fprintf(stderr, "  workloop wl=0x%llx: delivering %d "
                                "synthetic SEND_POSSIBLE event(s) on active "
                                "receive notification port 0x%x\n",
                                (unsigned long long)snapshot[i].workloop_id,
                                got, (unsigned)snapshot[i].port);
                    }
                    deliver_workloop_events_to_thread(snapshot[i].workloop_id,
                                                      drained, got);
                } else if (do_strace) {
                    fprintf(stderr, "  workloop wl=0x%llx: active receive on "
                            "notification port 0x%x has no synthetic "
                            "SEND_POSSIBLE event\n",
                            (unsigned long long)snapshot[i].workloop_id,
                            (unsigned)snapshot[i].port);
                }
            }
            continue;
        }
        if (suppress_workloop_readiness_delivery(
                &snapshot[i].template_kev)) {
            continue;
        }
        if (is_workloop_active(snapshot[i].workloop_id) &&
            !clear_stale_workloop_active(snapshot[i].workloop_id, "poll")) {
            if (notification_port) {
                stash_active_workloop_notification_events(
                    snapshot[i].workloop_id, &snapshot[i], "poll");
                continue;
            }
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: active owner present, "
                        "skipping monitor prereceive on 0x%x\n",
                        (unsigned long long)snapshot[i].workloop_id,
                        (unsigned)snapshot[i].port);
            }
            continue;
        }
        parked = workloop_template_is_readiness_only(&snapshot[i].template_kev)
            ? has_exact_parked_workloop_thread(snapshot[i].workloop_id)
            : has_parked_workloop_thread(snapshot[i].workloop_id);
        if (notification_port && !parked) {
            bool wants_msg =
                template_needs_prereceived_msg(&snapshot[i].template_kev);

            if (wants_msg) {
                got = drain_notification_machport_events(
                    &snapshot[i].template_kev, drained,
                    ARRAY_SIZE(drained), 0);
                if (got > 0) {
                    struct kevent_qos_s zero_wake_ev;

                    if (take_zero_wake_workloop_req(snapshot[i].workloop_id,
                                                    &zero_wake_ev)) {
                        if (do_strace) {
                            fprintf(stderr, "  workloop wl=0x%llx: consumed "
                                    "pending THREAD_REQUEST for notification "
                                    "message on 0x%x\n",
                                    (unsigned long long)snapshot[i].workloop_id,
                                    (unsigned)snapshot[i].port);
                        }
                    } else {
                        got = prepend_workloop_req_event(
                            snapshot[i].workloop_id, NULL, drained, got,
                            ARRAY_SIZE(drained));
                    }
                    if (do_strace) {
                        fprintf(stderr, "  workloop wl=0x%llx: waking for "
                                "%d notification message event(s) on 0x%x\n",
                                 (unsigned long long)snapshot[i].workloop_id,
                                 got, (unsigned)snapshot[i].port);
                    }
                    deliver_workloop_events_to_thread(
                        snapshot[i].workloop_id, drained, got);
                    continue;
                }
                if (do_strace) {
                    fprintf(stderr, "  workloop wl=0x%llx: deferring message "
                            "notification port 0x%x until a message is "
                            "available\n",
                            (unsigned long long)snapshot[i].workloop_id,
                            (unsigned)snapshot[i].port);
                }
                continue;
            }

            got = drain_notification_machport_events(&snapshot[i].template_kev,
                                                     drained,
                                                     ARRAY_SIZE(drained), 0);
            if (got > 0) {
                if (!notification_port) {
                    got = filter_workloop_notification_events(drained, got);
                }
            }
            if (got > 0) {
                if (!wants_msg) {
                    if (do_strace) {
                        fprintf(stderr, "  workloop wl=0x%llx: delivering %d "
                                "notification event(s) on 0x%x\n",
                                (unsigned long long)snapshot[i].workloop_id,
                                got, (unsigned)snapshot[i].port);
                    }
                    deliver_workloop_events_to_thread(snapshot[i].workloop_id,
                                                      drained, got);
                } else {
                    int stashed = stash_workloop_port_events(snapshot[i].port,
                                                             drained, got);
                    if (do_strace) {
                        fprintf(stderr, "  workloop wl=0x%llx: stashed %d deferred "
                                "notification event(s) on 0x%x\n",
                                (unsigned long long)snapshot[i].workloop_id,
                                stashed, (unsigned)snapshot[i].port);
                    }
                }
            } else if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: deferring notification "
                        "port 0x%x until a parked thread is available\n",
                        (unsigned long long)snapshot[i].workloop_id,
                        (unsigned)snapshot[i].port);
            }
            continue;
        }

        if (notification_port) {
            got = drain_notification_machport_events(&snapshot[i].template_kev,
                                                     drained,
                                                     ARRAY_SIZE(drained), 0);
        } else {
            got = prereceive_machport_drain_timeout(&snapshot[i].template_kev,
                                                    drained,
                                                    ARRAY_SIZE(drained), 0);
        }
        if (got > 0) {
            struct kevent_qos_s zero_wake_ev;

            if (!notification_port) {
                got = filter_workloop_notification_events(drained, got);
            }
            if (got > 0) {
                mark_workloop_readiness_delivered(&snapshot[i].template_kev);
            }
            if (got > 0 && parked &&
                take_zero_wake_workloop_req(snapshot[i].workloop_id,
                                            &zero_wake_ev)) {
                if (do_strace) {
                    fprintf(stderr, "  workloop wl=0x%llx: consumed returned "
                            "THREAD_REQUEST while waking parked thread\n",
                            (unsigned long long)snapshot[i].workloop_id);
                }
            }
        }
        if (got > 0) {
            if (!parked) {
                got = prepend_workloop_req_event(snapshot[i].workloop_id,
                                                 NULL, drained, got,
                                                 ARRAY_SIZE(drained));
            }
            if (do_strace) {
                fprintf(stderr, "  workloop wl=0x%llx: polling woke %d "
                        "MACHPORT event(s) on 0x%x\n",
                        (unsigned long long)snapshot[i].workloop_id, got,
                        (unsigned)snapshot[i].port);
            }
            deliver_workloop_events_to_thread(snapshot[i].workloop_id,
                                              drained, got);
        }
    }
}

static void service_workq_notification_events_filtered(bool synthetic_only)
{
    workq_machport_entry snapshot[MAX_WORKQ_MACHPORTS];
    int snapshot_count = 0;

    pthread_mutex_lock(&workq_machport_lock);
    for (int i = 0; i < workq_machport_count; i++) {
        if (!workq_machports[i].has_template ||
            (synthetic_only && !workq_machports[i].synthetic) ||
            !is_workq_notification_port(workq_machports[i].port)) {
            continue;
        }
        snapshot[snapshot_count++] = workq_machports[i];
    }
    pthread_mutex_unlock(&workq_machport_lock);

    if (do_strace && snapshot_count > 0) {
        fprintf(stderr, "  workq MACHPORT snapshot_count=%d\n",
                snapshot_count);
        for (int i = 0; i < snapshot_count; i++) {
            fprintf(stderr, "    snapshot[%d]: port=0x%x notify=%d\n",
                    i, (unsigned)snapshot[i].port,
                    is_workq_notification_port(snapshot[i].port));
        }
    }

    for (int i = 0; i < snapshot_count; i++) {
        struct kevent_qos_s drained[16];
        int got;

        if (is_port_active_rcv(snapshot[i].port)) {
            got = take_synthetic_send_possible_events(&snapshot[i].template_kev,
                                                      drained,
                                                      ARRAY_SIZE(drained));
            if (got > 0) {
                got = filter_workq_notification_events(snapshot[i].port,
                                                       drained, got);
            }
            if (got > 0) {
                if (do_strace) {
                    fprintf(stderr, "  workq MACHPORT 0x%x: delivering %d "
                            "synthetic SEND_POSSIBLE event(s) while active "
                            "receive is pending\n",
                            (unsigned)snapshot[i].port, got);
                }
                deliver_kevents_to_thread(drained, got);
            } else if (do_strace) {
                fprintf(stderr, "  workq MACHPORT 0x%x: active receive has no "
                        "synthetic SEND_POSSIBLE event\n",
                        (unsigned)snapshot[i].port);
            }
            continue;
        }

        got = take_synthetic_send_possible_events(&snapshot[i].template_kev,
                                                  drained,
                                                  ARRAY_SIZE(drained));
        if (got == 0) {
            got = prereceive_machport_drain_timeout(&snapshot[i].template_kev,
                                                     drained,
                                                     ARRAY_SIZE(drained), 0);
        }
        if (got > 0) {
            got = filter_workq_notification_events(snapshot[i].port, drained,
                                                   got);
        }
        if (got > 0) {
            if (do_strace) {
                fprintf(stderr, "  workq MACHPORT 0x%x: polling woke %d "
                        "event(s)\n",
                        (unsigned)snapshot[i].port, got);
            }
            deliver_kevents_to_thread(drained, got);
        }
    }
}

void service_workq_notification_events(void)
{
    service_workq_notification_events_filtered(false);
}

/*
 * Parked workqueue thread — waiting to be re-dispatched.
 *
 * When a wq thread calls WQOPS_THREAD_RETURN, the real kernel parks
 * it (blocks) rather than destroying it.  When new work arrives the
 * kernel wakes a parked thread, sets up its registers, and returns
 * to the wqthread entry point.  We emulate this with a condvar.
 */
typedef struct parked_wq_thread {
    CPUArchState *env;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool has_work;
    /* Stack geometry from original creation */
    abi_ulong self_addr;
    abi_ulong stack_top;
    abi_ulong stack_bottom;
    abi_ulong tsd_base;
    /* New work parameters (set by dispatcher) */
    uint32_t new_flags;
    struct parked_wq_thread *next;
} parked_wq_thread;

static parked_wq_thread *parked_list = NULL;
static pthread_mutex_t parked_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Parked kevent workqueue thread — called WQOPS_THREAD_KEVENT_RETURN
 * and is waiting for new kevent work from the monitor thread.
 */
typedef struct parked_kevent_wq {
    CPUArchState *env;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool has_work;
    abi_ulong self_addr;
    abi_ulong stack_top;
    abi_ulong stack_bottom;
    abi_ulong tsd_base;
    struct kevent_qos_s *delivered_events;
    int delivered_nevents;
    struct parked_kevent_wq *next;
} parked_kevent_wq;

static parked_kevent_wq *parked_kevent_list = NULL;
static pthread_mutex_t parked_kevent_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Parked workloop thread — called WQOPS_THREAD_WORKLOOP_RETURN and
 * waiting for new workloop events from the monitor thread.
 */
typedef struct parked_workloop_wq {
    CPUArchState *env;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool has_work;
    abi_ulong self_addr;
    abi_ulong stack_top;
    abi_ulong stack_bottom;
    abi_ulong tsd_base;
    struct kevent_qos_s *delivered_events;
    int delivered_nevents;
    uint64_t workloop_id;
    struct parked_workloop_wq *next;
} parked_workloop_wq;

static parked_workloop_wq *parked_workloop_list = NULL;
static pthread_mutex_t parked_workloop_lock = PTHREAD_MUTEX_INITIALIZER;

static bool has_exact_parked_workloop_thread(uint64_t workloop_id)
{
    bool found = false;

    pthread_mutex_lock(&parked_workloop_lock);
    for (parked_workloop_wq *pw = parked_workloop_list; pw; pw = pw->next) {
        if (pw->workloop_id == workloop_id) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&parked_workloop_lock);
    return found;
}

static bool has_parked_workloop_thread(uint64_t workloop_id)
{
    return has_exact_parked_workloop_thread(workloop_id);
}

/*
 * Workqueue kqueue monitor.
 *
 * When libdispatch registers EVFILT_MACHPORT events on the workqueue
 * kqueue (via kevent_qos with fd=-1 and KEVENT_FLAG_WORKQ), we forward
 * them to a real kqueue fd.  A dedicated monitor thread blocks on this
 * kqueue and, when events fire, creates or wakes workqueue threads to
 * process them — replicating the kernel's automatic workqueue dispatch.
 */
static pthread_t workq_monitor_tid;
static bool workq_monitor_started;
static CPUArchState *workq_monitor_parent_env;
static TaskState *workq_monitor_parent_ts;

/* Saved udata and QoS from EVFILT_USER registration on workq kqueue */
static uint64_t saved_evfilt_user_udata;
static uint32_t saved_evfilt_user_qos;

#define _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG 0x02000000

static pthread_mutex_t event_manager_lock = PTHREAD_MUTEX_INITIALIZER;
static bool event_manager_active;
static struct kevent_qos_s pending_event_manager_events[16];
static int pending_event_manager_count;

static bool kevent_needs_event_manager(const struct kevent_qos_s *ev)
{
    uint32_t qos;

    if (ev->filter != EVFILT_USER_PRIVATE &&
        ev->filter != EVFILT_TIMER_PRIVATE) {
        return false;
    }

    qos = ev->qos ? ev->qos : saved_evfilt_user_qos;
    return qos & _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG;
}

static bool kevent_list_needs_event_manager(const struct kevent_qos_s *events,
                                            int nevents)
{
    for (int i = 0; events && i < nevents; i++) {
        if (kevent_needs_event_manager(&events[i])) {
            return true;
        }
    }
    return false;
}

static void stash_event_manager_events(const struct kevent_qos_s *events,
                                       int nevents)
{
    for (int i = 0; events && i < nevents; i++) {
        bool duplicate_user_poke = false;

        if (events[i].filter == EVFILT_USER_PRIVATE) {
            for (int j = 0; j < pending_event_manager_count; j++) {
                if (pending_event_manager_events[j].filter ==
                    EVFILT_USER_PRIVATE &&
                    pending_event_manager_events[j].ident == events[i].ident) {
                    duplicate_user_poke = true;
                    break;
                }
            }
        }
        if (duplicate_user_poke) {
            continue;
        }
        if (pending_event_manager_count <
            ARRAY_SIZE(pending_event_manager_events)) {
            pending_event_manager_events[pending_event_manager_count++] =
                events[i];
        }
    }
}

static int finish_event_manager_turn(struct kevent_qos_s *events,
                                     int max_events)
{
    int count;

    pthread_mutex_lock(&event_manager_lock);
    count = MIN(pending_event_manager_count, max_events);
    if (count > 0) {
        memcpy(events, pending_event_manager_events,
               count * sizeof(events[0]));
        if (count < pending_event_manager_count) {
            memmove(pending_event_manager_events,
                    &pending_event_manager_events[count],
                    (pending_event_manager_count - count) *
                    sizeof(pending_event_manager_events[0]));
        }
        pending_event_manager_count -= count;
        event_manager_active = true;
    } else {
        event_manager_active = false;
    }
    pthread_mutex_unlock(&event_manager_lock);

    return count;
}

#define MAX_WORKQ_KNOTE_QOS 64
typedef struct WorkqKnoteQos {
    int16_t filter;
    uint64_t ident;
    uint64_t udata;
    uint32_t qos;
} WorkqKnoteQos;

static WorkqKnoteQos workq_knote_qos[MAX_WORKQ_KNOTE_QOS];
static int workq_knote_qos_count;
static pthread_mutex_t workq_knote_qos_lock = PTHREAD_MUTEX_INITIALIZER;

static void remember_workq_knote_qos(const struct kevent_qos_s *kev)
{
    if (kev->filter != EVFILT_USER_PRIVATE &&
        kev->filter != EVFILT_TIMER_PRIVATE) {
        return;
    }

    pthread_mutex_lock(&workq_knote_qos_lock);
    for (int i = 0; i < workq_knote_qos_count; i++) {
        if (workq_knote_qos[i].filter == kev->filter &&
            workq_knote_qos[i].ident == kev->ident &&
            workq_knote_qos[i].udata == kev->udata) {
            if (kev->flags & EV_DELETE) {
                workq_knote_qos[i] =
                    workq_knote_qos[--workq_knote_qos_count];
            } else if (kev->flags & EV_ADD) {
                workq_knote_qos[i].qos = kev->qos;
            }
            pthread_mutex_unlock(&workq_knote_qos_lock);
            return;
        }
    }

    if ((kev->flags & EV_ADD) && workq_knote_qos_count < MAX_WORKQ_KNOTE_QOS) {
        workq_knote_qos[workq_knote_qos_count++] = (WorkqKnoteQos) {
            .filter = kev->filter,
            .ident = kev->ident,
            .udata = kev->udata,
            .qos = kev->qos,
        };
    }
    pthread_mutex_unlock(&workq_knote_qos_lock);
}

static bool lookup_workq_knote_qos(int16_t filter, uint64_t ident,
                                   uint64_t udata, uint32_t *qos)
{
    bool found = false;

    pthread_mutex_lock(&workq_knote_qos_lock);
    for (int i = 0; i < workq_knote_qos_count; i++) {
        if (workq_knote_qos[i].filter == filter &&
            workq_knote_qos[i].ident == ident &&
            workq_knote_qos[i].udata == udata) {
            *qos = workq_knote_qos[i].qos;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&workq_knote_qos_lock);
    return found;
}

#define MAX_WORKQ_TIMERS 32

typedef struct WorkqTimer {
    bool active;
    bool relative;
    uint64_t deadline;
    uint64_t interval;
    struct kevent_qos_s kev;
} WorkqTimer;

static WorkqTimer workq_timers[MAX_WORKQ_TIMERS];
static pthread_mutex_t workq_timer_lock = PTHREAD_MUTEX_INITIALIZER;

static uint64_t ns_to_mach_ticks(uint64_t ns)
{
    static mach_timebase_info_data_t timebase;

    if (timebase.denom == 0) {
        mach_timebase_info(&timebase);
    }
    if (timebase.numer == 0) {
        return ns;
    }

    __uint128_t ticks = (__uint128_t)ns * timebase.denom;
    ticks /= timebase.numer;
    return ticks > UINT64_MAX ? UINT64_MAX : (uint64_t)ticks;
}

static uint64_t timer_data_to_mach_ticks(int64_t data, uint32_t fflags)
{
    uint64_t value = data > 0 ? (uint64_t)data : 0;

    if (fflags & NOTE_MACHTIME) {
        return value;
    }
    if (fflags & NOTE_SECONDS) {
        return ns_to_mach_ticks(value * 1000000000ULL);
    }
    if (fflags & NOTE_USECONDS) {
        return ns_to_mach_ticks(value * 1000ULL);
    }
    if (fflags & NOTE_NSECONDS) {
        return ns_to_mach_ticks(value);
    }
    return ns_to_mach_ticks(value * 1000000ULL);
}

static bool workq_timer_deadline(const struct kevent_qos_s *kev,
                                 uint64_t now, uint64_t *deadline,
                                 uint64_t *interval, bool *relative)
{
    if ((kev->fflags & NOTE_ABSOLUTE) && !(kev->fflags & NOTE_MACHTIME)) {
        return false;
    }

    uint64_t ticks = timer_data_to_mach_ticks(kev->data, kev->fflags);
    *relative = !(kev->fflags & NOTE_ABSOLUTE);
    *interval = ticks;
    if (*relative) {
        *deadline = UINT64_MAX - now < ticks ? UINT64_MAX : now + ticks;
    } else {
        *deadline = ticks;
    }
    return true;
}

static bool workq_timer_same_knote(const WorkqTimer *timer,
                                   const struct kevent_qos_s *kev)
{
    return timer->active &&
           timer->kev.ident == kev->ident &&
           timer->kev.udata == kev->udata;
}

static int register_workq_timer(const struct kevent_qos_s *kev)
{
    uint64_t now = mach_absolute_time();
    uint64_t deadline;
    uint64_t interval;
    bool relative;
    int slot = -1;

    if (kev->filter != EVFILT_TIMER_PRIVATE) {
        return -1;
    }

    pthread_mutex_lock(&workq_timer_lock);
    for (int i = 0; i < MAX_WORKQ_TIMERS; i++) {
        if (workq_timer_same_knote(&workq_timers[i], kev)) {
            slot = i;
            break;
        }
        if (slot < 0 && !workq_timers[i].active) {
            slot = i;
        }
    }

    if (kev->flags & EV_DELETE) {
        if (slot >= 0 && workq_timer_same_knote(&workq_timers[slot], kev)) {
            workq_timers[slot].active = false;
        }
        pthread_mutex_unlock(&workq_timer_lock);
        return 0;
    }

    if (kev->flags & EV_DISABLE) {
        if (slot >= 0 && workq_timer_same_knote(&workq_timers[slot], kev)) {
            workq_timers[slot].active = false;
        }
        pthread_mutex_unlock(&workq_timer_lock);
        return 0;
    }

    if (slot < 0 ||
        !workq_timer_deadline(kev, now, &deadline, &interval, &relative)) {
        pthread_mutex_unlock(&workq_timer_lock);
        return -1;
    }

    workq_timers[slot].active = true;
    workq_timers[slot].relative = relative;
    workq_timers[slot].deadline = deadline;
    workq_timers[slot].interval = interval;
    workq_timers[slot].kev = *kev;
    remember_workq_knote_qos(kev);

    if (do_strace) {
        fprintf(stderr, "  workq_timer: armed ident=0x%llx udata=0x%llx "
                "flags=0x%x fflags=0x%x data=%lld deadline=%llu now=%llu "
                "qos=0x%x\n",
                (unsigned long long)kev->ident,
                (unsigned long long)kev->udata, kev->flags, kev->fflags,
                (long long)kev->data, (unsigned long long)deadline,
                (unsigned long long)now, kev->qos);
    }

    pthread_mutex_unlock(&workq_timer_lock);
    return 0;
}

static int collect_due_workq_timers(struct kevent_qos_s *events, int max_events)
{
    uint64_t now = mach_absolute_time();
    int count = 0;

    pthread_mutex_lock(&workq_timer_lock);
    for (int i = 0; i < MAX_WORKQ_TIMERS && count < max_events; i++) {
        WorkqTimer *timer = &workq_timers[i];

        if (!timer->active || timer->deadline > now) {
            continue;
        }

        events[count] = timer->kev;
        events[count].flags = EV_ADD | EV_ENABLE | EV_CLEAR |
                              (timer->kev.flags & EV_ONESHOT);
        events[count].fflags = 0;
        events[count].xflags = 0;
        events[count].data = 1;
        memset(events[count].ext, 0, sizeof(events[count].ext));
        count++;

        if ((timer->kev.flags & EV_ONESHOT) || !timer->relative ||
            timer->interval == 0) {
            timer->active = false;
        } else {
            timer->deadline = UINT64_MAX - now < timer->interval
                            ? UINT64_MAX : now + timer->interval;
        }
    }
    pthread_mutex_unlock(&workq_timer_lock);

    if (do_strace && count > 0) {
        fprintf(stderr, "  workq_timer: %d timer event(s) due\n", count);
    }
    return count;
}

/* Stack allocation constants (must match WQOPS_QUEUE_REQTHREADS) */
#define PTH_DEFAULT_STACKSZ    (512 * 1024)
#define PTHREAD_T_OFFSET_ARM64 (12 * 1024)

static int create_guest_thread(CPUArchState *parent_env,
                               abi_ulong pc, abi_ulong sp,
                               abi_ulong arg0, abi_ulong arg1,
                               abi_ulong arg2, abi_ulong arg3,
                               abi_ulong arg4, abi_ulong arg5,
                               abi_ulong tsd_base,
                               TaskState *parent_ts,
                               bool is_workqueue,
                               abi_ulong wq_self, abi_ulong wq_stop,
                               abi_ulong wq_sbot, abi_ulong wq_tsd,
                               uint64_t active_workloop_id);

static void deliver_kevents_to_thread(struct kevent_qos_s *events,
                                      int nevents);
static void deliver_workloop_events_to_thread(uint64_t workloop_id,
                                               struct kevent_qos_s *events,
                                               int nevents);

/*
 * Create a standard (non-kevent, non-workloop) workqueue thread.
 * Used when kevent_qos WORKQ gets NOTE_TRIGGER on EVFILT_USER,
 * indicating libdispatch needs a thread for pending work (timers, etc.).
 */
static int create_guest_thread_for_wq(CPUArchState *env, uint32_t qos)
{
    if (!saved_wqthread || !workq_monitor_parent_env) {
        return -1;
    }

    /* Try to wake a parked thread first */
    parked_wq_thread *pw = NULL;
    pthread_mutex_lock(&parked_lock);
    if (parked_list) {
        pw = parked_list;
        parked_list = pw->next;
        pw->next = NULL;
    }
    pthread_mutex_unlock(&parked_lock);

    uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                   | WQ_FLAG_THREAD_TSD_BASE_SET
                   | WQ_FLAG_THREAD_PRIO_QOS
                   | (qos & 0xF);

    if (pw) {
        uint32_t reuse_flags = (flags & ~WQ_FLAG_THREAD_TSD_BASE_SET)
                             | WQ_FLAG_THREAD_REUSE;
        pthread_mutex_lock(&pw->mutex);
        pw->new_flags = reuse_flags;
        pw->has_work = true;
        pthread_cond_signal(&pw->cond);
        pthread_mutex_unlock(&pw->mutex);
        return 0;
    }

    size_t page_sz = qemu_real_host_page_size();
    size_t guardsize = page_sz;
    size_t pthsize = saved_pthsize ? saved_pthsize : 0x4000;
    size_t total = guardsize + PTH_DEFAULT_STACKSZ
                 + PTHREAD_T_OFFSET_ARM64 + pthsize;

    mmap_lock();
    abi_ulong stackaddr = target_mmap(0, total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();
    if (stackaddr == (abi_ulong)-1) {
        return -1;
    }

    mmap_lock();
    target_mprotect(stackaddr, guardsize, PROT_NONE);
    mmap_unlock();

    abi_ulong stack_bottom = stackaddr + guardsize;
    abi_ulong self_addr = stackaddr + guardsize + PTH_DEFAULT_STACKSZ
                        + PTHREAD_T_OFFSET_ARM64;
    abi_ulong stack_top = self_addr & ~(abi_ulong)0xF;
    abi_ulong tsd_base = self_addr;
    if (saved_tsd_offset) {
        tsd_base = self_addr + saved_tsd_offset;
    }

    TaskState *parent_ts = workq_monitor_parent_ts;

    return create_guest_thread(
        workq_monitor_parent_env,
        saved_wqthread, stack_top,
        self_addr, 0, stack_bottom,
        0, flags, 0, tsd_base, parent_ts,
        true, self_addr, stack_top, stack_bottom, tsd_base, 0);
}

/*
 * Convert kevent_qos_s to kevent64_s for registration on regular kqueues.
 * The kevent_qos syscall doesn't work correctly on regular kqueues
 * (returns EINVAL with flags=0), so we use kevent64 instead.
 */
static void kqos_to_k64(const struct kevent_qos_s *src, struct kevent64_s *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->ident = src->ident;
    dst->filter = src->filter;
    /*
     * Strip EV_UDATA_SPECIFIC (0x100) and EV_VANISHED (0x200) — these
     * are workloop-specific flags that don't work on regular kqueues.
     * Keep EV_DISPATCH (0x80) which is required for EVFILT_MACHPORT
     * with MACH_RCV_MSG.
     */
    dst->flags = src->flags & ~(uint16_t)0x0300;
    dst->fflags = src->fflags;
    dst->data = src->data;
    dst->udata = src->udata;

    if (src->filter == EVFILT_MACHPORT) {
        /*
         * Clear ext[0]/ext[1] for MACHPORT events.  The guest's ext[0]
         * is a guest-space receive buffer that the kernel would try to
         * pre-receive into.  With guest_base != 0 this would corrupt
         * random host memory.  We handle pre-receive ourselves in the
         * monitor thread via prereceive_machport_drain().
         */
        dst->ext[0] = 0;
        dst->ext[1] = 0;
    } else {
        dst->ext[0] = src->ext[0];
        dst->ext[1] = src->ext[1];
    }
}

static void k64_to_kqos(const struct kevent64_s *src, struct kevent_qos_s *dst)
{
    memset(dst, 0, sizeof(*dst));
    dst->ident = src->ident;
    dst->filter = src->filter;
    dst->flags = src->flags;
    dst->fflags = src->fflags;
    dst->data = src->data;
    dst->udata = src->udata;
    dst->ext[0] = src->ext[0];
    dst->ext[1] = src->ext[1];
}

/*
 * Register kevent_qos_s events on a regular kqueue using kevent64.
 * Returns 0 on success, -1 on error.
 */
static int workq_kqueue_register(const struct kevent_qos_s *changelist,
                                 int nchanges)
{
    int kq = get_workq_kqueue();
    int registered = 0;

    for (int i = 0; i < nchanges; i++) {
        if (changelist[i].filter == EVFILT_MACHPORT ||
            changelist[i].filter == EVFILT_TIMER) {
            if (changelist[i].filter == EVFILT_TIMER) {
                int rc = register_workq_timer(&changelist[i]);
                if (rc == 0) {
                    registered++;
                } else if (do_strace) {
                    fprintf(stderr, "  workq_kqueue_register TIMER: "
                            "unsupported ident=0x%llx flags=0x%x "
                            "fflags=0x%x data=%lld\n",
                            (unsigned long long)changelist[i].ident,
                            changelist[i].flags, changelist[i].fflags,
                            (long long)changelist[i].data);
                }
                continue;
            }
            struct kevent64_s k64;
            kqos_to_k64(&changelist[i], &k64);
            int rc = kevent64(kq, &k64, 1, NULL, 0, 0, NULL);
            if (rc < 0) {
                if (do_strace) {
                    fprintf(stderr, "  workq_kqueue_register: "
                            "filter=%d ident=0x%llx failed errno=%d\n",
                            changelist[i].filter,
                            (unsigned long long)changelist[i].ident,
                            errno);
                }
            } else {
                registered++;
            }
        } else {
            /* Skip non-MACHPORT (e.g. WORKLOOP) — can't go on kqueue */
            if (do_strace) {
                fprintf(stderr, "  workq_kqueue_register: "
                        "skip filter=%d ident=0x%llx\n",
                        changelist[i].filter,
                        (unsigned long long)changelist[i].ident);
            }
        }
    }
    return registered > 0 ? 0 : (nchanges > 0 ? -1 : 0);
}

/*
 * Pre-receive a Mach message for an EVFILT_MACHPORT kevent.
 *
 * The XNU kernel pre-receives the Mach message into a buffer before
 * delivering the kevent to workqueue threads.  libdispatch expects this:
 *   fflags==0 → message already received, sitting at ext[0]
 *   fflags==MACH_RCV_TOO_LARGE → message not received, data=size
 *
 * Our regular kqueue cannot pre-receive, so we do it here in the
 * monitor thread.  On success, we update the kevent_qos_s so that
 * the guest thread sees fflags=0 and ext[0]=guest_buffer.
 */
static abi_ulong prereceive_one_msg_timeout(mach_port_t port,
                                            mach_msg_size_t hint_size,
                                            uint32_t receive_flags,
                                            mach_msg_timeout_t timeout_ms,
                                            mach_msg_size_t *received_size_out)
{
    mach_msg_option_t rcv_options =
        MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT |
        (receive_flags & (MACH_RCV_LARGE_IDENTITY |
                          MACH_RCV_TRAILER_MASK |
                          MACH_RCV_VOUCHER |
                          MACH_MSG_STRICT_REPLY));
    mach_msg_size_t trailer_size = REQUESTED_TRAILER_SIZE(rcv_options);
    mach_msg_size_t buf_size = hint_size + trailer_size;
    if (buf_size < 4096) {
        buf_size = 4096;
    }
    void *buf = g_malloc0(buf_size);
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;

    kern_return_t kr = mach_msg(hdr,
        rcv_options,
        0, buf_size, port, timeout_ms, MACH_PORT_NULL);

    if (kr == MACH_RCV_TOO_LARGE) {
        buf_size = hdr->msgh_size + trailer_size;
        buf = g_realloc(buf, buf_size);
        memset(buf, 0, buf_size);
        hdr = (mach_msg_header_t *)buf;
        kr = mach_msg(hdr, rcv_options, 0, buf_size, port, timeout_ms,
                      MACH_PORT_NULL);
    }

    if (kr != KERN_SUCCESS) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    if (hdr->msgh_size < sizeof(mach_msg_header_t) ||
        hdr->msgh_size > buf_size ||
        hdr->msgh_size > UINT32_MAX - MAX_TRAILER_SIZE) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    mach_msg_size_t msg_rounded = (hdr->msgh_size + 3U) & ~3U;
    if (msg_rounded > buf_size ||
        msg_rounded > UINT32_MAX - MAX_TRAILER_SIZE) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    mach_msg_trailer_t *trailer =
        (mach_msg_trailer_t *)((uint8_t *)buf + msg_rounded);
    if (msg_rounded + sizeof(*trailer) <= buf_size &&
        trailer->msgh_trailer_size >= sizeof(*trailer) &&
        trailer->msgh_trailer_size <= MAX_TRAILER_SIZE &&
        msg_rounded <= buf_size - trailer->msgh_trailer_size) {
        trailer_size = trailer->msgh_trailer_size;
    }

    mach_msg_size_t received_size = msg_rounded + trailer_size;
    mach_msg_size_t copy_size = MIN(received_size, buf_size);
    abi_long guest_buf_ret;

    mmap_lock();
    guest_buf_ret = target_mmap(0, received_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();

    if (guest_buf_ret < 0) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    abi_ulong guest_buf = (abi_ulong)guest_buf_ret;
    memcpy(g2h_untagged(guest_buf), buf, copy_size);

    kern_return_t fix_ret = fixup_mig_reply_ool(g2h_untagged(guest_buf),
                                                received_size,
                                                MACH_PORT_NULL);
    if (fix_ret != KERN_SUCCESS) {
        if (do_strace) {
            fprintf(stderr,
                    "  workq_monitor: OOL fixup failed for port 0x%x "
                    "msg_size=%u id=%u ret=%d\n",
                    port, hdr->msgh_size, hdr->msgh_id, fix_ret);
        }
        target_munmap(guest_buf, received_size);
        g_free(buf);
        return (abi_ulong)-1;
    }

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: prereceived port 0x%x "
                "msg_size=%u id=%u -> guest 0x%llx\n",
                port, hdr->msgh_size, hdr->msgh_id,
                (unsigned long long)guest_buf);
    }

    g_free(buf);
    if (received_size_out) {
        *received_size_out = received_size;
    }
    return guest_buf;
}

static abi_ulong prereceive_one_msg(mach_port_t port,
                                    mach_msg_size_t hint_size)
{
    return prereceive_one_msg_timeout(
        port, hint_size,
        MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
        MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
        100, NULL);
}

/*
 * Pre-receive ALL pending Mach messages for an EVFILT_MACHPORT kevent.
 *
 * Drains the port's message queue.  For each received message, creates
 * a kevent_qos_s with fflags=0 and ext[0]=guest_buffer (matching what
 * the kernel delivers to workqueue threads).  Returns the count of
 * successfully pre-received events, stored in out_events[].
 */
static int prereceive_machport_drain(struct kevent_qos_s *template_kev,
                                     struct kevent_qos_s *out_events,
                                     int max_events)
{
    return prereceive_machport_drain_port_timeout(template_kev,
                                                  (mach_port_t)template_kev->ident,
                                                  out_events, max_events, 100);
}

static int prereceive_machport_drain_timeout(
    struct kevent_qos_s *template_kev,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms)
{
    return prereceive_machport_drain_port_timeout(
        template_kev, (mach_port_t)template_kev->ident,
        out_events, max_events, timeout_ms);
}

static int prereceive_machport_drain_port_timeout(
    const struct kevent_qos_s *template_kev,
    mach_port_t port,
    struct kevent_qos_s *out_events,
    int max_events,
    mach_msg_timeout_t timeout_ms)
{
    mach_msg_size_t hint = (mach_msg_size_t)template_kev->data;
    int count = 0;
    bool wants_msg = template_needs_prereceived_msg(template_kev);

    if (!wants_msg) {
        mach_port_status_t status;

        if (!max_events ||
            !machport_get_receive_status(port, &status) ||
            status.mps_msgcount == 0) {
            return 0;
        }
        out_events[0] = *template_kev;
        out_events[0].flags &= ~(uint16_t)(EV_UDATA_SPECIFIC |
                                           EV_VANISHED);
        out_events[0].fflags = 0;
        out_events[0].data = status.mps_msgcount;
        out_events[0].ext[0] = 0;
        out_events[0].ext[1] = 0;
        out_events[0].ext[2] = 0;
        out_events[0].ext[3] = 0;
        return 1;
    }

    /*
     * XNU reports one prereceived MACH_RCV_MSG knote activation per turn.
     * Draining a whole port queue into one dispatch workloop handoff can make
     * libdispatch invoke async-reply state with messages from later turns.
     */
    max_events = MIN(max_events, 1);

    while (count < max_events) {
        mach_msg_size_t received_size = 0;
        abi_ulong guest_buf = prereceive_one_msg_timeout(port, hint,
                                                         template_kev->fflags,
                                                         timeout_ms,
                                                         &received_size);
        if (guest_buf == (abi_ulong)-1) {
            break;
        }
        /* Build kevent for this message */
        out_events[count] = *template_kev;
        /*
         * Returned MACHPORT events don't preserve the workloop-only
         * registration bits; libdispatch expects the runtime event shape.
         */
        out_events[count].flags = machport_runtime_event_flags(
            out_events[count].flags);
        out_events[count].fflags = 0;
        mach_msg_header_t *gh =
            (mach_msg_header_t *)g2h_untagged(guest_buf);
        out_events[count].data = gh->msgh_size;
        out_events[count].ext[0] = (uint64_t)guest_buf;
        out_events[count].ext[1] = received_size;
        out_events[count].ext[2] = 0;
        out_events[count].ext[3] = 0;
        count++;
        hint = 4096;  /* next message might be any size */
    }

    return count;
}

static void *workq_kqueue_monitor_func(void *arg)
{
    struct kevent64_s events64[8];
    struct kevent_qos_s events_qos[8];
    int kq = get_workq_kqueue();
    /*
     * Use a short timeout so we periodically re-trigger EVFILT_USER.
     * libdispatch defers NOTE_TRIGGER pokes, so the manager thread
     * may park before dispatch_after adds its timer.  Periodic
     * re-triggering ensures the manager wakes to process new work.
     */
    struct timespec poll_ts = { .tv_sec = 0, .tv_nsec = 50000000 }; /* 50ms */

    rcu_register_thread();

    while (1) {
        int n = kevent64(kq, NULL, 0, events64, 8, 0, &poll_ts);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            usleep(10000);
            continue;
        }
        if (n == 0) {
            /*
             * Timeout — create a plain workqueue thread to drain
             * pending dispatch work (e.g., dispatch_after timers).
             * libdispatch defers NOTE_TRIGGER pokes, so the manager
             * may miss new work.  A plain thread drains the root
             * queue and processes timers.
             */
            static int idle_ticks;
            struct kevent_qos_s timer_events[8];
            int timer_count = collect_due_workq_timers(
                timer_events, ARRAY_SIZE(timer_events));

            if (timer_count > 0) {
                deliver_kevents_to_thread(timer_events, timer_count);
                idle_ticks = 0;
                continue;
            }

            service_workloop_machport_events();
            service_workq_notification_events_filtered(true);
            idle_ticks++;
            if (idle_ticks >= 2 && saved_wqthread
                && workq_monitor_parent_env) {
                idle_ticks = 0;
                create_guest_thread_for_wq(workq_monitor_parent_env, 4);
            }
            continue;
        }

        /* Convert to kevent_qos_s for the guest */
        for (int i = 0; i < n; i++) {
            uint32_t qos = 0;

            k64_to_kqos(&events64[i], &events_qos[i]);
            if (lookup_workq_knote_qos(events_qos[i].filter,
                                       events_qos[i].ident,
                                       events_qos[i].udata, &qos)) {
                events_qos[i].qos = qos;
            }
        }

        if (do_strace) {
            fprintf(stderr, "  workq_monitor: %d events fired\n", n);
            for (int i = 0; i < n; i++) {
                fprintf(stderr, "    event[%d]: filter=%d ident=0x%llx "
                        "flags=0x%x fflags=0x%x data=%lld "
                        "udata=0x%llx\n",
                        i, events_qos[i].filter,
                        (unsigned long long)events_qos[i].ident,
                        events_qos[i].flags, events_qos[i].fflags,
                        (long long)events_qos[i].data,
                        (unsigned long long)events_qos[i].udata);
            }
        }

        /*
         * Pre-receive Mach messages for MACHPORT events.
         * This replicates the kernel's workqueue kevent delivery which
         * receives the message before waking the thread.
         *
         * We drain ALL pending messages since the port might have
         * multiple (e.g. a notification + the real callback).
         * Each pre-received message becomes a separate kevent delivery.
         */
        struct kevent_qos_s regular_buf[16];
        int regular_count = 0;
        regular_count = collect_due_workq_timers(
            regular_buf, ARRAY_SIZE(regular_buf));
        struct {
            uint64_t wl_id;
            struct kevent_qos_s events[16];
            int count;
        } wl_groups[8];
        int wl_group_count = 0;

        for (int i = 0; i < n; i++) {
            if (events_qos[i].filter == EVFILT_MACHPORT) {
                struct kevent_qos_s drained[16];
                mach_port_t event_port = (mach_port_t)events_qos[i].ident;
                uint64_t wl_id = find_workloop_for_port(event_port);
                bool parked = wl_id &&
                    (workloop_template_is_readiness_only(&events_qos[i])
                     ? has_exact_parked_workloop_thread(wl_id)
                     : has_parked_workloop_thread(wl_id));
                bool workq_notification_port =
                    is_workq_notification_port(event_port);
                bool notification_port = wl_id && workq_notification_port;
                bool rearm_machport = true;

                if (is_port_active_rcv(event_port)) {
                    goto rearm_machport_event;
                }
                if (wl_id &&
                    suppress_workloop_readiness_delivery(&events_qos[i])) {
                    rearm_machport = false;
                    goto rearm_machport_event;
                }
                if (notification_port && !parked) {
                    bool wants_msg = template_needs_prereceived_msg(&events_qos[i]);
                    int got = drain_notification_machport_events(
                        &events_qos[i], drained, ARRAY_SIZE(drained), 100);

                    if (wants_msg) {
                        if (got > 0) {
                            got = prepend_workloop_req_event(
                                wl_id, NULL, drained, got,
                                ARRAY_SIZE(drained));
                            if (do_strace) {
                                fprintf(stderr,
                                        "  workq_monitor: delivering %d "
                                        "notification message event(s) on port "
                                        "0x%x for wl=0x%llx\n",
                                        got, (unsigned)events_qos[i].ident,
                                        (unsigned long long)wl_id);
                            }
                            deliver_workloop_events_to_thread(wl_id, drained,
                                                              got);
                        } else if (do_strace) {
                            fprintf(stderr,
                                    "  workq_monitor: deferring message "
                                    "notification port 0x%x for wl=0x%llx until "
                                    "the thread parks\n",
                                    (unsigned)events_qos[i].ident,
                                    (unsigned long long)wl_id);
                        }
                        goto rearm_machport_event;
                    }

                    if (got > 0) {
                        if (do_strace) {
                            fprintf(stderr,
                                    "  workq_monitor: delivering %d "
                                    "notification event(s) on port 0x%x "
                                    "for wl=0x%llx\n",
                                    got,
                                    (unsigned)events_qos[i].ident,
                                    (unsigned long long)wl_id);
                        }
                        deliver_workloop_events_to_thread(wl_id, drained,
                                                          got);
                    } else if (do_strace) {
                        fprintf(stderr,
                                "  workq_monitor: deferring workloop "
                                "notification port 0x%x for wl=0x%llx until "
                                "the thread parks\n",
                                (unsigned)events_qos[i].ident,
                                (unsigned long long)wl_id);
                    }
                    goto rearm_machport_event;
                }

                int got = prereceive_machport_drain(&events_qos[i],
                                                    drained,
                                                    ARRAY_SIZE(drained));
                if (got == 0) {
                    if (wl_id) {
                        WorkloopMachportState state =
                            workloop_machport_state(
                                (mach_port_t)events_qos[i].ident);
                        if (state != WORKLOOP_MACHPORT_LIVE) {
                            suppress_dead_workloop_machport_fallback(
                                wl_id, (mach_port_t)events_qos[i].ident,
                                "monitor", state);
                        } else if (do_strace) {
                            fprintf(stderr,
                                    "  workq_monitor: dropped empty MACHPORT "
                                    "event on port 0x%x for wl=0x%llx\n",
                                    (unsigned)events_qos[i].ident,
                                    (unsigned long long)wl_id);
                        }
                        goto rearm_machport_event;
                    }
                    if (workq_notification_port) {
                        if (do_strace) {
                            fprintf(stderr,
                                    "  workq_monitor: dropped empty workq "
                                    "notification event on port 0x%x\n",
                                    (unsigned)event_port);
                        }
                        goto rearm_machport_event;
                    }
                    /* Non-workloop consumers can still handle raw events. */
                    drained[0] = events_qos[i];
                    got = 1;
                } else if (wl_id) {
                    if (!notification_port) {
                        got = filter_workloop_notification_events(drained, got);
                    }
                    if (got > 0 &&
                        mark_workloop_readiness_delivered(&events_qos[i])) {
                        rearm_machport = false;
                    }
                    if (got > 0 && !parked) {
                        got = prepend_workloop_req_event(
                            wl_id, NULL, drained, got,
                            ARRAY_SIZE(drained));
                    } else if (got > 0 && parked) {
                        /*
                         * Pair the persistent zero-wake request with these
                         * MACHPORT events, but do not deliver it as a separate
                         * event: libdispatch treats the real MACHPORT message
                         * as the wakeup and only needs the pending request
                         * consumed.
                         */
                        struct kevent_qos_s zero_wake_ev;
                        if (take_zero_wake_workloop_req(wl_id,
                                                        &zero_wake_ev)) {
                            if (do_strace) {
                                fprintf(stderr, "  workloop wl=0x%llx: "
                                        "consumed returned THREAD_REQUEST "
                                        "while grouping MACHPORT event(s)\n",
                                        (unsigned long long)wl_id);
                            }
                        }
                    }
                } else if (workq_notification_port) {
                    got = filter_workq_notification_events(event_port, drained,
                                                          got);
                    if (got == 0) {
                        goto rearm_machport_event;
                    }
                }

                if (wl_id) {
                    int group = -1;
                    for (int g = 0; g < wl_group_count; g++) {
                        if (wl_groups[g].wl_id == wl_id) {
                            group = g;
                            break;
                        }
                    }
                    if (group < 0 && wl_group_count < ARRAY_SIZE(wl_groups)) {
                        group = wl_group_count++;
                        wl_groups[group].wl_id = wl_id;
                        wl_groups[group].count = 0;
                    }
                    if (group >= 0) {
                        for (int j = 0; j < got &&
                             wl_groups[group].count < ARRAY_SIZE(
                                 wl_groups[group].events); j++) {
                            wl_groups[group].events[wl_groups[group].count++] =
                                drained[j];
                        }
                    }
                } else {
                    for (int j = 0; j < got &&
                         regular_count < ARRAY_SIZE(regular_buf); j++) {
                        regular_buf[regular_count++] = drained[j];
                    }
                }

                /*
                 * Re-arm the kevent (EV_ENABLE) so it fires again if
                 * more messages arrive.  EVFILT_MACHPORT with
                 * EV_DISPATCH is one-shot; we must re-enable it.
                 */
rearm_machport_event:
                if (rearm_machport) {
                    struct kevent64_s rearm;
                    memset(&rearm, 0, sizeof(rearm));
                    rearm.ident = events_qos[i].ident;
                    rearm.filter = EVFILT_MACHPORT;
                    rearm.flags = EV_ENABLE;
                    rearm.fflags = events_qos[i].fflags;
                    rearm.udata = events64[i].udata;
                    rearm.ext[0] = events64[i].ext[0];
                    rearm.ext[1] = events64[i].ext[1];
                    kevent64(kq, &rearm, 1, NULL, 0, 0, NULL);
                }
            } else {
                /* Non-MACHPORT event, pass through */
                if (regular_count < ARRAY_SIZE(regular_buf)) {
                    regular_buf[regular_count++] = events_qos[i];
                }
            }
        }

        for (int g = 0; g < wl_group_count; g++) {
            if (wl_groups[g].count > 0) {
                deliver_workloop_events_to_thread(wl_groups[g].wl_id,
                    wl_groups[g].events, wl_groups[g].count);
            }
        }
        if (regular_count > 0) {
            deliver_kevents_to_thread(regular_buf, regular_count);
        }
    }
    return NULL;
}

/*
 * Create or wake a workqueue thread to process kevent events.
 */
static void deliver_kevents_to_thread(struct kevent_qos_s *events,
                                      int nevents)
{
    bool needs_event_manager = kevent_list_needs_event_manager(events, nevents);

    if (needs_event_manager) {
        pthread_mutex_lock(&event_manager_lock);
        if (event_manager_active) {
            stash_event_manager_events(events, nevents);
            if (do_strace) {
                fprintf(stderr, "  workq_monitor: deferred %d event-manager "
                        "kevent(s) while manager active\n", nevents);
            }
            pthread_mutex_unlock(&event_manager_lock);
            return;
        }
        event_manager_active = true;
        pthread_mutex_unlock(&event_manager_lock);
    }

    /* Try to wake a parked kevent thread first */
    parked_kevent_wq *pk = NULL;
    pthread_mutex_lock(&parked_kevent_lock);
    if (parked_kevent_list) {
        pk = parked_kevent_list;
        parked_kevent_list = pk->next;
        pk->next = NULL;
    }
    pthread_mutex_unlock(&parked_kevent_lock);

    if (pk) {
        pk->delivered_events = g_memdup2(events,
            nevents * sizeof(struct kevent_qos_s));
        pk->delivered_nevents = nevents;

        if (do_strace) {
            fprintf(stderr, "  workq_monitor: waking parked kevent "
                    "thread self=0x%lx with %d events\n",
                    (unsigned long)pk->self_addr, nevents);
            for (int i = 0; i < nevents; i++) {
                fprintf(stderr,
                        "    deliver-kevent[%d]: filter=%d ident=0x%llx "
                        "flags=0x%x fflags=0x%x data=%lld udata=0x%llx "
                        "ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                        i, events[i].filter,
                        (unsigned long long)events[i].ident,
                        events[i].flags, events[i].fflags,
                        (long long)events[i].data,
                        (unsigned long long)events[i].udata,
                        (unsigned long long)events[i].ext[0],
                        (unsigned long long)events[i].ext[1],
                        (unsigned long long)events[i].ext[2],
                        (unsigned long long)events[i].ext[3]);
            }
        }

        pthread_mutex_lock(&pk->mutex);
        pk->has_work = true;
        pthread_cond_signal(&pk->cond);
        pthread_mutex_unlock(&pk->mutex);
        return;
    }

    /* No parked kevent thread — create a new workqueue thread */
    if (!saved_wqthread || !workq_monitor_parent_env) {
        if (needs_event_manager) {
            pthread_mutex_lock(&event_manager_lock);
            event_manager_active = false;
            pthread_mutex_unlock(&event_manager_lock);
        }
        return;
    }

    size_t page_sz = qemu_real_host_page_size();
    size_t guardsize = page_sz;
    size_t pthsize = saved_pthsize ? saved_pthsize : 0x4000;
    size_t total = guardsize + PTH_DEFAULT_STACKSZ
                 + PTHREAD_T_OFFSET_ARM64 + pthsize;

    mmap_lock();
    abi_ulong stackaddr = target_mmap(0, total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();

    if (stackaddr == (abi_ulong)-1) {
        if (needs_event_manager) {
            pthread_mutex_lock(&event_manager_lock);
            event_manager_active = false;
            pthread_mutex_unlock(&event_manager_lock);
        }
        return;
    }

    mmap_lock();
    target_mprotect(stackaddr, guardsize, PROT_NONE);
    mmap_unlock();

    abi_ulong stack_bottom = stackaddr + guardsize;
    abi_ulong self_addr = stackaddr + guardsize + PTH_DEFAULT_STACKSZ
                        + PTHREAD_T_OFFSET_ARM64;
    abi_ulong stack_top = self_addr & ~(abi_ulong)0xF;

    abi_ulong tsd_base = self_addr;
    if (saved_tsd_offset) {
        tsd_base = self_addr + saved_tsd_offset;
    }

    /*
     * Allocate keventlist on the new thread's stack.
     * libdispatch reuses this buffer for deferred items (up to 16),
     * so allocate at least 16 slots even if we only have a few events.
     */
#define DISPATCH_DEFERRED_ITEMS_MAX 16
    int keventlist_slots = nevents > DISPATCH_DEFERRED_ITEMS_MAX
                         ? nevents : DISPATCH_DEFERRED_ITEMS_MAX;
    size_t keventlist_sz = keventlist_slots * sizeof(struct kevent_qos_s);
    abi_ulong sp = stack_top;
    sp -= keventlist_sz;
    sp &= ~(abi_ulong)0xF;
    memset(g2h_untagged(sp), 0, keventlist_sz);
    memcpy(g2h_untagged(sp), events,
           nevents * sizeof(struct kevent_qos_s));
    abi_ulong keventlist = sp;
#undef DISPATCH_DEFERRED_ITEMS_MAX

    sp -= 256;  /* headroom */
    sp &= ~(abi_ulong)0xF;

    uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                   | WQ_FLAG_THREAD_TSD_BASE_SET
                   | WQ_FLAG_THREAD_KEVENT;

    /*
     * If the EVFILT_USER was registered with event manager QoS
     * (by libdispatch's _dispatch_kq_init), mark this thread as
     * the event manager.  XNU sets EVENT_MANAGER *without*
     * PRIO_QOS — they are mutually exclusive.
     */
    bool is_event_manager = false;
    for (int i = 0; i < nevents; i++) {
        if ((events[i].filter == EVFILT_USER ||
             events[i].filter == EVFILT_TIMER) &&
            ((events[i].qos ? events[i].qos : saved_evfilt_user_qos) &
             _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)) {
            is_event_manager = true;
            break;
        }
    }
    if (is_event_manager) {
        flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
    } else {
        flags |= WQ_FLAG_THREAD_PRIO_QOS | 4;  /* QoS default */
    }

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: creating kevent thread "
                "self=0x%lx sp=0x%lx keventlist=0x%lx "
                "nevents=%d flags=0x%x\n",
                (unsigned long)self_addr, (unsigned long)sp,
                (unsigned long)keventlist, nevents, flags);
    }

    int rc = create_guest_thread(
        workq_monitor_parent_env,
        saved_wqthread,
        sp,
        self_addr,       /* x0 = pthread_self */
        0,               /* x1 = kport (set by worker) */
        stack_bottom,    /* x2 = stacklowaddr */
        keventlist,      /* x3 = keventlist */
        flags,           /* x4 = flags */
        nevents,         /* x5 = nkevents */
        tsd_base,
        workq_monitor_parent_ts,
        true, self_addr, stack_top,
        stack_bottom, tsd_base, 0);
    if (do_strace) {
        fprintf(stderr, "  workq_monitor: kevent thread create rc=%d "
                "self=0x%lx\n", rc, (unsigned long)self_addr);
    }
    if (rc < 0 && needs_event_manager) {
        pthread_mutex_lock(&event_manager_lock);
        event_manager_active = false;
        pthread_mutex_unlock(&event_manager_lock);
    }
}

/*
 * Create or wake a workloop thread to process events for a specific
 * dispatch workloop.  Unlike kevent threads, workloop threads pass the
 * workloop ID (kqueue_id_t) on the stack immediately before the
 * keventlist so libpthread's wqthread_start can hand it to
 * __libdispatch_workloopfunction.
 */
static void deliver_workloop_events_to_thread(uint64_t workloop_id,
                                              struct kevent_qos_s *events,
                                              int nevents)
{
    if (nevents <= 0) {
        if (do_strace) {
            fprintf(stderr, "  workq_monitor: skipping empty workloop "
                    "delivery wl=0x%llx\n",
                    (unsigned long long)workloop_id);
        }
        return;
    }

    if (!mark_workloop_active(workloop_id)) {
        if (do_strace) {
            fprintf(stderr, "  workq_monitor: deferring %d event(s) for "
                    "active workloop wl=0x%llx\n", nevents,
                    (unsigned long long)workloop_id);
        }
        defer_active_workloop_events(workloop_id, events, nevents);
        return;
    }

    refresh_workloop_delivery_values(events, nevents);

    /* Try to wake a parked workloop thread first */
    parked_workloop_wq *pw = NULL;
    pthread_mutex_lock(&parked_workloop_lock);
    parked_workloop_wq **link = &parked_workloop_list;
    while (*link) {
        if ((*link)->workloop_id == workloop_id) {
            pw = *link;
            *link = pw->next;
            pw->next = NULL;
            break;
        }
        link = &(*link)->next;
    }
    pthread_mutex_unlock(&parked_workloop_lock);

    if (pw) {
        /*
         * If a zero-wake THREAD_REQUEST is pending for this workloop, consume
         * it when real events arrive.  The real MACHPORT event is the wakeup;
         * delivering the returned THREAD_REQUEST as a second event can make
         * libdispatch replay stale workloop state.
         */
        struct kevent_qos_s zero_wake_ev;
        bool consumed_zero = (nevents > 0 &&
            take_zero_wake_workloop_req(workloop_id, &zero_wake_ev));
        int total = nevents;

        if (total > 0) {
            pw->delivered_events = g_malloc(
                total * sizeof(struct kevent_qos_s));
            if (events && nevents > 0) {
                memcpy(pw->delivered_events, events,
                       nevents * sizeof(struct kevent_qos_s));
            }
        } else {
            pw->delivered_events = NULL;
        }
        pw->delivered_nevents = total;
        pw->workloop_id = workloop_id;

        if (do_strace) {
            if (consumed_zero) {
                fprintf(stderr, "  workq_monitor: consumed returned "
                        "THREAD_REQUEST for wl=0x%llx before wake\n",
                        (unsigned long long)workloop_id);
            }
            fprintf(stderr, "  workq_monitor: waking parked workloop "
                    "thread self=0x%lx wl=0x%llx with %d events\n",
                    (unsigned long)pw->self_addr,
                    (unsigned long long)workloop_id, nevents);
            for (int i = 0; events && i < nevents; i++) {
                fprintf(stderr, "    deliver kev[%d]: filter=%d ident=0x%llx "
                        "flags=0x%x fflags=0x%x data=%lld qos=0x%x udata=0x%llx "
                        "ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                        i, events[i].filter,
                        (unsigned long long)events[i].ident,
                        events[i].flags, events[i].fflags,
                        (long long)events[i].data, events[i].qos,
                        (unsigned long long)events[i].udata,
                        (unsigned long long)events[i].ext[0],
                        (unsigned long long)events[i].ext[1],
                        (unsigned long long)events[i].ext[2],
                        (unsigned long long)events[i].ext[3]);
            }
        }

        pthread_mutex_lock(&pw->mutex);
        pw->has_work = true;
        pthread_cond_signal(&pw->cond);
        pthread_mutex_unlock(&pw->mutex);
        return;
    }

    /* No parked workloop thread — create a new one */
    if (!saved_wqthread || !workq_monitor_parent_env) {
        clear_workloop_active(workloop_id);
        return;
    }

    size_t page_sz = qemu_real_host_page_size();
    size_t guardsize = page_sz;
    size_t pthsize = saved_pthsize ? saved_pthsize : 0x4000;
    size_t total = guardsize + PTH_DEFAULT_STACKSZ
                 + PTHREAD_T_OFFSET_ARM64 + pthsize;

    mmap_lock();
    abi_ulong stackaddr = target_mmap(0, total,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();

    if (stackaddr == (abi_ulong)-1) {
        clear_workloop_active(workloop_id);
        return;
    }

    mmap_lock();
    target_mprotect(stackaddr, guardsize, PROT_NONE);
    mmap_unlock();

    abi_ulong stack_bottom = stackaddr + guardsize;
    abi_ulong self_addr = stackaddr + guardsize + PTH_DEFAULT_STACKSZ
                        + PTHREAD_T_OFFSET_ARM64;
    abi_ulong stack_top = self_addr & ~(abi_ulong)0xF;

    abi_ulong tsd_base = self_addr;
    if (saved_tsd_offset) {
        tsd_base = self_addr + saved_tsd_offset;
    }

    /*
     * Stack layout for workloop threads (from libpthread source):
     *   [kqueue_id_t]   <- kqidptr = keventlist - 8
     *   [kevent_qos_s]  <- keventlist (x3 points here)
     *   [kevent_qos_s]
     *   ...
     */
#define DISPATCH_DEFERRED_ITEMS_MAX 16
    int workloop_slots = nevents > DISPATCH_DEFERRED_ITEMS_MAX
                       ? nevents : DISPATCH_DEFERRED_ITEMS_MAX;
    size_t events_sz = workloop_slots * sizeof(struct kevent_qos_s);
    abi_ulong sp = stack_top;
    /* Reserve space for kqueue_id_t + events */
    sp -= sizeof(uint64_t) + events_sz;
    sp &= ~(abi_ulong)0xF;

    /* Write kqueue_id_t first, then events */
    abi_ulong kqid_addr = sp;
    abi_ulong keventlist = sp + sizeof(uint64_t);
    *(uint64_t *)g2h_untagged(kqid_addr) = workloop_id;
    memset(g2h_untagged(keventlist), 0, events_sz);
    if (events && nevents > 0) {
        memcpy(g2h_untagged(keventlist), events,
               nevents * sizeof(struct kevent_qos_s));
    }
#undef DISPATCH_DEFERRED_ITEMS_MAX

    sp -= 256;  /* headroom */
    sp &= ~(abi_ulong)0xF;

    uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                   | WQ_FLAG_THREAD_TSD_BASE_SET
                   | WQ_FLAG_THREAD_PRIO_QOS
                   | WQ_FLAG_THREAD_KEVENT
                   | WQ_FLAG_THREAD_WORKLOOP
                   | 4;  /* QoS default */

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: creating workloop thread "
                "self=0x%lx sp=0x%lx keventlist=0x%lx "
                "wl=0x%llx nevents=%d flags=0x%x\n",
                (unsigned long)self_addr, (unsigned long)sp,
                (unsigned long)keventlist,
                (unsigned long long)workloop_id, nevents, flags);
        for (int i = 0; events && i < nevents; i++) {
            fprintf(stderr, "    deliver kev[%d]: filter=%d ident=0x%llx "
                    "flags=0x%x fflags=0x%x data=%lld qos=0x%x udata=0x%llx "
                    "ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                    i, events[i].filter,
                    (unsigned long long)events[i].ident,
                    events[i].flags, events[i].fflags,
                    (long long)events[i].data, events[i].qos,
                    (unsigned long long)events[i].udata,
                    (unsigned long long)events[i].ext[0],
                    (unsigned long long)events[i].ext[1],
                    (unsigned long long)events[i].ext[2],
                    (unsigned long long)events[i].ext[3]);
        }
    }

    int rc = create_guest_thread(
        workq_monitor_parent_env,
        saved_wqthread,
        sp,
        self_addr,       /* x0 = pthread_self */
        0,               /* x1 = kport (set by worker) */
        stack_bottom,    /* x2 = stacklowaddr */
        keventlist,      /* x3 = keventlist */
        flags,           /* x4 = flags */
        nevents,         /* x5 = nkevents */
        tsd_base,
        workq_monitor_parent_ts,
        true, self_addr, stack_top,
        stack_bottom, tsd_base, workloop_id);
    if (do_strace) {
        fprintf(stderr, "  workq_monitor: workloop thread create rc=%d "
                "self=0x%lx wl=0x%llx\n", rc, (unsigned long)self_addr,
                (unsigned long long)workloop_id);
    }
    if (rc < 0) {
        clear_workloop_active(workloop_id);
    }
}

static void ensure_workq_monitor(CPUArchState *env, TaskState *ts)
{
    if (workq_monitor_started) {
        return;
    }
    workq_monitor_started = true;
    workq_monitor_parent_env = env;
    workq_monitor_parent_ts = ts;

    /*
     * Transition to parallel code generation NOW, while we're on a guest
     * thread (current_cpu is set).  The monitor is a host-only thread and
     * cannot safely call tb_flush__exclusive_or_serial(), so make sure
     * CF_PARALLEL is already set before the monitor ever calls
     * create_guest_thread → begin_parallel_context.
     */
    begin_parallel_context(env_cpu(env));

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 256 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&workq_monitor_tid, &attr,
                   workq_kqueue_monitor_func, NULL);
    pthread_attr_destroy(&attr);

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: started, kq_fd=%d\n",
                get_workq_kqueue());
    }
}

typedef struct {
    CPUArchState *env;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    TaskState *parent_ts;
    /* For bsdthread_create */
    abi_ulong start_func;
    abi_ulong func_arg;
    abi_ulong stack;
    abi_ulong pthread_self;
    uint32_t flags;
    abi_ulong tsd_base;
    /* For workqueue threads */
    bool is_workqueue;
    int wq_flags;
    abi_ulong wq_self_addr;
    abi_ulong wq_stack_top;
    abi_ulong wq_stack_bottom;
    abi_ulong wq_tsd_base;
} new_thread_info;

static pthread_mutex_t clone_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Allocate a guest stack for a new thread.
 * Returns the stack top (highest address, SP-aligned).
 */
static abi_ulong alloc_thread_stack(size_t size)
{
    abi_ulong addr;

    mmap_lock();
    addr = target_mmap(0, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();

    if (addr == (abi_ulong)-1) {
        return 0;
    }
    /* Stack grows down: return top of allocation */
    return addr + size;
}

static void strace_dump_guest_backtrace(CPUArchState *env, const char *tag)
{
    uint64_t fp = env->xregs[29];
    uint64_t mach_self_slot = 0;

    if (saved_mach_thread_self_offset &&
        guest_range_valid_untagged(env->cp15.tpidrro_el[0] +
                                   saved_mach_thread_self_offset,
                                   sizeof(uint64_t))) {
        mach_self_slot =
            *(uint64_t *)g2h_untagged(env->cp15.tpidrro_el[0] +
                                      saved_mach_thread_self_offset);
    }

    fprintf(stderr,
            "  %s pc=0x%lx lr=0x%lx tpidr=0x%lx tpidrro=0x%lx mach_self=0x%lx\n",
            tag,
            (unsigned long)env->pc,
            (unsigned long)env->xregs[30],
            (unsigned long)env->cp15.tpidr_el[0],
            (unsigned long)env->cp15.tpidrro_el[0],
            (unsigned long)mach_self_slot);
    for (int i = 0; i < 16 && fp != 0; i++) {
        uint64_t *frame;
        uint64_t saved_fp;
        uint64_t saved_lr;

        if (!guest_range_valid_untagged(fp, 2 * sizeof(uint64_t))) {
            fprintf(stderr, "    bt[%d] invalid fp=0x%lx\n", i,
                    (unsigned long)fp);
            break;
        }
        frame = g2h_untagged(fp);
        saved_fp = frame[0];
        saved_lr = frame[1];
        fprintf(stderr, "    bt[%d]=0x%lx\n", i, (unsigned long)saved_lr);
        if (saved_fp <= fp) {
            break;
        }
        fp = saved_fp;
    }
}

static void write_mach_thread_self_tsd_slot(abi_ulong tsd_base,
                                            mach_port_t self_port)
{
    abi_ulong slot_addr;

    if (!tsd_base || !saved_mach_thread_self_offset) {
        return;
    }

    slot_addr = tsd_base + saved_mach_thread_self_offset;
    if (!guest_range_valid_untagged(slot_addr, sizeof(uint64_t))) {
        return;
    }

    *(uint64_t *)g2h_untagged(slot_addr) = (uint64_t)self_port;
}

/*
 * Host thread function for new guest threads.
 * Clones CPU state and enters cpu_loop.
 */
static void *guest_thread_func(void *arg)
{
    new_thread_info *shared_info = arg;
    new_thread_info local_info = *shared_info;
    new_thread_info *info = &local_info;
    CPUArchState *env;
    CPUState *cpu;
    TaskState *ts;
    mach_port_t self_port;

    /*
     * The startup record lives on the creator's stack.  Copy it before any
     * potentially blocking registration, then let the creator release
     * clone_lock.  Otherwise an RCU/TCG registration stall can deadlock other
     * guest threads that need to clone concurrently.
     */
    pthread_mutex_lock(&shared_info->mutex);
    pthread_cond_broadcast(&shared_info->cond);
    pthread_mutex_unlock(&shared_info->mutex);

    if (do_strace && info->is_workqueue) {
        fprintf(stderr, "  guest_thread_stage: after-start-signal "
                "self=0x%lx pc=0x%lx\n",
                (unsigned long)info->wq_self_addr,
                (unsigned long)info->env->pc);
    }

    rcu_register_thread();
    if (do_strace && info->is_workqueue) {
        fprintf(stderr, "  guest_thread_stage: after-rcu self=0x%lx\n",
                (unsigned long)info->wq_self_addr);
    }
    tcg_register_thread();
    if (do_strace && info->is_workqueue) {
        fprintf(stderr, "  guest_thread_stage: after-tcg self=0x%lx\n",
                (unsigned long)info->wq_self_addr);
    }

    env = info->env;
    cpu = env_cpu(env);
    thread_cpu = cpu;

    ts = get_task_state(cpu);
    ts->ts_tid = qemu_get_thread_id();

    /*
     * Save workqueue thread stack geometry in TaskState so
     * WQOPS_THREAD_RETURN can park and later re-dispatch this thread
     * without needing to remember the original creation parameters.
     */
    if (info->is_workqueue) {
        ts->is_wq_thread = true;
        ts->wq_self_addr = info->wq_self_addr;
        ts->wq_stack_top = info->wq_stack_top;
        ts->wq_stack_bottom = info->wq_stack_bottom;
        ts->wq_tsd_base = info->wq_tsd_base;
        ts->wq_event_manager =
            info->wq_flags & WQ_FLAG_THREAD_EVENT_MANAGER;
    }

    /*
     * Set x1 = mach_thread_self() for this thread.
     * XNU sets kport to the new thread's own Mach port.
     * We must call mach_thread_self() here (on the worker thread)
     * rather than from the parent, otherwise os_unfair_lock sees the
     * main thread's port and falsely detects recursion.
     */
    self_port = mach_thread_self();
    if (do_strace && info->is_workqueue) {
        fprintf(stderr, "  guest_thread_stage: after-mach-self "
                "self=0x%lx port=0x%x\n",
                (unsigned long)info->wq_self_addr, self_port);
    }
    env->xregs[1] = (abi_ulong)self_port;
    write_mach_thread_self_tsd_slot(
        info->is_workqueue ? info->wq_tsd_base : info->tsd_base,
        self_port);

    if (do_strace && info->is_workqueue) {
        fprintf(stderr,
                "  guest_thread_start: pc=0x%lx self=0x%lx "
                "sp=0x%lx x2=0x%lx x3=0x%lx flags=0x%lx nevents=%lu\n",
                (unsigned long)env->pc,
                (unsigned long)env->xregs[0],
                (unsigned long)env->xregs[31],
                (unsigned long)env->xregs[2],
                (unsigned long)env->xregs[3],
                (unsigned long)env->xregs[4],
                (unsigned long)env->xregs[5]);
    }

    /* Wait for parent to finish setup */
    pthread_mutex_lock(&clone_lock);
    pthread_mutex_unlock(&clone_lock);

    cpu_loop(env);
    /* NOTREACHED */
    return NULL;
}

/*
 * Create a new guest thread.
 * Sets up a cloned CPU with pc/sp/args and spawns a host thread.
 * Returns 0 on success, -errno on failure.
 */
static int create_guest_thread(CPUArchState *parent_env,
                               abi_ulong pc, abi_ulong sp,
                               abi_ulong arg0, abi_ulong arg1,
                               abi_ulong arg2, abi_ulong arg3,
                               abi_ulong arg4, abi_ulong arg5,
                               abi_ulong tsd_base,
                               TaskState *parent_ts,
                               bool is_workqueue,
                               abi_ulong wq_self, abi_ulong wq_stop,
                               abi_ulong wq_sbot, abi_ulong wq_tsd,
                               uint64_t active_workloop_id)
{
    CPUState *parent_cpu = env_cpu(parent_env);
    CPUArchState *new_env;
    CPUState *new_cpu;
    TaskState *ts;
    new_thread_info info;
    pthread_attr_t attr;
    int ret;

    /* Grab clone lock so thread setup is atomic */
    pthread_mutex_lock(&clone_lock);

    /* Switch to parallel code generation on first additional thread */
    begin_parallel_context(parent_cpu);

    /* Clone the CPU */
    new_env = cpu_copy(parent_env);
    new_cpu = env_cpu(new_env);

    /* Set up new task state */
    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    ts->bprm = parent_ts->bprm;
    ts->info = parent_ts->info;
    ts->signal_mask = parent_ts->signal_mask;
    ts->active_workloop_id = active_workloop_id;
    new_cpu->opaque = ts;

    /* Set up the new thread's registers */
    new_env->pc = pc;
    new_env->xregs[0] = arg0;
    new_env->xregs[1] = arg1;
    new_env->xregs[2] = arg2;
    new_env->xregs[3] = arg3;
    new_env->xregs[4] = arg4;
    new_env->xregs[5] = arg5;
    new_env->xregs[29] = 0;  /* FP */
    new_env->xregs[30] = 0;  /* LR — thread should never return */
    if (sp) {
        new_env->xregs[31] = sp;
    }

    /*
     * Set up TPIDRRO_EL0 for the new thread.  TPIDR_EL0 is libplatform's
     * cthread slot and is inherited from the parent CPU state; pthread_self()
     * is reached through TPIDRRO_EL0/TSD, not by overwriting TPIDR_EL0.
     */
    new_env->cp15.tpidrro_el[0] = tsd_base;

    /* Prepare thread info for synchronization */
    memset(&info, 0, sizeof(info));
    pthread_mutex_init(&info.mutex, NULL);
    pthread_mutex_lock(&info.mutex);
    pthread_cond_init(&info.cond, NULL);
    info.env = new_env;
    info.parent_ts = parent_ts;
    info.tsd_base = tsd_base;
    info.is_workqueue = is_workqueue;
    info.wq_self_addr = wq_self;
    info.wq_stack_top = wq_stop;
    info.wq_stack_bottom = wq_sbot;
    info.wq_tsd_base = wq_tsd;
    info.wq_flags = (int)arg4;

    /* Create host thread */
    pthread_t thread_id;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 1024 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    ret = pthread_create(&thread_id, &attr, guest_thread_func, &info);
    pthread_attr_destroy(&attr);

    if (ret != 0) {
        g_free(ts);
        pthread_mutex_unlock(&clone_lock);
        return -ret;
    }

    /* Wait for child to initialize */
    pthread_cond_wait(&info.cond, &info.mutex);
    pthread_mutex_unlock(&info.mutex);
    pthread_mutex_unlock(&clone_lock);

    return 0;
}

/*
 * On macOS with Cryptex volumes (macOS 13+), /System/Library/dyld/ does
 * not exist on the root volume.  The shared cache files live under the
 * Cryptex prefix.  dyld hardcodes the traditional path, so we redirect
 * file-system accesses to the actual location.
 */
#define CRYPTEX_PREFIX "/System/Volumes/Preboot/Cryptexes/OS"
#define DYLD_CACHE_DIR "/System/Library/dyld"

static const char *redirect_path(const char *path, char *buf, size_t bufsz)
{
    if (strncmp(path, DYLD_CACHE_DIR, strlen(DYLD_CACHE_DIR)) == 0) {
        snprintf(buf, bufsz, "%s%s", CRYPTEX_PREFIX, path);
        struct stat st;
        if (stat(buf, &st) == 0) {
            return buf;
        }
    }
    return path;
}

/*
 * PAC signing helpers — declared in target/arm/tcg/pauth_helper.c.
 * We use these to PAC-sign shared-cache pointers during fixup
 * processing so that the guest's autda/autia instructions can
 * successfully authenticate them at runtime.
 */
uint64_t helper_pacia(CPUARMState *env, uint64_t x, uint64_t y);
uint64_t helper_pacda(CPUARMState *env, uint64_t x, uint64_t y);

/*
 * Process ARM64e chained fixups (slide info v5) for a shared cache
 * mapping.  This replicates what XNU's vm_shared_region_slide_page_v5()
 * does: walk the fixup chains page by page, rebase every pointer by
 * (value_add + slide), and PAC-sign authenticated pointers using the
 * guest CPU's keys.
 *
 * @env:         guest CPU state (carries PAC keys)
 * @slide_buf:   slide info data read from the cache file
 * @slide_len:   length of slide_buf in bytes
 * @mapped_host: host pointer to the mapped region
 * @guest_addr:  guest base address of the mapped region
 * @region_size: size of the mapped region
 * @slide:       ASLR slide amount (0 for private caches)
 */
static void apply_slide_info_v5(CPUARMState *env,
                                const uint8_t *slide_buf,
                                uint64_t slide_len,
                                void *mapped_host,
                                uint64_t guest_addr,
                                uint64_t region_size,
                                uint32_t slide)
{
    /* dyld_cache_slide_info5 header (24 bytes including value_add). */
    if (slide_len < 24) {
        return;
    }
    uint32_t version, page_size, page_starts_count;
    uint64_t value_add;
    memcpy(&version, slide_buf, 4);
    memcpy(&page_size, slide_buf + 4, 4);
    memcpy(&page_starts_count, slide_buf + 8, 4);
    /* 4 bytes padding at offset 12 */
    memcpy(&value_add, slide_buf + 16, 8);

    if (version != 5 || page_size == 0 || (page_size & 7) ||
        page_starts_count == 0) {
        if (do_strace) {
            fprintf(stderr, "qemu: slide info version %u (expected 5), skipping\n",
                    version);
        }
        return;
    }

    /* page_starts array follows the header (uint16_t each) */
    const uint16_t *page_starts =
        (const uint16_t *)(slide_buf + 24);
    uint64_t needed = 24 + (uint64_t)page_starts_count * 2;
    if (needed > slide_len) {
        return;
    }

    for (uint32_t pi = 0; pi < page_starts_count; pi++) {
        uint16_t start = page_starts[pi];
        if (start == 0xFFFF) {
            continue; /* DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE */
        }

        uint64_t page_off = (uint64_t)pi * page_size;
        if (page_off >= region_size) {
            break;
        }
        uint64_t page_available = MIN((uint64_t)page_size,
                                      region_size - page_off);
        if ((start & 7) || start + sizeof(uint64_t) > page_available) {
            if (do_strace) {
                fprintf(stderr, "qemu: invalid slide chain start page=%u "
                        "start=0x%x page_available=0x%llx\n",
                        pi, start, (unsigned long long)page_available);
            }
            continue;
        }

        uint8_t *page_base = (uint8_t *)mapped_host + page_off;
        uint8_t *page_end = page_base + page_available;
        uint8_t *loc = page_base + start;
        uint32_t max_chain_entries = page_available / sizeof(uint64_t);

        for (uint32_t chain = 0; chain < max_chain_entries; chain++) {
            uint64_t raw;
            memcpy(&raw, loc, 8);

            /* Extract chain-next delta (bits 62:52, in 8-byte units) */
            uint64_t delta =
                ((raw & 0x7FF0000000000000ULL) >> 52) * 8;

            bool is_auth = (raw & (1ULL << 63)) != 0;
            uint64_t runtime_offset = raw & 0x3FFFFFFFFULL;
            uint64_t target = runtime_offset + value_add + slide;

            if (is_auth) {
                uint16_t diversity = (uint16_t)((raw >> 34) & 0xFFFF);
                bool addr_div = (raw & (1ULL << 50)) != 0;
                bool key_is_data = (raw & (1ULL << 51)) != 0;

                uint64_t modifier;
                if (addr_div) {
                    uint64_t slot_addr = guest_addr +
                        (uint64_t)(loc - (uint8_t *)mapped_host);
                    modifier = ((uint64_t)diversity << 48) |
                               (slot_addr & 0x0000FFFFFFFFFFFFULL);
                } else {
                    modifier = (uint64_t)diversity;
                }

                if (key_is_data) {
                    target = helper_pacda(env, target, modifier);
                } else {
                    target = helper_pacia(env, target, modifier);
                }
            } else {
                /* Non-auth rebase: add high8 bits */
                uint64_t high8 = (raw << 22) & 0xFF00000000000000ULL;
                target |= high8;
            }

            memcpy(loc, &target, 8);
            if (delta == 0) {
                break;
            }

            uint64_t remaining =
                (uint64_t)(page_end - (loc + sizeof(uint64_t)));
            if (delta > remaining) {
                if (do_strace) {
                    fprintf(stderr, "qemu: slide chain page=%u escaped page "
                            "at offset=0x%llx delta=0x%llx\n",
                            pi, (unsigned long long)(loc - page_base),
                            (unsigned long long)delta);
                }
                break;
            }
            loc += delta;
        }
    }
}

/* Syscall implementation */

/* Guest address of the mapped shared cache (0 = not yet mapped) */
static uint64_t guest_shared_cache_addr;

#define TARGET_ULF_NO_ERRNO 0x01000000u
#define WORKLOOP_BLOCKING_POLL_SLICE_MS 50

static void service_blocking_workloop_events(void)
{
    service_workloop_machport_events();
    service_pending_workloop_reqs();
    service_workq_notification_events();
}

static bool ulock_syscall_error(long host_ret, uint32_t op, int *host_errno)
{
    if (op & TARGET_ULF_NO_ERRNO) {
        if (host_ret < 0) {
            *host_errno = (int)-host_ret;
            return true;
        }
        return false;
    }

    if (host_ret == -1) {
        *host_errno = errno;
        return true;
    }
    return false;
}

static bool macos_signal_pending(CPUARMState *env)
{
    TaskState *ts = get_task_state(env_cpu(env));

    return qatomic_read(&ts->signal_pending) != 0;
}

static bool consume_workloop_sync_wake_for_ulock(uint64_t wl_id,
                                                 abi_ulong wait_addr,
                                                 uint64_t value,
                                                 const char *where)
{
    if (!consume_workloop_sync_wake(wl_id)) {
        return false;
    }

    if (guest_range_valid_untagged(wait_addr, sizeof(uint32_t))) {
        *(uint32_t *)g2h_untagged(wait_addr) = 0;
    }
    if (do_strace) {
        fprintf(stderr, "  ulock_wait: consuming workloop sync wake%s%s "
                "wl=0x%llx addr=0x%llx value=0x%llx\n",
                where && where[0] ? " " : "",
                where && where[0] ? where : "",
                (unsigned long long)wl_id,
                (unsigned long long)wait_addr,
                (unsigned long long)value);
    }
    return true;
}

static long interrupted_ulock_ret(uint32_t op)
{
    if (op & TARGET_ULF_NO_ERRNO) {
        return -(long)EINTR;
    }
    errno = EINTR;
    return -1;
}

static abi_long finish_ulock_syscall(CPUARMState *env, long host_ret,
                                     uint32_t op)
{
    if ((op & TARGET_ULF_NO_ERRNO) && host_ret < 0) {
        env->CF = 0;
        env->xregs[0] = (uint64_t)(int64_t)host_ret;
        return -TARGET_EJUSTRETURN;
    }

    if (host_ret == -1) {
        int host_errno = errno;

        if (op & TARGET_ULF_NO_ERRNO) {
            env->CF = 0;
            env->xregs[0] = (uint64_t)(int64_t)-host_errno;
            return -TARGET_EJUSTRETURN;
        }
        return -host_errno;
    }

    return host_ret;
}

abi_long do_macos_syscall(void *cpu_env, int num, abi_long arg1,
                          abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7,
                          abi_long arg8)
{
    CPUState *cpu = env_cpu(cpu_env);
    CPUARMState *env = cpu_env;
    abi_long ret;

    if (do_strace) {
        print_syscall(cpu, num, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    switch (num) {
    case TARGET_MACOS_NR_exit:
        /* exit(int status) */
        gdb_exit(arg1);
        _exit(arg1);
        ret = 0; /* not reached */
        break;

    case TARGET_MACOS_NR_read:
        /* read(int fd, void *buf, size_t count) */
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_read(arg1, p, arg3));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_write:
        /* write(int fd, const void *buf, size_t count) */
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_write(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_open:
        /* open(const char *path, int flags, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                ret = get_errno(safe_open(rp, target_to_host_bitmask(arg2, fcntl_flags_tbl),
                                          arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_close:
        /* close(int fd) */
        ret = get_errno(close(arg1));
        break;

    case TARGET_MACOS_NR_getpid:
        ret = get_errno(getpid());
        break;

    case TARGET_MACOS_NR_getuid:
        ret = get_errno(getuid());
        break;

    case TARGET_MACOS_NR_geteuid:
        ret = get_errno(geteuid());
        break;

    case TARGET_MACOS_NR_getgid:
        ret = get_errno(getgid());
        break;

    case TARGET_MACOS_NR_getegid:
        ret = get_errno(getegid());
        break;

    case TARGET_MACOS_NR_getppid:
        ret = get_errno(getppid());
        break;

    case TARGET_MACOS_NR_dup:
        /* dup(int fd) */
        ret = get_errno(dup(arg1));
        break;

    case TARGET_MACOS_NR_dup2:
        /* dup2(int oldfd, int newfd) */
        ret = get_errno(dup2(arg1, arg2));
        break;

    case TARGET_MACOS_NR_fcntl:
        /* fcntl(int fd, int cmd, ...) */
        ret = do_bsd_fcntl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_ioctl:
        /* ioctl(int fd, unsigned long request, ...) */
        ret = do_bsd_ioctl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_lseek:
        /* lseek(int fd, off_t offset, int whence) */
        ret = get_errno(lseek(arg1, arg2, arg3));
        break;

    case TARGET_MACOS_NR_mmap:
        /* mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset) */
        ret = target_mmap(arg1, arg2, arg3,
                         target_to_host_bitmask(arg4, mmap_flags_tbl),
                         arg5, arg6);
        break;

    case TARGET_MACOS_NR_munmap:
        /* munmap(void *addr, size_t len) */
        ret = target_munmap(arg1, arg2);
        break;

    case TARGET_MACOS_NR_mprotect:
        /* mprotect(void *addr, size_t len, int prot) */
        ret = target_mprotect(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_msync:
        /* msync(void *addr, size_t len, int flags) */
        ret = target_msync(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_access:
        /* access(const char *path, int mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(access(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_chdir:
        /* chdir(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chdir(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchdir:
        /* fchdir(int fd) */
        ret = get_errno(fchdir(arg1));
        break;

    case TARGET_MACOS_NR_chmod:
        /* chmod(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chmod(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchmod:
        /* fchmod(int fd, mode_t mode) */
        ret = get_errno(fchmod(arg1, arg2));
        break;

    case TARGET_MACOS_NR_chown:
        /* chown(const char *path, uid_t owner, gid_t group) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chown(p, arg2, arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchown:
        /* fchown(int fd, uid_t owner, gid_t group) */
        ret = get_errno(fchown(arg1, arg2, arg3));
        break;

    case TARGET_MACOS_NR_gettimeofday:
        /*
         * gettimeofday(struct timeval *tv, struct timezone *tz,
         *              uint64_t *mach_absolute_time)
         * macOS extends POSIX gettimeofday with a third argument.
         * When non-NULL, the kernel writes mach_absolute_time() there.
         * libdispatch uses this to arm timers.
         */
        {
            struct timeval tv;
            ret = get_errno(gettimeofday(&tv, NULL));
            if (!is_error(ret)) {
                if (arg1 && copy_to_user_timeval(arg1, &tv)) {
                    ret = -TARGET_EFAULT;
                }
                if (arg3) {
                    uint64_t mat = mach_absolute_time();
                    *(uint64_t *)g2h_untagged(arg3) = mat;
                }
            }
        }
        break;

    case TARGET_MACOS_NR_readlink:
        /* readlink(const char *path, char *buf, size_t bufsiz) */
        {
            void *p = lock_user_string(arg1);
            void *p2 = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(readlink(p, p2, arg3));
            }
            unlock_user(p2, arg2, ret);
            unlock_user(p, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_symlink:
        /* symlink(const char *target, const char *linkpath) */
        {
            void *p = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(symlink(p, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_unlink:
        /* unlink(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(unlink(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_mkdir:
        /* mkdir(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkdir(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_rmdir:
        /* rmdir(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(rmdir(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_stat:
    case TARGET_MACOS_NR_stat64:
        /* stat(const char *path, struct stat *buf) */
        {
            struct stat st;
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                ret = get_errno(stat(rp, &st));
                unlock_user(p, arg1, 0);
                if (!is_error(ret)) {
                    if (arg2 && host_to_target_stat(arg2, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_fstat:
    case TARGET_MACOS_NR_fstat64:
        /* fstat(int fd, struct stat *buf) */
        {
            struct stat st;
            ret = get_errno(fstat(arg1, &st));
            if (!is_error(ret)) {
                if (arg2 && host_to_target_stat(arg2, &st)) {
                    ret = -TARGET_EFAULT;
                }
            }
        }
        break;

    case TARGET_MACOS_NR_lstat:
    case TARGET_MACOS_NR_lstat64:
        /* lstat(const char *path, struct stat *buf) */
        {
            struct stat st;
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(lstat(p, &st));
                unlock_user(p, arg1, 0);
                if (!is_error(ret)) {
                    if (arg2 && host_to_target_stat(arg2, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_link:
        /* link(const char *path, const char *link) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(link(p1, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_pipe:
        /* pipe() -> returns fd[0] in X0, fd[1] in X1 */
        {
            int pipefd[2];
            ret = get_errno(pipe(pipefd));
            if (!is_error(ret)) {
                CPUARMState *arm_env = (CPUARMState *)cpu_env;
                arm_env->xregs[0] = pipefd[0];
                arm_env->xregs[1] = pipefd[1];
                ret = 0;
            }
        }
        break;

    case TARGET_MACOS_NR_umask:
        /* umask(int newmask) */
        ret = get_errno(umask(arg1));
        break;

    case TARGET_MACOS_NR_rename:
        /* rename(const char *from, const char *to) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg2);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(rename(p1, p2));
            }
            unlock_user(p2, arg2, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_flock:
        /* flock(int fd, int how) */
        ret = get_errno(flock(arg1, arg2));
        break;

    case TARGET_MACOS_NR_fsync:
        /* fsync(int fd) */
        ret = get_errno(fsync(arg1));
        break;

    case TARGET_MACOS_NR_fdatasync:
        /* fdatasync(int fd) */
        ret = get_errno(fdatasync(arg1));
        break;

    case TARGET_MACOS_NR_readv:
    case TARGET_MACOS_NR_readv_nocancel:
        /* readv(int fd, struct iovec *iovp, int iovcnt) */
        {
            struct iovec *vec;
            int count = arg3;
            if (count <= 0 || count > 1024) {
                ret = -TARGET_EINVAL;
                break;
            }
            vec = g_new(struct iovec, count);
            /* Direct mapping: guest iovec same as host iovec */
            void *p = lock_user(VERIFY_READ, arg2,
                                count * sizeof(struct iovec), 1);
            if (!p) {
                g_free(vec);
                ret = -TARGET_EFAULT;
                break;
            }
            memcpy(vec, p, count * sizeof(struct iovec));
            unlock_user(p, arg2, 0);
            ret = get_errno(readv(arg1, vec, count));
            g_free(vec);
        }
        break;

    case TARGET_MACOS_NR_writev:
    case TARGET_MACOS_NR_writev_nocancel:
        /* writev(int fd, struct iovec *iovp, int iovcnt) */
        {
            struct iovec *vec;
            int count = arg3;
            if (count <= 0 || count > 1024) {
                ret = -TARGET_EINVAL;
                break;
            }
            vec = g_new(struct iovec, count);
            void *p = lock_user(VERIFY_READ, arg2,
                                count * sizeof(struct iovec), 1);
            if (!p) {
                g_free(vec);
                ret = -TARGET_EFAULT;
                break;
            }
            memcpy(vec, p, count * sizeof(struct iovec));
            unlock_user(p, arg2, 0);
            ret = get_errno(writev(arg1, vec, count));
            g_free(vec);
        }
        break;

    case TARGET_MACOS_NR_pread:
    case TARGET_MACOS_NR_pread_nocancel:
        /* pread(int fd, void *buf, size_t nbyte, off_t offset) */
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pread(arg1, p, arg3, arg4));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_pwrite:
    case TARGET_MACOS_NR_pwrite_nocancel:
        /* pwrite(int fd, const void *buf, size_t nbyte, off_t offset) */
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pwrite(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_truncate:
        /* truncate(const char *path, off_t length) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(truncate(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_ftruncate:
        /* ftruncate(int fd, off_t length) */
        ret = get_errno(ftruncate(arg1, arg2));
        break;

    case TARGET_MACOS_NR_getdtablesize:
        /* getdtablesize() */
        ret = get_errno(getdtablesize());
        break;

    case TARGET_MACOS_NR_getpgrp:
        ret = get_errno(getpgrp());
        break;

    case TARGET_MACOS_NR_setpgid:
        /* setpgid(pid_t pid, pid_t pgid) */
        ret = get_errno(setpgid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_setsid:
        ret = get_errno(setsid());
        break;

    case TARGET_MACOS_NR_getpgid:
        /* getpgid(pid_t pid) */
        ret = get_errno(getpgid(arg1));
        break;

    case TARGET_MACOS_NR_getsid:
        /* getsid(pid_t pid) */
        ret = get_errno(getsid(arg1));
        break;

    case TARGET_MACOS_NR_setuid:
        ret = get_errno(setuid(arg1));
        break;

    case TARGET_MACOS_NR_setgid:
        ret = get_errno(setgid(arg1));
        break;

    case TARGET_MACOS_NR_seteuid:
        ret = get_errno(seteuid(arg1));
        break;

    case TARGET_MACOS_NR_setegid:
        ret = get_errno(setegid(arg1));
        break;

    case TARGET_MACOS_NR_setreuid:
        ret = get_errno(setreuid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_setregid:
        ret = get_errno(setregid(arg1, arg2));
        break;

    case TARGET_MACOS_NR_getgroups:
        /* getgroups(int gidsetsize, gid_t *grouplist) */
        {
            gid_t *grouplist = NULL;
            if (arg1 > 0) {
                grouplist = lock_user(VERIFY_WRITE, arg2,
                                      arg1 * sizeof(gid_t), 0);
                if (!grouplist) {
                    ret = -TARGET_EFAULT;
                    break;
                }
            }
            ret = get_errno(getgroups(arg1, grouplist));
            if (grouplist) {
                unlock_user(grouplist, arg2, ret * sizeof(gid_t));
            }
        }
        break;

    case TARGET_MACOS_NR_setgroups:
        /* setgroups(int ngroups, const gid_t *gidset) */
        {
            gid_t *gidset = lock_user(VERIFY_READ, arg2,
                                       arg1 * sizeof(gid_t), 1);
            if (!gidset) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(setgroups(arg1, gidset));
                unlock_user(gidset, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getrlimit:
        /* getrlimit(int resource, struct rlimit *rlp) */
        {
            struct rlimit rlim;
            ret = get_errno(getrlimit(arg1, &rlim));
            if (!is_error(ret) && arg2) {
                struct rlimit *p = lock_user(VERIFY_WRITE, arg2,
                                             sizeof(struct rlimit), 0);
                if (!p) {
                    ret = -TARGET_EFAULT;
                } else {
                    *p = rlim;
                    unlock_user(p, arg2, sizeof(struct rlimit));
                }
            }
        }
        break;

    case TARGET_MACOS_NR_setrlimit:
        /* setrlimit(int resource, const struct rlimit *rlp) */
        {
            struct rlimit *p = lock_user(VERIFY_READ, arg2,
                                          sizeof(struct rlimit), 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(setrlimit(arg1, p));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_madvise:
        /* madvise(void *addr, size_t len, int advice) */
        ret = get_errno(madvise(g2h_untagged(arg1), arg2, arg3));
        break;

    case TARGET_MACOS_NR_mlock:
        /* mlock(const void *addr, size_t len) */
        ret = get_errno(mlock(g2h_untagged(arg1), arg2));
        break;

    case TARGET_MACOS_NR_munlock:
        /* munlock(const void *addr, size_t len) */
        ret = get_errno(munlock(g2h_untagged(arg1), arg2));
        break;

    case TARGET_MACOS_NR_pathconf:
        /* pathconf(const char *path, int name) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(pathconf(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fpathconf:
        /* fpathconf(int fd, int name) */
        ret = get_errno(fpathconf(arg1, arg2));
        break;

    case TARGET_MACOS_NR_sync:
        sync();
        ret = 0;
        break;

    case TARGET_MACOS_NR_lchown:
        /* lchown(const char *path, uid_t owner, gid_t group) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(lchown(p, arg2, arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_chroot:
        /* chroot(const char *path) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(chroot(p));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_mkfifo:
        /* mkfifo(const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkfifo(p, arg2));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getrusage:
        /* getrusage(int who, struct rusage *usage) */
        {
            struct rusage ru;
            ret = get_errno(getrusage(arg1, &ru));
            if (!is_error(ret) && arg2) {
                struct rusage *p = lock_user(VERIFY_WRITE, arg2,
                                              sizeof(struct rusage), 0);
                if (!p) {
                    ret = -TARGET_EFAULT;
                } else {
                    *p = ru;
                    unlock_user(p, arg2, sizeof(struct rusage));
                }
            }
        }
        break;

    case TARGET_MACOS_NR_getentropy:
        /* getentropy(void *buf, size_t buflen) */
        {
            void *p = lock_user(VERIFY_WRITE, arg1, arg2, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(getentropy(p, arg2));
                unlock_user(p, arg1, arg2);
            }
        }
        break;

    case TARGET_MACOS_NR_thread_selfid:
        /* thread_selfid() - return current thread ID */
        {
            uint64_t tid;
            pthread_threadid_np(NULL, &tid);
            ret = tid;
        }
        break;

    case TARGET_MACOS_NR_gettid:
        /* gettid(uint64_t *thread_id, int who) — get thread ID */
        {
            uint64_t tid;
            pthread_threadid_np(NULL, &tid);
            if (arg1) {
                *(uint64_t *)g2h_untagged(arg1) = tid;
            }
            ret = 0;
        }
        break;

    case TARGET_MACOS_NR_issetugid:
        /* issetugid() - always return 0 for now */
        ret = 0;
        break;

    /* _nocancel variants: delegate to their base syscalls */
    case TARGET_MACOS_NR_read_nocancel:
        {
            void *p = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_read(arg1, p, arg3));
                unlock_user(p, arg2, ret);
            }
        }
        break;

    case TARGET_MACOS_NR_write_nocancel:
        {
            void *p = lock_user(VERIFY_READ, arg2, arg3, 1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_write(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_open_nocancel:
        {
            void *p = lock_user_string(arg1);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(safe_open(p, target_to_host_bitmask(arg2,
                                fcntl_flags_tbl), arg3));
                unlock_user(p, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_close_nocancel:
        ret = get_errno(close(arg1));
        break;

    case TARGET_MACOS_NR_fcntl_nocancel:
        ret = do_bsd_fcntl(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_fsync_nocancel:
        ret = get_errno(fsync(arg1));
        break;

    /* *at syscalls */
    case TARGET_MACOS_NR_openat:
    case TARGET_MACOS_NR_openat_nocancel:
        /* openat(int fd, const char *path, int oflag, mode_t mode) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                if (rp != p) {
                    /* Redirected to absolute path — use AT_FDCWD */
                    ret = get_errno(openat(AT_FDCWD, rp,
                                    target_to_host_bitmask(arg3,
                                        fcntl_flags_tbl), arg4));
                } else {
                    ret = get_errno(openat(arg1, p,
                                    target_to_host_bitmask(arg3,
                                        fcntl_flags_tbl), arg4));
                }
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_faccessat:
        /* faccessat(int fd, const char *path, int mode, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(faccessat(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchmodat:
        /* fchmodat(int fd, const char *path, mode_t mode, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(fchmodat(arg1, p, arg3, arg4));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fchownat:
        /* fchownat(int fd, const char *path, uid_t uid, gid_t gid, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(fchownat(arg1, p, arg3, arg4, arg5));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fstatat:
    case TARGET_MACOS_NR_fstatat64:
        /* fstatat(int fd, const char *path, struct stat *buf, int flag) */
        {
            struct stat st;
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                char rdbuf[PATH_MAX];
                const char *rp = redirect_path(p, rdbuf, sizeof(rdbuf));
                if (rp != p) {
                    ret = get_errno(fstatat(AT_FDCWD, rp, &st, arg4));
                } else {
                    ret = get_errno(fstatat(arg1, p, &st, arg4));
                }
                unlock_user(p, arg2, 0);
                if (!is_error(ret)) {
                    if (arg3 && host_to_target_stat(arg3, &st)) {
                        ret = -TARGET_EFAULT;
                    }
                }
            }
        }
        break;

    case TARGET_MACOS_NR_unlinkat:
        /* unlinkat(int fd, const char *path, int flag) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(unlinkat(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_readlinkat:
        /* readlinkat(int fd, const char *path, char *buf, size_t bufsiz) */
        {
            void *p = lock_user_string(arg2);
            void *p2 = lock_user(VERIFY_WRITE, arg3, arg4, 0);
            if (!p || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(readlinkat(arg1, p, p2, arg4));
            }
            unlock_user(p2, arg3, ret);
            unlock_user(p, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_symlinkat:
        /* symlinkat(const char *target, int fd, const char *linkpath) */
        {
            void *p1 = lock_user_string(arg1);
            void *p2 = lock_user_string(arg3);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(symlinkat(p1, arg2, p2));
            }
            unlock_user(p2, arg3, 0);
            unlock_user(p1, arg1, 0);
        }
        break;

    case TARGET_MACOS_NR_mkdirat:
        /* mkdirat(int fd, const char *path, mode_t mode) */
        {
            void *p = lock_user_string(arg2);
            if (!p) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(mkdirat(arg1, p, arg3));
                unlock_user(p, arg2, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_renameat:
        /* renameat(int fromfd, const char *from, int tofd, const char *to) */
        {
            void *p1 = lock_user_string(arg2);
            void *p2 = lock_user_string(arg4);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(renameat(arg1, p1, arg3, p2));
            }
            unlock_user(p2, arg4, 0);
            unlock_user(p1, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_linkat:
        /* linkat(int fd1, const char *name1, int fd2, const char *name2, int flag) */
        {
            void *p1 = lock_user_string(arg2);
            void *p2 = lock_user_string(arg4);
            if (!p1 || !p2) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(linkat(arg1, p1, arg3, p2, arg5));
            }
            unlock_user(p2, arg4, 0);
            unlock_user(p1, arg2, 0);
        }
        break;

    case TARGET_MACOS_NR_sigaction:
        ret = do_sigaction(arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_sigprocmask:
        /* sigprocmask(int how, const sigset_t *set, sigset_t *oldset) */
        ret = do_bsd_sigprocmask(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR_sigaltstack:
        ret = do_sigaltstack(arg1, arg2,
                             ((CPUARMState *)cpu_env)->xregs[31]);
        break;

    case TARGET_MACOS_NR_sigreturn:
        ret = do_sigreturn(cpu_env, arg1);
        break;

    case TARGET_MACOS_NR_setitimer:
    case TARGET_MACOS_NR_getitimer:
    {
        /*
         * setitimer(int which, const struct itimerval *value,
         *           struct itimerval *ovalue)
         * getitimer(int which, struct itimerval *value)
         *
         * Forward to host.  struct itimerval is the same layout on
         * arm64 guest and host (two struct timeval = 2×16 bytes).
         */
        struct itimerval *v = arg2 ? (struct itimerval *)g2h_untagged(arg2)
                                   : NULL;
        struct itimerval *ov = arg3 ? (struct itimerval *)g2h_untagged(arg3)
                                    : NULL;
        if (num == TARGET_MACOS_NR_setitimer) {
            ret = get_errno(setitimer((int)arg1, v, ov));
        } else {
            ret = get_errno(getitimer((int)arg1, v));
        }
        break;
    }

    case TARGET_MACOS_NR_kill:
        /* kill(pid_t pid, int sig) */
        if ((pid_t)arg1 == getpid() && arg2 != 0) {
            /* Self-signal: queue directly for guest delivery */
            int guest_sig = target_to_host_signal(arg2);
            if (guest_sig >= 1 && guest_sig <= TARGET_NSIG) {
                target_siginfo_t info = {};
                info.si_signo = guest_sig;
                info.si_code = SI_USER;
                info.si_pid = getpid();
                info.si_uid = getuid();
                queue_signal(cpu_env, guest_sig, QEMU_SI_KILL, &info);
                ret = 0;
            } else {
                ret = -TARGET_EINVAL;
            }
        } else {
            ret = get_errno(kill(arg1, target_to_host_signal(arg2)));
        }
        break;

    case TARGET_MACOS_NR___pthread_kill:
        /*
         * __pthread_kill(pthread_t thread, int sig)
         * We're single-threaded — the only thread is self.  Queue the
         * signal directly for guest delivery instead of using host kill(),
         * which may fail if the host signal mask blocks it.
         */
        if (arg2 == 0) {
            ret = 0;
        } else {
            int guest_sig = arg2;
            if (guest_sig >= 1 && guest_sig <= TARGET_NSIG) {
                target_siginfo_t info = {};
                info.si_signo = guest_sig;
                info.si_code = SI_USER;
                info.si_pid = getpid();
                info.si_uid = getuid();
                queue_signal(cpu_env, guest_sig, QEMU_SI_KILL, &info);
                ret = 0;
            } else {
                ret = -TARGET_EINVAL;
            }
        }
        break;

    case TARGET_MACOS_NR___pthread_sigmask:
        /*
         * __pthread_sigmask(int how, const sigset_t *set, sigset_t *oset)
         * Same semantics as sigprocmask for a single-threaded process.
         */
        ret = do_bsd_sigprocmask(cpu_env, arg1, arg2, arg3);
        break;

    case TARGET_MACOS_NR___semwait_signal:
    case TARGET_MACOS_NR___semwait_signal_nocancel:
        /*
         * __semwait_signal(int cond_sem, int mutex_sem, int timeout,
         *                  int relative, int64_t tv_sec, int32_t tv_nsec)
         *
         * Used by pthread_cond_wait/timed-wait and dispatch internals.
         * Mach semaphore ports are real host ports (created via real
         * semaphore_create trap), so forward directly to the host kernel.
         *
         * If the port is invalid (e.g. psynch handle), fall back to
         * a timed sleep so the caller retries gracefully.
         */
        {
            /*
             * Service any pending workloop thread requests.
             * This is where deferred kevent_id THREAD_REQUEST handling
             * kicks in — the caller is blocked waiting for serial queue
             * work to complete.
             */
            service_workloop_machport_events();
            service_pending_workloop_reqs();
            service_workq_notification_events();

            int sysno = (num == TARGET_MACOS_NR___semwait_signal)
                ? SYS___semwait_signal
                : SYS___semwait_signal_nocancel;
            int rv = syscall(sysno,
                             (int)arg1,       /* cond_sem */
                             (int)arg2,       /* mutex_sem */
                             (int)arg3,       /* timeout */
                             (int)arg4,       /* relative */
                             (int64_t)arg5,   /* tv_sec */
                             (int32_t)arg6);  /* tv_nsec */
            if (rv == 0) {
                ret = 0;
            } else if (errno == ETIMEDOUT) {
                ret = -TARGET_ETIMEDOUT;
            } else if (errno == EINTR) {
                ret = -TARGET_EINTR;
            } else {
                /*
                 * Real syscall failed (EINVAL = invalid semaphore).
                 * Fall back to a timed sleep so the caller retries.
                 */
                int has_timeout = (int)arg3;
                int64_t tv_sec = (int64_t)arg5;
                int32_t tv_nsec = (int32_t)arg6;
                if (has_timeout && (tv_sec > 0 || tv_nsec > 0)) {
                    struct timespec ts;
                    ts.tv_sec = tv_sec;
                    ts.tv_nsec = tv_nsec;
                    nanosleep(&ts, NULL);
                    ret = -TARGET_ETIMEDOUT;
                } else {
                    struct timespec ts = { .tv_sec = 0,
                                           .tv_nsec = 1000000 };
                    nanosleep(&ts, NULL);
                    ret = -TARGET_EINTR;
                }
            }
        }
        break;

    case TARGET_MACOS_NR_psynch_rw_longrdlock:
        ret = get_errno(syscall(SYS_psynch_rw_longrdlock,
                                g2h_untagged(arg1), (uint32_t)arg2,
                                (uint32_t)arg3, (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_yieldwrlock:
        ret = get_errno(syscall(SYS_psynch_rw_yieldwrlock,
                                g2h_untagged(arg1), (uint32_t)arg2,
                                (uint32_t)arg3, (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_downgrade:
        ret = get_errno(syscall(SYS_psynch_rw_downgrade,
                                g2h_untagged(arg1), (uint32_t)arg2,
                                (uint32_t)arg3, (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_upgrade:
        ret = get_errno(syscall(SYS_psynch_rw_upgrade,
                                g2h_untagged(arg1), (uint32_t)arg2,
                                (uint32_t)arg3, (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_mutexwait:
        ret = get_errno(syscall(SYS_psynch_mutexwait, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint64_t)arg4, (uint32_t)arg5));
        break;

    case TARGET_MACOS_NR_psynch_mutexdrop:
        ret = get_errno(syscall(SYS_psynch_mutexdrop, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint64_t)arg4, (uint32_t)arg5));
        break;

    case TARGET_MACOS_NR_psynch_cvbroad:
        ret = get_errno(syscall(SYS_psynch_cvbroad, g2h_untagged(arg1),
                                (uint64_t)arg2, (uint64_t)arg3,
                                (uint32_t)arg4, g2h_untagged(arg5),
                                (uint64_t)arg6, (uint64_t)arg7));
        break;

    case TARGET_MACOS_NR_psynch_cvsignal:
        ret = get_errno(syscall(SYS_psynch_cvsignal, g2h_untagged(arg1),
                                (uint64_t)arg2, (uint32_t)arg3, (int)arg4,
                                g2h_untagged(arg5), (uint64_t)arg6,
                                (uint64_t)arg7, (uint32_t)arg8));
        break;

    case TARGET_MACOS_NR_psynch_cvwait:
        ret = get_errno(syscall(SYS_psynch_cvwait, g2h_untagged(arg1),
                                (uint64_t)arg2, (uint32_t)arg3,
                                g2h_untagged(arg4), (uint64_t)arg5,
                                (uint32_t)arg6, (int64_t)arg7,
                                (uint32_t)arg8));
        break;

    case TARGET_MACOS_NR_psynch_rw_rdlock:
        ret = get_errno(syscall(SYS_psynch_rw_rdlock, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_wrlock:
        ret = get_errno(syscall(SYS_psynch_rw_wrlock, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_unlock:
        ret = get_errno(syscall(SYS_psynch_rw_unlock, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_rw_unlock2:
        ret = get_errno(syscall(SYS_psynch_rw_unlock2, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint32_t)arg4, (int)arg5));
        break;

    case TARGET_MACOS_NR_psynch_cvclrprepost:
        ret = get_errno(syscall(SYS_psynch_cvclrprepost, g2h_untagged(arg1),
                                (uint32_t)arg2, (uint32_t)arg3,
                                (uint32_t)arg4, (uint32_t)arg5,
                                (uint32_t)arg6, (uint32_t)arg7));
        break;

    /*
     * ulock_wait / ulock_wake / ulock_wait2
     *
     * These implement os_unfair_lock and other user-space locking
     * primitives.  The addr argument is a guest pointer to the lock
     * word; we translate to a host address and forward to the real
     * kernel so the futex-like wait/wake mechanism works correctly.
     */
    case TARGET_MACOS_NR_ulock_wait:
        /*
         * __ulock_wait(uint32_t op, void *addr, uint64_t value,
         *              uint32_t timeout_us)
         *
         * libdispatch waits for queue/thread-event handoffs here.  Mirror the
         * semwait path by periodically servicing emulated workloop events while
         * a guest thread is blocked in an indefinite host ulock wait.
         */
        {
            uint32_t op = (uint32_t)arg1;
            void *addr = g2h_untagged(arg2);
            uint64_t value = (uint64_t)arg3;
            uint32_t remaining_us = (uint32_t)arg4;
            bool indefinite = remaining_us == 0;
            long rv;
            int host_errno = 0;

            do {
                uint32_t slice_us = indefinite
                    ? WORKLOOP_BLOCKING_POLL_SLICE_MS * 1000
                    : MIN(remaining_us,
                          WORKLOOP_BLOCKING_POLL_SLICE_MS * 1000);
                uint64_t wait_workloop = (uint64_t)arg5;

                if (indefinite && wait_workloop &&
                    consume_workloop_sync_wake_for_ulock(wait_workloop,
                                                         (abi_ulong)arg2,
                                                         value, "")) {
                    rv = 0;
                    break;
                }

                service_blocking_workloop_events();
                if (indefinite && wait_workloop &&
                    consume_workloop_sync_wake_for_ulock(wait_workloop,
                                                         (abi_ulong)arg2,
                                                         value,
                                                         "after service")) {
                    rv = 0;
                    break;
                }
                rv = syscall(SYS_ulock_wait, op, addr, value, slice_us);
                if (!ulock_syscall_error(rv, op, &host_errno) ||
                    host_errno != ETIMEDOUT) {
                    break;
                }
                service_blocking_workloop_events();
                if (indefinite && wait_workloop &&
                    consume_workloop_sync_wake_for_ulock(wait_workloop,
                                                         (abi_ulong)arg2,
                                                         value,
                                                         "after timeout")) {
                    rv = 0;
                    break;
                }
                if (macos_signal_pending(env)) {
                    rv = interrupted_ulock_ret(op);
                    break;
                }
                if (!indefinite) {
                    if (remaining_us <= slice_us) {
                        break;
                    }
                    remaining_us -= slice_us;
                }
            } while (indefinite || remaining_us > 0);

            ret = finish_ulock_syscall(env, rv, op);
        }
        break;

    case TARGET_MACOS_NR_ulock_wake:
        /* __ulock_wake(uint32_t op, void *addr, uint64_t wake_value) */
        ret = finish_ulock_syscall(env,
                                   syscall(SYS_ulock_wake,
                                           (uint32_t)arg1,
                                           g2h_untagged(arg2),
                                           (uint64_t)arg3),
                                   (uint32_t)arg1);
        break;

    case TARGET_MACOS_NR_ulock_wait2:
        /* __ulock_wait2(uint32_t op, void *addr, uint64_t value,
         *               uint64_t timeout_ns, uint64_t value2) */
        {
            uint32_t op = (uint32_t)arg1;
            void *addr = g2h_untagged(arg2);
            uint64_t value = (uint64_t)arg3;
            uint64_t remaining_ns = (uint64_t)arg4;
            uint64_t value2 = (uint64_t)arg5;
            bool indefinite = remaining_ns == 0;
            uint64_t slice_ns = (uint64_t)WORKLOOP_BLOCKING_POLL_SLICE_MS *
                                1000000ULL;
            long rv;
            int host_errno = 0;

            do {
                uint64_t this_ns = indefinite ? slice_ns
                    : MIN(remaining_ns, slice_ns);

                service_blocking_workloop_events();
                rv = syscall(SYS_ulock_wait2, op, addr, value, this_ns,
                             value2);
                if (!ulock_syscall_error(rv, op, &host_errno) ||
                    host_errno != ETIMEDOUT) {
                    break;
                }
                service_blocking_workloop_events();
                if (macos_signal_pending(env)) {
                    rv = interrupted_ulock_ret(op);
                    break;
                }
                if (!indefinite) {
                    if (remaining_ns <= this_ns) {
                        break;
                    }
                    remaining_ns -= this_ns;
                }
            } while (indefinite || remaining_ns > 0);

            ret = finish_ulock_syscall(env, rv, op);
        }
        break;

    case TARGET_MACOS_NR_bsdthread_ctl:
        /*
         * bsdthread_ctl(uint32_t cmd, uint64_t arg1, ...)
         * Thread control for QoS, scheduling, etc.
         */
        ret = 0;
        break;

    case TARGET_MACOS_NR_bsdthread_create:
        /*
         * bsdthread_create(void *func, void *func_arg,
         *                  void *stack, pthread_t thread, uint32_t flags)
         *
         * Creates a new BSD thread.  This is what pthread_create calls
         * underneath.  The kernel creates a thread that enters at the
         * threadstart callback (registered via bsdthread_register).
         *
         * threadstart(pthread_t self, mach_port_t kport,
         *             void *(*start)(void *), void *arg,
         *             size_t stacksize, unsigned int flags)
         */
        {
            if (!saved_threadstart) {
                ret = -TARGET_ENOTSUP;
                break;
            }

            abi_ulong sp = arg3;
            abi_ulong stack_bottom = 0;
            abi_ulong pthread_self = arg4;

            if (!sp) {
                /* Older libpthread paths can ask the kernel to supply one. */
                abi_ulong stack_top = alloc_thread_stack(WQ_STACK_SIZE);
                if (!stack_top) {
                    ret = -TARGET_ENOMEM;
                    break;
                }
                stack_bottom = stack_top - WQ_STACK_SIZE;
                sp = stack_top;
            }
            sp &= ~0xFULL;
            if (!pthread_self) {
                pthread_self = stack_bottom;
            }
            abi_ulong tsd_base = pthread_self;
            if (saved_tsd_offset) {
                tsd_base += saved_tsd_offset;
            }

            TaskState *parent_ts = get_task_state(
                env_cpu((CPUArchState *)cpu_env));

            /*
             * threadstart calling convention:
             *   x0 = pthread_self (use the thread pointer arg4)
             *   x1 = mach_thread_self port
             *   x2 = start function (arg1)
             *   x3 = start arg (arg2)
             *   x4 = stacksize
             *   x5 = flags, including the kernel-set TSD_BASE_SET bit
             */
            int rc = create_guest_thread(
                (CPUArchState *)cpu_env,
                saved_threadstart,  /* PC = threadstart callback */
                sp,
                pthread_self,               /* x0 = pthread_self */
                0,                          /* x1 = kport (set by worker) */
                arg1,                       /* x2 = start func */
                arg2,                       /* x3 = start arg */
                WQ_STACK_SIZE,              /* x4 = stacksize */
                arg5 | PTHREAD_START_TSD_BASE_SET, /* x5 = flags */
                tsd_base,
                parent_ts,
                false, 0, 0, 0, 0, 0);     /* not a wq thread */

            if (rc < 0) {
                ret = rc;
            } else {
                /* Return the thread pointer to caller */
                ret = 0;
            }
        }
        break;

    case TARGET_MACOS_NR_bsdthread_terminate:
        /*
         * bsdthread_terminate(void *stackaddr, size_t freesize,
         *                     mach_port_t kport, mach_port_t joinsem)
         *
         * Thread termination.  Free the stack and exit the thread.
         * For the main thread, this would exit the process.
         */
        {
            /* Free the thread's stack if provided */
            if (arg1 && arg2) {
                mmap_lock();
                target_munmap(arg1, arg2);
                mmap_unlock();
            }
            /* Exit this thread (not the whole process) */
            thread_cpu = NULL;
            rcu_unregister_thread();
            pthread_exit(NULL);
        }
        break;

    case TARGET_MACOS_NR_bsdthread_register:
        /*
         * __bsdthread_register(threadstart, wqthread, pthsize,
         *                      data, data_size, dispatch_queue_offset)
         *
         * Registers pthread callbacks with the kernel.  We save the
         * callback pointers for use when creating workqueue threads.
         *
         * We must:
         *   1. Return the feature-flag bitmap (rv > 0).
         *   2. Fill in the "copy-out" fields of the registration struct.
         *
         * Feature bits (from kern_internal.h):
         *   0x01  PTHREAD_FEATURE_DISPATCHFUNC
         *   0x02  PTHREAD_FEATURE_FINEPRIO
         *   0x04  PTHREAD_FEATURE_BSDTHREADCTL
         *   0x08  PTHREAD_FEATURE_SETSELF
         *   0x10  PTHREAD_FEATURE_QOS_MAINTENANCE
         *   0x40  PTHREAD_FEATURE_KEVENT
         *   0x80  PTHREAD_FEATURE_WORKLOOP
         *  0x100  PTHREAD_FEATURE_COOPERATIVE_WORKQ
         *  0x40000000  PTHREAD_FEATURE_QOS_DEFAULT
         */
        {
            /* Save callback pointers for thread creation.
             * Strip PAC bits — shared cache functions have upper-bit
             * signatures on arm64e.  Keep only the lower 48 bits.
             */
            saved_threadstart = arg1 & 0x0000FFFFFFFFFFFFULL;
            saved_wqthread = arg2 & 0x0000FFFFFFFFFFFFULL;
            saved_pthsize = arg3;

            if (do_strace) {
                fprintf(stderr, "  bsdthread_register: threadstart=0x%lx "
                        "wqthread=0x%lx pthsize=0x%lx\n",
                        (unsigned long)arg1, (unsigned long)arg2,
                        (unsigned long)arg3);
            }

            /* Fill in copy-out fields if a data pointer was provided */
            if (arg4 && arg5 >= 24) {
                /*
                 * struct _pthread_registration_data (packed):
                 *   u64 version                  [+0]  copy-in/out
                 *   u64 dispatch_queue_offset     [+8]  copy-in
                 *   u64 main_qos                 [+16] copy-out
                 *   u32 tsd_offset               [+24] copy-in
                 *   u32 return_to_kernel_offset   [+28] copy-in
                 *   u32 mach_thread_self_offset   [+32] copy-in
                 *   u64 stack_addr_hint          [+36] copy-out
                 *   u32 mutex_default_policy      [+44] copy-out
                 *   u32 joinable_offset_bits      [+48] copy-in
                 *   u32 wq_quantum_expiry_offset  [+52] copy-in
                 */
                uint8_t *data = (uint8_t *)g2h_untagged(arg4);
                uint64_t datasz = arg5;

                /* Read tsd_offset from copy-in data */
                if (datasz >= 28) {
                    memcpy(&saved_tsd_offset, data + 24, 4);
                    if (do_strace) {
                        fprintf(stderr, "  bsdthread_register: "
                                "tsd_offset=%u\n", saved_tsd_offset);
                    }
                }
                if (datasz >= 36) {
                    memcpy(&saved_mach_thread_self_offset, data + 32, 4);
                    if (do_strace) {
                        fprintf(stderr, "  bsdthread_register: "
                                "mach_thread_self_offset=%u\n",
                                saved_mach_thread_self_offset);
                    }
                }

                /* main_qos = 0 (THREAD_QOS_UNSPECIFIED) */
                if (datasz >= 24) {
                    memset(data + 16, 0, 8);
                }
                /* stack_addr_hint = 0 (use default) */
                if (datasz >= 44) {
                    memset(data + 36, 0, 8);
                }
                /* mutex_default_policy = FIRSTFIT(2) | ULOCK(0x100) */
                if (datasz >= 48) {
                    uint32_t policy = 0x102;
                    memcpy(data + 44, &policy, 4);
                }
            }
            ret = 0x400001df;
        }
        break;

    case TARGET_MACOS_NR_workq_open:
        /*
         * workq_open(void)
         * We emulate the workqueue with our own kqueue, so just
         * return success.  Do NOT forward to the kernel — that
         * would create real kernel workqueue threads that interfere
         * with our emulation.
         */
        get_workq_kqueue();
        ret = 0;
        if (do_strace) {
            fprintf(stderr, "  workq_open -> 0 (emulated)\n");
        }
        break;

    case TARGET_MACOS_NR_workq_kernreturn:
        /*
         * workq_kernreturn(int options, void *item, int affinity, int prio)
         *
         * Kernel interface for workqueue thread management.
         * WQOPS_QUEUE_REQTHREADS: libdispatch requests N threads at a
         *   given QoS priority.  We create one workqueue thread that
         *   enters at the wqthread callback registered via bsdthread_register.
         * WQOPS_THREAD_RETURN: workqueue thread is done, return to pool.
         *   In our model the host thread exits.
         */
        {
            int wq_op = (int)arg1;

            if (do_strace) {
                fprintf(stderr, "  workq_kernreturn: op=0x%x item=0x%lx "
                        "aff=%d prio=%d\n",
                        wq_op, (unsigned long)arg2, (int)arg3, (int)arg4);
            }

            switch (wq_op) {
            case WQOPS_QUEUE_REQTHREADS:
            case WQOPS_QUEUE_REQTHREADS2:
            {
                /*
                 * arg2 = reqcount (number of threads requested)
                 * arg3 = priority / QoS class
                 *
                 * Create one workqueue thread.  The thread enters at
                 * the wqthread callback with:
                 *   x0 = pthread_self (we allocate a fake one)
                 *   x1 = mach_thread_self port
                 *   x2 = stack bottom address
                 *   x3 = NULL (keventlist, for non-kevent threads)
                 *   x4 = flags (WQ_FLAG_THREAD_NEWSPI)
                 *   x5 = 0 (nkevents)
                 */
                if (!saved_wqthread) {
                    ret = -TARGET_ENOTSUP;
                    break;
                }

                /*
                 * Allocate the workqueue thread stack region.
                 *
                 * XNU layout (from workq_thread_get_addrs):
                 *   stackaddr  = base of allocation
                 *   guard page = stackaddr .. + guardsize
                 *   usable stack = guard .. + PTH_DEFAULT_STACKSIZE
                 *   gap (arm64) = 12 KB (PTHREAD_T_OFFSET)
                 *   self       = stackaddr + guard + stacksz + gap
                 *   stack_top  = self & ~0xF
                 *   stack_bottom = stackaddr + guard
                 *
                 * total = guard + stacksz + gap + pthsize
                 */
                size_t page_sz = qemu_real_host_page_size();
                size_t guardsize = page_sz;
                size_t pthsize = saved_pthsize ? saved_pthsize : 0x4000;
                size_t total = guardsize + PTH_DEFAULT_STACKSZ
                             + PTHREAD_T_OFFSET_ARM64 + pthsize;

                mmap_lock();
                abi_ulong stackaddr = target_mmap(0, total,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                mmap_unlock();

                if (stackaddr == (abi_ulong)-1) {
                    ret = -TARGET_ENOMEM;
                    break;
                }

                /* Mark guard page as inaccessible */
                mmap_lock();
                target_mprotect(stackaddr, guardsize, PROT_NONE);
                mmap_unlock();

                abi_ulong stack_bottom = stackaddr + guardsize;
                abi_ulong self_addr = stackaddr + guardsize
                                    + PTH_DEFAULT_STACKSZ
                                    + PTHREAD_T_OFFSET_ARM64;
                abi_ulong stack_top = self_addr & ~(abi_ulong)0xF;

                /*
                 * TSD base = self + tsd_offset.
                 * The kernel calls thread_set_tsd_base() with this value
                 * which sets TPIDRRO_EL0 on the new thread.
                 */
                abi_ulong tsd_base = self_addr;
                if (saved_tsd_offset) {
                    tsd_base = self_addr + saved_tsd_offset;
                }

                /*
                 * Build flags for the upcall.
                 *
                 * The priority (arg4 = prio param) is a pthread_priority_t.
                 * QoS is encoded one-hot in bits 8-13:
                 *   qos = __builtin_ffs((pp & 0x3F00) >> 8)
                 * The kernel constructs upcall flags:
                 *   flags = WQ_FLAG_THREAD_NEWSPI | qos | WQ_FLAG_THREAD_PRIO_QOS
                 *
                 * We also add WQ_FLAG_THREAD_TSD_BASE_SET since we set
                 * TPIDRRO_EL0 ourselves.
                 */
                uint32_t pp = (uint32_t)arg4;
                uint32_t qos_bits = (pp & 0x00003F00) >> 8;
                uint32_t qos = qos_bits ? __builtin_ffs(qos_bits) : 4;
                uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                               | WQ_FLAG_THREAD_TSD_BASE_SET
                               | WQ_FLAG_THREAD_PRIO_QOS
                               | qos;
                if (pp & 0x80000000) {  /* _PTHREAD_PRIORITY_OVERCOMMIT_FLAG */
                    flags |= WQ_FLAG_THREAD_OVERCOMMIT;
                }

                TaskState *parent_ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));

                /*
                 * Try to wake a parked thread first (reuse).
                 * If none available, create a new one.
                 */
                parked_wq_thread *pw = NULL;
                pthread_mutex_lock(&parked_lock);
                if (parked_list) {
                    pw = parked_list;
                    parked_list = pw->next;
                    pw->next = NULL;
                }
                pthread_mutex_unlock(&parked_lock);

                if (pw) {
                    /* Reuse parked thread — use REUSE flag */
                    uint32_t reuse_flags = (flags & ~WQ_FLAG_THREAD_TSD_BASE_SET)
                                         | WQ_FLAG_THREAD_REUSE;
                    if (do_strace) {
                        fprintf(stderr, "  WQOPS_QUEUE_REQTHREADS: "
                                "reuse parked thread "
                                "self=0x%lx flags=0x%x\n",
                                (unsigned long)pw->self_addr,
                                reuse_flags);
                    }
                    pthread_mutex_lock(&pw->mutex);
                    pw->new_flags = reuse_flags;
                    pw->has_work = true;
                    pthread_cond_signal(&pw->cond);
                    pthread_mutex_unlock(&pw->mutex);
                    ret = 0;
                } else {
                    if (do_strace) {
                        fprintf(stderr, "  WQOPS_QUEUE_REQTHREADS: "
                                "wqthread=0x%lx self=0x%lx "
                                "sp=0x%lx stacklow=0x%lx "
                                "tsd_base=0x%lx flags=0x%x\n",
                                (unsigned long)saved_wqthread,
                                (unsigned long)self_addr,
                                (unsigned long)stack_top,
                                (unsigned long)stack_bottom,
                                (unsigned long)tsd_base,
                                flags);
                    }

                    int rc = create_guest_thread(
                        (CPUArchState *)cpu_env,
                        saved_wqthread,  /* PC = wqthread callback */
                        stack_top,       /* SP */
                        self_addr,       /* x0 = pthread_self */
                        0,               /* x1 = kport (set by worker) */
                        stack_bottom,    /* x2 = stacklowaddr */
                        0,               /* x3 = keventlist (NULL) */
                        flags,           /* x4 = flags */
                        0,               /* x5 = nkevents */
                        tsd_base,        /* TPIDRRO_EL0 */
                        parent_ts,
                        true, self_addr, stack_top,
                        stack_bottom, tsd_base, 0);

                    if (do_strace) {
                        fprintf(stderr, "  create_guest_thread: rc=%d\n", rc);
                    }

                    if (rc < 0) {
                        ret = rc;
                    } else {
                        ret = 0;
                    }
                }
                break;
            }

            case WQOPS_THREAD_RETURN:
            {
                /*
                 * XNU does not re-enter userland from WQOPS_THREAD_RETURN;
                 * the worker thread is finished.  Parking and reusing the
                 * guest thread causes libdispatch to spin in THREAD_RETURN
                 * while other threads are blocked waiting for replies.
                 */
                if (do_strace) {
                    strace_dump_guest_backtrace((CPUArchState *)cpu_env,
                                                "WQOPS_THREAD_RETURN");
                }
                TaskState *ts = get_task_state(env_cpu((CPUArchState *)cpu_env));
                if (ts && ts->active_workloop_id) {
                    if (do_strace) {
                        fprintf(stderr, "  WQOPS_THREAD_RETURN: clearing "
                                "active workloop wl=0x%llx\n",
                                (unsigned long long)ts->active_workloop_id);
                    }
                    clear_workloop_active(ts->active_workloop_id);
                    set_workloop_sync_wake_inflight(ts->active_workloop_id,
                                                    false);
                    clear_workloop_readiness_inflight(ts->active_workloop_id);
                    ts->active_workloop_id = 0;
                }
                thread_cpu = NULL;
                rcu_unregister_thread();
                pthread_exit(NULL);
            }

            case WQOPS_THREAD_WORKLOOP_RETURN:
            {
                /*
                 * Workloop thread is done.  Forward any changelist to
                 * our workq kqueue, then park in the workloop-parked
                 * list.  The monitor thread will wake it when new
                 * workloop events arrive for any workloop.
                 */
                struct kevent_qos_s *cl = arg2
                    ? (struct kevent_qos_s *)g2h_untagged(arg2) : NULL;
                int nchanges = (int)arg3;
                uint64_t current_wl_id = 0;
                bool ended_ownership = false;
                bool sync_end_changelist = false;
                bool sync_wait_changelist = false;

                if (arg2) {
                    abi_ulong kqid_addr = arg2 - sizeof(uint64_t);
                    current_wl_id = *(uint64_t *)g2h_untagged(kqid_addr);
                }
                TaskState *ts = get_task_state(env_cpu((CPUArchState *)cpu_env));
                if (!current_wl_id && ts) {
                    current_wl_id = ts->active_workloop_id;
                }

                if (do_strace) {
                    fprintf(stderr, "  WQOPS_THREAD_WORKLOOP_RETURN: "
                            "wl=0x%llx nchanges=%d\n",
                            (unsigned long long)current_wl_id, nchanges);
                    for (int i = 0; cl && i < nchanges; i++) {
                        fprintf(stderr,
                                "    return kev[%d]: filter=%d ident=0x%llx "
                                "flags=0x%x fflags=0x%x qos=0x%x "
                                "udata=0x%llx ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                                i, cl[i].filter,
                                (unsigned long long)cl[i].ident,
                                cl[i].flags, cl[i].fflags, cl[i].qos,
                                (unsigned long long)cl[i].udata,
                                (unsigned long long)cl[i].ext[0],
                                (unsigned long long)cl[i].ext[1],
                                (unsigned long long)cl[i].ext[2],
                                (unsigned long long)cl[i].ext[3]);
                    }
                }

                for (int i = 0; cl && i < nchanges; i++) {
                    if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                        (cl[i].fflags & NOTE_WL_END_OWNERSHIP)) {
                        ended_ownership = true;
                    }
                    if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                        (cl[i].fflags & NOTE_WL_END_OWNERSHIP)) {
                        sync_end_changelist = true;
                    }
                    if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                        (cl[i].fflags & NOTE_WL_SYNC_WAIT)) {
                        sync_wait_changelist = true;
                    }
                }

                for (int i = 0; cl && i < nchanges; i++) {
                    if (cl[i].filter == EVFILT_MACHPORT) {
                        if (cl[i].flags & EV_DELETE) {
                            remove_workloop_port((mach_port_t)cl[i].ident);
                        } else {
                            add_workloop_port(current_wl_id, &cl[i]);
                        }
                    } else if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                               (cl[i].fflags & NOTE_WL_THREAD_REQUEST)) {
                        if (cl[i].flags & EV_DELETE) {
                            clear_pending_workloop_req(current_wl_id);
                        } else if (sync_end_changelist &&
                                   !sync_wait_changelist) {
                            cache_workloop_req_template(current_wl_id, &cl[i]);
                            store_pending_workloop_req(current_wl_id, &cl[i],
                                                       true);
                            if (do_strace) {
                            fprintf(stderr,
                                    "  WQOPS_THREAD_WORKLOOP_RETURN: "
                                    "THREAD_REQUEST sync-end state "
                                    "update stored zero-wake wl=0x%llx\n",
                                    (unsigned long long)current_wl_id);
                            }
                        } else {
                            if (cl[i].fflags == NOTE_WL_THREAD_REQUEST &&
                                (cl[i].ext[EV_EXTIDX_WL_VALUE] >> 56) == 0xff) {
                                record_workloop_sync_wake(
                                    current_wl_id, "workloop-return");
                            }
                            store_pending_workloop_req(current_wl_id, &cl[i],
                                                       true);
                        }
                    }
                }

                if (ended_ownership) {
                    clear_workloop_active(current_wl_id);
                    set_workloop_sync_wake_inflight(current_wl_id, false);
                    clear_workloop_readiness_inflight(current_wl_id);
                }

                if (cl && nchanges > 0) {
                    int rc = workq_kqueue_register(cl, nchanges);
                    if (do_strace) {
                        fprintf(stderr,
                            "  WQOPS_THREAD_WORKLOOP_RETURN: "
                            "registered %d events -> %d\n",
                            nchanges, rc);
                    }
                }

                parked_workloop_wq pw;
                memset(&pw, 0, sizeof(pw));
                pthread_mutex_init(&pw.mutex, NULL);
                pthread_cond_init(&pw.cond, NULL);
                pw.env = (CPUArchState *)cpu_env;
                pw.has_work = false;

                pw.self_addr = ts->wq_self_addr;
                pw.stack_top = ts->wq_stack_top;
                pw.stack_bottom = ts->wq_stack_bottom;
                pw.tsd_base = ts->wq_tsd_base;
                pw.workloop_id = current_wl_id;

                /*
                 * Check for ready work before publishing this stack-local
                 * parked record.  Otherwise the monitor can race in, remove
                 * the parked thread, and deliver a later reply while the
                 * return path is still holding an earlier prereceived reply.
                 */
                if (current_wl_id) {
                    struct kevent_qos_s events[16];
                    int nevents = prepare_workloop_events(current_wl_id, false,
                                                          NULL, events,
                                                          ARRAY_SIZE(events),
                                                          true);
                    if (nevents > 0) {
                        if (do_strace) {
                            fprintf(stderr, "  WQOPS_THREAD_WORKLOOP_RETURN: "
                                    "immediate reuse wl=0x%llx with %d event(s)\n",
                                    (unsigned long long)current_wl_id,
                                    nevents);
                        }
                        pw.delivered_events = g_malloc(
                            nevents * sizeof(struct kevent_qos_s));
                        memcpy(pw.delivered_events, events,
                               nevents * sizeof(struct kevent_qos_s));
                        pw.delivered_nevents = nevents;
                        mark_workloop_active(current_wl_id);
                        ts->active_workloop_id = current_wl_id;
                    }
                }

                if (pw.delivered_nevents == 0) {
                    pthread_mutex_lock(&parked_workloop_lock);
                    pw.next = parked_workloop_list;
                    parked_workloop_list = &pw;
                    pthread_mutex_unlock(&parked_workloop_lock);
                    clear_workloop_active(current_wl_id);
                    if (ts && ts->active_workloop_id == current_wl_id) {
                        ts->active_workloop_id = 0;
                    }
                    set_workloop_sync_wake_inflight(current_wl_id, false);

                    /* Wait for events from monitor thread */
                    pthread_mutex_lock(&pw.mutex);
                    while (!pw.has_work) {
                        pthread_cond_wait(&pw.cond, &pw.mutex);
                    }
                    pthread_mutex_unlock(&pw.mutex);
                }
                if (ts) {
                    ts->active_workloop_id = pw.workloop_id;
                }

                /* Copy delivered events to guest stack with wl ID */
                CPUArchState *env = (CPUArchState *)cpu_env;
#define DISPATCH_DEFERRED_ITEMS_MAX 16
                int workloop_slots = pw.delivered_nevents
                    > DISPATCH_DEFERRED_ITEMS_MAX
                    ? pw.delivered_nevents : DISPATCH_DEFERRED_ITEMS_MAX;
                size_t ev_sz = workloop_slots
                             * sizeof(struct kevent_qos_s);
                abi_ulong sp = pw.stack_top;
                sp -= sizeof(uint64_t) + ev_sz;
                sp &= ~(abi_ulong)0xF;

                abi_ulong kqid_addr = sp;
                abi_ulong keventlist = sp + sizeof(uint64_t);
                *(uint64_t *)g2h_untagged(kqid_addr) = pw.workloop_id;
                memset(g2h_untagged(keventlist), 0, ev_sz);
                memcpy(g2h_untagged(keventlist),
                       pw.delivered_events,
                       pw.delivered_nevents * sizeof(struct kevent_qos_s));
#undef DISPATCH_DEFERRED_ITEMS_MAX
                sp -= 256;
                sp &= ~(abi_ulong)0xF;

                uint32_t reuse_flags = WQ_FLAG_THREAD_WORKLOOP
                    | WQ_FLAG_THREAD_REUSE
                    | WQ_FLAG_THREAD_NEWSPI
                    | WQ_FLAG_THREAD_KEVENT
                    | WQ_FLAG_THREAD_PRIO_QOS | 4;
                ts->wq_event_manager = false;

                mach_port_t self_port = mach_thread_self();

                env->pc = saved_wqthread;
                env->xregs[31] = sp;
                env->xregs[0] = pw.self_addr;
                env->xregs[1] = (abi_ulong)self_port;
                env->xregs[2] = pw.stack_bottom;
                env->xregs[3] = keventlist;
                env->xregs[4] = reuse_flags;
                env->xregs[5] = pw.delivered_nevents;
                env->xregs[29] = 0;
                env->xregs[30] = 0;
                env->cp15.tpidrro_el[0] = pw.tsd_base;
                write_mach_thread_self_tsd_slot(pw.tsd_base, self_port);

                g_free(pw.delivered_events);
                pthread_mutex_destroy(&pw.mutex);
                pthread_cond_destroy(&pw.cond);

                ret = -TARGET_EJUSTRETURN;
                break;
            }

            case WQOPS_THREAD_KEVENT_RETURN:
            {
                /*
                 * Kevent workqueue thread is done.  Forward any new
                 * changelist to our workq kqueue, then park the thread
                 * in the kevent-parked list.  The monitor thread will
                 * wake it when new kevent events fire.
                 */
                struct kevent_qos_s *cl = arg2
                    ? (struct kevent_qos_s *)g2h_untagged(arg2) : NULL;
                int nchanges = (int)arg3;

                if (do_strace) {
                    fprintf(stderr, "  WQOPS_THREAD_KEVENT_RETURN: "
                            "nchanges=%d\n", nchanges);
                    for (int i = 0; cl && i < nchanges; i++) {
                        fprintf(stderr,
                                "    kevent return kev[%d]: filter=%d "
                                "ident=0x%llx flags=0x%x fflags=0x%x "
                                "qos=0x%x udata=0x%llx "
                                "ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                                i, cl[i].filter,
                                (unsigned long long)cl[i].ident,
                                cl[i].flags, cl[i].fflags, cl[i].qos,
                                (unsigned long long)cl[i].udata,
                                (unsigned long long)cl[i].ext[0],
                                (unsigned long long)cl[i].ext[1],
                                (unsigned long long)cl[i].ext[2],
                                (unsigned long long)cl[i].ext[3]);
                    }
                }

                if (cl && nchanges > 0) {
                    int rc = workq_kqueue_register(cl, nchanges);
                    if (do_strace) {
                        fprintf(stderr,
                            "  WQOPS_THREAD_KEVENT_RETURN: "
                            "registered %d events -> %d\n",
                            nchanges, rc);
                    }
                }

                parked_kevent_wq pk;
                memset(&pk, 0, sizeof(pk));
                pthread_mutex_init(&pk.mutex, NULL);
                pthread_cond_init(&pk.cond, NULL);
                pk.env = (CPUArchState *)cpu_env;
                pk.has_work = false;

                TaskState *ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));
                pk.self_addr = ts->wq_self_addr;
                pk.stack_top = ts->wq_stack_top;
                pk.stack_bottom = ts->wq_stack_bottom;
                pk.tsd_base = ts->wq_tsd_base;

                if (ts->wq_event_manager) {
                    struct kevent_qos_s pending_events[16];
                    int pending_nevents =
                        finish_event_manager_turn(pending_events,
                                                  ARRAY_SIZE(pending_events));

                    if (pending_nevents > 0) {
                        pk.delivered_events = g_memdup2(
                            pending_events,
                            pending_nevents * sizeof(pending_events[0]));
                        pk.delivered_nevents = pending_nevents;
                        if (do_strace) {
                            fprintf(stderr, "  WQOPS_THREAD_KEVENT_RETURN: "
                                    "reusing event manager for %d deferred "
                                    "kevent(s)\n", pending_nevents);
                        }
                        goto redispatch_kevent_thread;
                    }
                    ts->wq_event_manager = false;
                }

                pthread_mutex_lock(&parked_kevent_lock);
                pk.next = parked_kevent_list;
                parked_kevent_list = &pk;
                pthread_mutex_unlock(&parked_kevent_lock);

                /* Wait for events from monitor thread */
                pthread_mutex_lock(&pk.mutex);
                while (!pk.has_work) {
                    pthread_cond_wait(&pk.cond, &pk.mutex);
                }
                pthread_mutex_unlock(&pk.mutex);

redispatch_kevent_thread:
                ;
                /* Copy delivered events to guest stack.
                 * Allocate at least 16 slots because libdispatch
                 * reuses this buffer for deferred items.
                 */
                CPUArchState *env = (CPUArchState *)cpu_env;
#define DISPATCH_DEFERRED_ITEMS_MAX 16
                int reuse_slots = pk.delivered_nevents
                    > DISPATCH_DEFERRED_ITEMS_MAX
                    ? pk.delivered_nevents : DISPATCH_DEFERRED_ITEMS_MAX;
                size_t ev_sz = reuse_slots
                             * sizeof(struct kevent_qos_s);
                abi_ulong sp = pk.stack_top;
                sp -= ev_sz;
                sp &= ~(abi_ulong)0xF;
                memset(g2h_untagged(sp), 0, ev_sz);
                memcpy(g2h_untagged(sp), pk.delivered_events,
                       pk.delivered_nevents
                       * sizeof(struct kevent_qos_s));
                abi_ulong keventlist = sp;
#undef DISPATCH_DEFERRED_ITEMS_MAX
                sp -= 256;
                sp &= ~(abi_ulong)0xF;

                uint32_t reuse_flags = WQ_FLAG_THREAD_KEVENT
                    | WQ_FLAG_THREAD_REUSE
                    | WQ_FLAG_THREAD_NEWSPI;

                /* Check if delivered events need event manager flag.
                 * EVENT_MANAGER and PRIO_QOS are mutually exclusive. */
                bool reuse_is_mgr = false;
                for (int ei = 0; ei < pk.delivered_nevents; ei++) {
                    if ((pk.delivered_events[ei].filter == EVFILT_USER ||
                         pk.delivered_events[ei].filter == EVFILT_TIMER) &&
                        ((pk.delivered_events[ei].qos
                          ? pk.delivered_events[ei].qos
                          : saved_evfilt_user_qos) &
                         _PTHREAD_PRIORITY_EVENT_MANAGER_FLAG)) {
                        reuse_is_mgr = true;
                        break;
                    }
                }
                if (reuse_is_mgr) {
                    reuse_flags |= WQ_FLAG_THREAD_EVENT_MANAGER;
                } else {
                    reuse_flags |= WQ_FLAG_THREAD_PRIO_QOS | 4;
                }
                ts->wq_event_manager = reuse_is_mgr;

                mach_port_t self_port = mach_thread_self();

                env->pc = saved_wqthread;
                env->xregs[31] = sp;
                env->xregs[0] = pk.self_addr;
                env->xregs[1] = (abi_ulong)self_port;
                env->xregs[2] = pk.stack_bottom;
                env->xregs[3] = keventlist;
                env->xregs[4] = reuse_flags;
                env->xregs[5] = pk.delivered_nevents;
                env->xregs[29] = 0;
                env->xregs[30] = 0;
                env->cp15.tpidrro_el[0] = pk.tsd_base;
                write_mach_thread_self_tsd_slot(pk.tsd_base, self_port);

                g_free(pk.delivered_events);
                pthread_mutex_destroy(&pk.mutex);
                pthread_cond_destroy(&pk.cond);

                ret = -TARGET_EJUSTRETURN;
                break;
            }

            case WQOPS_SHOULD_NARROW:
                /* Should we reduce thread count?  No. */
                ret = 0;
                break;

            case WQOPS_QUEUE_NEWSPISUPP:
                /*
                 * Query for newer SPI support.  arg2 = feature key.
                 * Return 0 to indicate we support the new SPI.
                 */
                ret = 0;
                break;

            case WQOPS_SET_EVENT_MANAGER_PRIORITY:
                /* Set event manager priority — just acknowledge. */
                ret = 0;
                break;

            case WQOPS_SETUP_DISPATCH:
            {
                /*
                 * libdispatch calls this to register its config struct.
                 * We emulate the workqueue ourselves, so just return
                 * success without forwarding to the kernel.
                 */
                if (do_strace) {
                    fprintf(stderr, "  WQOPS_SETUP_DISPATCH: "
                            "config=0x%lx size=%d (emulated)\n",
                            (unsigned long)arg2, (int)arg3);
                }
                ret = 0;
                break;
            }

            default:
                if (do_strace) {
                    fprintf(stderr, "  workq_kernreturn: unknown op 0x%x\n",
                            wq_op);
                }
                ret = 0;
                break;
            }
        }
        break;

    /*
     * Syscalls required by dyld and dynamically linked programs
     */

    case TARGET_MACOS_NR_kqueue:
        /* kqueue(void) — create a new kernel event queue */
        ret = get_errno(kqueue());
        break;

    case TARGET_MACOS_NR_kevent: {
        /*
         * kevent(int kq, const struct kevent *changelist, int nchanges,
         *        struct kevent *eventlist, int nevents,
         *        const struct timespec *timeout)
         */
        struct kevent *cl = arg2 ? (struct kevent *)g2h_untagged(arg2) : NULL;
        struct kevent *el = arg4 ? (struct kevent *)g2h_untagged(arg4) : NULL;
        struct timespec *ts = arg6 ? (struct timespec *)g2h_untagged(arg6) : NULL;
        ret = get_errno(kevent((int)arg1, cl, (int)arg3, el, (int)arg5, ts));
        break;
    }

    case TARGET_MACOS_NR_kevent64: {
        /*
         * kevent64(int kq, const struct kevent64_s *changelist, int nchanges,
         *          struct kevent64_s *eventlist, int nevents,
         *          unsigned int flags, const struct timespec *timeout)
         *
         * Forward to host via raw syscall.  The kevent64_s struct is the
         * same layout on guest and host (both arm64).
         */
        void *cl = arg2 ? g2h_untagged(arg2) : NULL;
        void *el = arg4 ? g2h_untagged(arg4) : NULL;
        void *ts = arg7 ? g2h_untagged(arg7) : NULL;
        ret = get_errno(syscall(SYS_kevent64, (int)arg1, cl, (int)arg3,
                                el, (int)arg5, (unsigned int)arg6, ts));
        break;
    }

    case TARGET_MACOS_NR_kevent_qos: {
        int kq = (int)arg1;
        unsigned int flags = (unsigned int)arg8;

        if (do_strace && kq != -1) {
            struct kevent_qos_s *cl_dbg = arg2
                ? (struct kevent_qos_s *)g2h_untagged(arg2) : NULL;
            fprintf(stderr, "  kevent_qos: kq=%d nchanges=%d "
                    "nevents=%d flags=0x%x\n",
                    kq, (int)arg3, (int)arg5, flags);
            if (cl_dbg) {
                for (int i = 0; i < (int)arg3; i++) {
                    fprintf(stderr, "    cl[%d]: filter=%d "
                            "ident=0x%llx fflags=0x%x\n",
                            i, cl_dbg[i].filter,
                            (unsigned long long)cl_dbg[i].ident,
                            cl_dbg[i].fflags);
                }
            }
        }

        if (kq == -1 && (flags & KEVENT_FLAG_WORKQ)) {
            /*
             * Workqueue kqueue: libdispatch registers events here.
             *
             * Register EVFILT_USER and EVFILT_TIMER events on our
             * workq kqueue so the monitor thread can deliver them
             * to workqueue threads.  This enables dispatch_after
             * and dispatch_source timers.
             *
             * MACHPORT events from kevent_qos WORKQ are NOT registered
             * here — they overlap with MIG reply ports and are handled
             * separately via kevent_id.
             */
            struct kevent_qos_s *cl = arg2
                ? (struct kevent_qos_s *)g2h_untagged(arg2) : NULL;
            int nchanges = (int)arg3;

            if (do_strace) {
                fprintf(stderr, "  kevent_qos WORKQ: nchanges=%d "
                        "nevents=%d flags=0x%x\n",
                        nchanges, (int)arg5, flags);
                if (cl) {
                    for (int i = 0; i < nchanges; i++) {
                        fprintf(stderr, "    kev[%d]: filter=%d "
                                "ident=0x%llx fflags=0x%x flags=0x%x "
                                "udata=0x%llx qos=0x%x\n",
                                i, cl[i].filter,
                                (unsigned long long)cl[i].ident,
                                cl[i].fflags, cl[i].flags,
                                (unsigned long long)cl[i].udata,
                                cl[i].qos);
                    }
                }
            }

            /*
             * Forward EVFILT_USER, EVFILT_TIMER, and EVFILT_MACHPORT
             * to our workqueue kqueue so the monitor thread can
             * dispatch them to workqueue threads.
             *
             * MACHPORT events must go through the kqueue for
             * dispatch_mach channels (e.g. XPC connections) that
             * rely exclusively on workqueue delivery.  The
             * active-receive-port guard (is_port_active_rcv)
             * prevents the monitor from stealing messages when
             * the guest has a direct mach_msg receive in flight.
             */
            if (cl && nchanges > 0 && saved_wqthread) {
                TaskState *ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));
                ensure_workq_monitor((CPUArchState *)cpu_env, ts);

                int wkq = get_workq_kqueue();
                for (int i = 0; i < nchanges; i++) {
                    int f = cl[i].filter;
                    if (f == EVFILT_TIMER_PRIVATE) {
                        int rc = register_workq_timer(&cl[i]);
                        if (do_strace) {
                            fprintf(stderr, "    registered TIMER "
                                    "ident=0x%llx on workq timer rc=%d%s\n",
                                    (unsigned long long)cl[i].ident, rc,
                                    rc < 0 ? " (FAILED)" : "");
                        }
                    } else if (f == EVFILT_USER_PRIVATE) {
                        struct kevent64_s k64;
                        kqos_to_k64(&cl[i], &k64);
                        remember_workq_knote_qos(&cl[i]);
                        /* Save udata/qos for EVFILT_USER re-triggers.
                         * Only save from the initial EV_ADD registration,
                         * not from NOTE_TRIGGER pokes which have qos=0. */
                        if (f == EVFILT_USER_PRIVATE && k64.udata
                            && (cl[i].flags & EV_ADD)) {
                            saved_evfilt_user_udata = k64.udata;
                            saved_evfilt_user_qos = cl[i].qos;
                        }
                        int rc = kevent64(wkq, &k64, 1, NULL, 0, 0,
                                          NULL);
                        if (do_strace) {
                            fprintf(stderr, "    registered filter=%d"
                                    " ident=0x%llx on workq kqueue"
                                    " rc=%d%s\n",
                                    cl[i].filter,
                                    (unsigned long long)cl[i].ident,
                                    rc,
                                    rc < 0 ? " (FAILED)" : "");
                        }
                    } else if (f == EVFILT_MACHPORT) {
                        mach_port_t port = (mach_port_t)cl[i].ident;
                        save_workq_machport_template(&cl[i]);

                        if (is_workq_notification_port(port)) {
                            register_workq_notification_template(port);
                            if (do_strace) {
                                fprintf(stderr, "    saved notify MACHPORT "
                                        "ident=0x%llx for manual polling\n",
                                        (unsigned long long)cl[i].ident);
                            }
                        } else {
                            struct kevent64_s k64;
                            kqos_to_k64(&cl[i], &k64);
                            int rc = kevent64(wkq, &k64, 1, NULL, 0, 0,
                                              NULL);
                            if (do_strace) {
                                fprintf(stderr,
                                        "    registered MACHPORT"
                                        " ident=0x%llx on workq kqueue"
                                        " rc=%d%s\n",
                                        (unsigned long long)cl[i].ident,
                                        rc,
                                        rc < 0 ? " (FAILED)" : "");
                            }
                        }
                    }
                }
            }

            ret = 0;
            if (do_strace) {
                fprintf(stderr, "    kevent_qos WORKQ -> 0\n");
            }
            break;
        }

        void *cl = arg2 ? g2h_untagged(arg2) : NULL;
        void *el = arg4 ? g2h_untagged(arg4) : NULL;
        void *d_out = arg6 ? g2h_untagged(arg6) : NULL;
        size_t *d_avail = arg7 ? (size_t *)g2h_untagged(arg7) : NULL;

        if (cl) {
            kevent_translate_machport_ptrs(
                (struct kevent_qos_s *)cl, (int)arg3, true);
        }
        {
            long raw = raw_kevent_qos(kq, cl, (int)arg3,
                                       el, (int)arg5, d_out, d_avail, flags);
            if (raw < 0) {
                errno = (int)(-raw);
                ret = -errno;
            } else {
                ret = raw;
            }
        }
        if (cl) {
            kevent_translate_machport_ptrs(
                (struct kevent_qos_s *)cl, (int)arg3, false);
        }
        if (el && ret > 0) {
            kevent_translate_machport_ptrs(
                (struct kevent_qos_s *)el, (int)ret, false);
        }
        break;
    }

    case TARGET_MACOS_NR_kevent_id: {
        /*
         * kevent_id(uint64_t id, const struct kevent_qos_s *changelist,
         *           int nchanges, struct kevent_qos_s *eventlist,
         *           int nevents, void *data_out,
         *           size_t *data_available, unsigned int flags)
         *
         * Used by libdispatch for workloop kqueues.  We emulate by
         * returning success for registrations without actually creating
         * a kernel workloop.  MACHPORT registrations are acknowledged
         * Used by libdispatch for workloop kqueues.
         *
         * MACHPORT registrations go to workq_kqueue_fd so the
         * monitor thread can deliver events to guest workqueue
         * threads.  WORKLOOP registrations are no-ops (we handle
         * thread management ourselves).
         */
        struct kevent_qos_s *cl = arg2
            ? (struct kevent_qos_s *)g2h_untagged(arg2) : NULL;
        int nchanges = (int)arg3;
        unsigned int kflags = (unsigned int)arg8;

        if (do_strace) {
            fprintf(stderr, "  kevent_id: id=0x%llx nchanges=%d "
                    "nevents=%d flags=0x%x\n",
                    (unsigned long long)arg1, nchanges,
                    (int)arg5, kflags);
            if (cl) {
                for (int i = 0; i < nchanges; i++) {
                    fprintf(stderr, "    kev[%d]: filter=%d "
                            "ident=0x%llx flags=0x%x "
                            "fflags=0x%x ext=[0x%llx,0x%llx,0x%llx,0x%llx]\n",
                            i, cl[i].filter,
                            (unsigned long long)cl[i].ident,
                            cl[i].flags, cl[i].fflags,
                            (unsigned long long)cl[i].ext[0],
                            (unsigned long long)cl[i].ext[1],
                            (unsigned long long)cl[i].ext[2],
                            (unsigned long long)cl[i].ext[3]);
                }
            }
        }

        /*
         * kevent_id: used by libdispatch for workloop kqueues.
         *
         * MACHPORT events go to our workq kqueue for manual monitoring.
         *
         * WORKLOOP events with NOTE_WL_THREAD_REQUEST tell us GCD
         * needs a thread to service a workloop (serial queue).  We
         * create a guest workloop thread with the THREAD_REQUEST event
         * so libdispatch can process queued blocks.
         */
        if (cl && nchanges > 0) {
            TaskState *ts = get_task_state(
                env_cpu((CPUArchState *)cpu_env));
            struct kevent_qos_s latest_thread_req;
            bool have_latest_thread_req = false;
            bool sync_end_changelist = false;
            bool sync_wait_changelist = false;
            bool sync_wait_thread_req_handled = false;
            bool *skip_change = g_new0(bool, nchanges);
            struct kevent_qos_s *eventlist = arg4
                ? (struct kevent_qos_s *)g2h_untagged(arg4) : NULL;
            int maxevents = (int)arg5;
            int error_events = 0;

            /* Ensure monitor is initialized for thread creation */
            ensure_workq_monitor((CPUArchState *)cpu_env, ts);

            for (int i = 0; i < nchanges; i++) {
                int wl_error = refresh_workloop_state_update(&cl[i]);

                if (wl_error == 0) {
                    continue;
                }
                if (wl_error == ESTALE &&
                    (cl[i].fflags & NOTE_WL_IGNORE_ESTALE)) {
                    skip_change[i] = true;
                    if (do_strace) {
                        fprintf(stderr, "    WORKLOOP state stale ignored "
                                "wl=0x%llx ident=0x%llx value=0x%llx\n",
                                (unsigned long long)arg1,
                                (unsigned long long)cl[i].ident,
                                (unsigned long long)cl[i].ext[EV_EXTIDX_WL_VALUE]);
                    }
                    continue;
                }
                if (eventlist && error_events < maxevents) {
                    eventlist[error_events] = cl[i];
                    eventlist[error_events].flags |= EV_ERROR;
                    eventlist[error_events].data = wl_error;
                    error_events++;
                }
            }

            if (error_events > 0) {
                ret = error_events;
                if (do_strace) {
                    fprintf(stderr, "    kevent_id -> %d workloop error "
                            "event(s)\n", error_events);
                }
                g_free(skip_change);
                break;
            }

            for (int i = 0; i < nchanges; i++) {
                if (skip_change[i]) {
                    continue;
                }
                if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                    (cl[i].fflags & NOTE_WL_THREAD_REQUEST)) {
                    latest_thread_req = cl[i];
                    refresh_workloop_req_value(&latest_thread_req);
                    have_latest_thread_req = true;
                }
                if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                    (cl[i].fflags & NOTE_WL_END_OWNERSHIP)) {
                    sync_end_changelist = true;
                }
                if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                    (cl[i].fflags & NOTE_WL_SYNC_WAIT)) {
                    sync_wait_changelist = true;
                }
            }

            for (int i = 0; i < nchanges; i++) {
                bool ended_ownership =
                    cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                    (cl[i].fflags & NOTE_WL_END_OWNERSHIP);

                if (skip_change[i]) {
                    continue;
                }
                if (ended_ownership) {
                    clear_workloop_active(arg1);
                }
                if (cl[i].filter == EVFILT_MACHPORT) {
                    mach_port_t mp = (mach_port_t)cl[i].ident;
                    if (cl[i].flags & EV_DELETE) {
                        remove_workloop_port(mp);
                        if (do_strace) {
                            fprintf(stderr, "    MACHPORT ident=0x%llx"
                                    " -> untrack wl=0x%llx\n",
                                    (unsigned long long)cl[i].ident,
                                    (unsigned long long)arg1);
                        }
                        continue;
                    }
                    add_workloop_port(arg1, &cl[i]);
                    if (do_strace) {
                        fprintf(stderr, "    MACHPORT ident=0x%llx"
                                " -> track-only wl=0x%llx\n",
                                (unsigned long long)cl[i].ident,
                                (unsigned long long)arg1);
                    }
                    /* If this port is a notification port, register it on
                     * the host kqueue now that the template is saved.
                     * record_workq_notification_port() may have been called
                     * before the template existed. */
                    if (is_workq_notification_port(mp)) {
                        register_workq_notification_template(mp);
                    }
                } else if ((cl[i].fflags & NOTE_WL_THREAD_REQUEST)
                           && cl[i].filter == EVFILT_WORKLOOP_PRIVATE) {
                    /*
                     * GCD serial queue needs a servicer thread.
                     * Defer thread creation to avoid crashing on
                     * framework-internal workloops.  The thread will
                     * be created when __semwait_signal detects the
                     * caller is blocked waiting for serial queue work.
                     *
                     * ext layout (libdispatch private):
                     *   ext[0] = WL_LANE
                     *   ext[1] = WL_ADDR  (&dq->dq_state)
                     *   ext[2] = WL_MASK
                     *   ext[3] = WL_VALUE (current dq_state)
                     */
                    struct kevent_qos_s wl_ev = cl[i];
                    struct kevent_qos_s events[16];
                    int nevents;
                    bool sync_wait = (wl_ev.fflags & NOTE_WL_SYNC_WAIT) != 0 ||
                        sync_wait_changelist;

                    /* Read current dq_state if WL_ADDR is set */
                    refresh_workloop_req_value(&wl_ev);
                    cache_workloop_req_template(arg1, &wl_ev);
                    if (sync_end_changelist && !sync_wait) {
                        if (do_strace) {
                            fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                    "wl=0x%llx -> sync-end, evaluating wake\n",
                                    (unsigned long long)arg1);
                        }
                    }
                    if (has_parked_workloop_thread(arg1)) {
                        if (do_strace) {
                            fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                    "wl=0x%llx -> waking parked thread\n",
                                    (unsigned long long)arg1);
                        }
                        nevents = prepare_workloop_events(arg1, false, NULL,
                                                          events,
                                                          ARRAY_SIZE(events),
                                                          false);
                        if (nevents > 0) {
                            /*
                             * Real work found — clear the persistent thread
                             * request and dispatch.  take_zero_wake inside
                             * prepare_workloop_events already consumed the
                             * zero-wake entry if one existed.
                             */
                            clear_pending_workloop_req(arg1);
                            deliver_workloop_events_to_thread(arg1, events,
                                                              nevents);
                        } else if (sync_wait) {
                            /*
                             * SYNC_WAIT transfers ownership to the blocked
                             * caller; it must not provision the parked
                             * servicer with a bare THREAD_REQUEST.  Keep the
                             * persistent request until a real knote fires.
                             */
                            if (do_strace) {
                                fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                        "wl=0x%llx -> keeping parked thread "
                                        "parked (sync wait, no real work)\n",
                                        (unsigned long long)arg1);
                            }
                            store_pending_workloop_req(arg1, &wl_ev, true);
                        } else if (sync_end_changelist && !sync_wait) {
                            struct kevent_qos_s zero_wake = wl_ev;

                            if (do_strace) {
                                fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                        "wl=0x%llx -> delivering sync-end "
                                        "zero wake\n",
                                        (unsigned long long)arg1);
                            }
                            clear_pending_workloop_req(arg1);
                            deliver_workloop_events_to_thread(arg1,
                                                              &zero_wake, 1);
                        } else {
                            /*
                             * No MACHPORT data available yet.  In XNU the
                             * kernel keeps the thread request pending on
                             * the workloop until a knote fires.  Don't
                             * clear — the monitor or a future poll will
                             * pair the zero-wake with MACHPORT events.
                             */
                            if (do_strace) {
                                fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                        "wl=0x%llx -> keeping parked thread "
                                        "parked (no real work yet)\n",
                                        (unsigned long long)arg1);
                            }
                            store_pending_workloop_req(arg1, &wl_ev, true);
                        }
                    } else if (sync_wait) {
                        if (do_strace) {
                            fprintf(stderr, "    WORKLOOP THREAD_REQ "
                                    "wl=0x%llx -> immediate sync wake\n",
                                        (unsigned long long)arg1);
                        }
                        nevents = prepare_workloop_events(arg1, false, NULL,
                                                          events,
                                                          ARRAY_SIZE(events),
                                                          false);
                        sync_wait_thread_req_handled = true;
                        if (nevents > 0) {
                            set_workloop_sync_wake_inflight(arg1, true);
                            clear_pending_workloop_req(arg1);
                            deliver_workloop_events_to_thread(arg1, events,
                                                              nevents);
                        } else {
                            store_pending_workloop_req(arg1, &wl_ev, true);
                        }
                    } else {
                        add_pending_workloop_req(arg1, &wl_ev);
                        /* strace is printed inside add_pending_workloop_req
                         * for the repeat case, or here for the first defer */
                    }
                } else if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                           (cl[i].fflags & NOTE_WL_SYNC_WAIT)) {
                    struct kevent_qos_s wl_ev;
                    struct kevent_qos_s events[16];
                    int nevents = 0;
                    bool have_wl_ev = have_latest_thread_req;

                    if (have_wl_ev) {
                        wl_ev = latest_thread_req;
                    } else {
                        have_wl_ev = lookup_workloop_req_template(arg1,
                                                                  &wl_ev);
                    }

                    if (do_strace) {
                        fprintf(stderr, "    WORKLOOP SYNC_WAIT "
                                "wl=0x%llx ident=0x%llx%s\n",
                                (unsigned long long)arg1,
                                 (unsigned long long)cl[i].ident,
                                 have_wl_ev ? "" : " (no thread request)");
                    }

                    if (sync_wait_thread_req_handled) {
                        continue;
                    }

                    if (have_wl_ev) {
                        cache_workloop_req_template(arg1, &wl_ev);
                        nevents = prepare_workloop_events(arg1, true, NULL,
                                                          events,
                                                          ARRAY_SIZE(events),
                                                          false);
                        if (nevents > 0) {
                            set_workloop_sync_wake_inflight(arg1, true);
                            clear_pending_workloop_req(arg1);
                            deliver_workloop_events_to_thread(arg1, events,
                                                              nevents);
                        } else {
                            store_pending_workloop_req(arg1, &wl_ev, true);
                        }
                    }
                } else if (cl[i].filter == EVFILT_WORKLOOP_PRIVATE &&
                           (cl[i].fflags & (NOTE_WL_SYNC_WAKE |
                                              NOTE_WL_END_OWNERSHIP))) {
                    if (do_strace) {
                        fprintf(stderr, "    WORKLOOP SYNC_WAKE/END "
                                "wl=0x%llx ident=0x%llx fflags=0x%x\n",
                                (unsigned long long)arg1,
                                 (unsigned long long)cl[i].ident,
                                  cl[i].fflags);
                    }
                    if (cl[i].fflags & NOTE_WL_SYNC_WAKE) {
                        record_workloop_sync_wake(arg1, "sync-wake");
                    }
                    set_workloop_sync_wake_inflight(arg1, false);
                    clear_workloop_readiness_inflight(arg1);
                } else {
                    if (do_strace) {
                        fprintf(stderr,
                                "    WORKLOOP ident=0x%llx -> no-op\n",
                                (unsigned long long)cl[i].ident);
                    }
                }
            }
            g_free(skip_change);
        }
        ret = 0;
        if (do_strace) {
            fprintf(stderr, "    kevent_id -> 0\n");
        }
        break;
    }

    case TARGET_MACOS_NR_guarded_kqueue_np: {
        /*
         * guarded_kqueue_np(const guardid_t *guard, unsigned guardflags)
         * Create a guarded kqueue fd.  Forward to host.
         */
        uint64_t *gp = arg1 ? (uint64_t *)g2h_untagged(arg1) : NULL;
        ret = get_errno(syscall(SYS_guarded_kqueue_np, gp, (unsigned int)arg2));
        break;
    }

    case TARGET_MACOS_NR_sysctl:
        /* __sysctl(int *name, u_int namelen, void *old, size_t *oldlenp,
         *          void *new, size_t newlen) */
        {
            int *name_ptr = NULL;
            void *old_ptr = NULL;
            size_t *oldlen_ptr = NULL;
            void *new_ptr = NULL;

            if (arg1) name_ptr = (int *)g2h_untagged(arg1);
            if (arg3) old_ptr = g2h_untagged(arg3);
            if (arg4) oldlen_ptr = (size_t *)g2h_untagged(arg4);
            if (arg5) new_ptr = g2h_untagged(arg5);

            if (do_strace && name_ptr) {
                fprintf(stderr, "  sysctl name=[");
                for (u_int i = 0; i < (u_int)arg2; i++) {
                    fprintf(stderr, "%s%d", i ? "." : "", name_ptr[i]);
                }
                fprintf(stderr, "]\n");
            }

            ret = get_errno(sysctl(name_ptr, (u_int)arg2, old_ptr,
                                   oldlen_ptr, new_ptr, (size_t)arg6));
        }
        break;

    case TARGET_MACOS_NR_sysctlbyname:
        /* sysctlbyname(const char *name, void *oldp, size_t *oldlenp,
         *              void *newp, size_t newlen) */
        {
            char *name_str = NULL;
            void *old_ptr = NULL;
            size_t *oldlen_ptr = NULL;
            void *new_ptr = NULL;

            if (arg1) name_str = (char *)g2h_untagged(arg1);
            if (arg3) old_ptr = g2h_untagged(arg3);
            if (arg4) oldlen_ptr = (size_t *)g2h_untagged(arg4);
            if (arg5) new_ptr = g2h_untagged(arg5);

            ret = get_errno(sysctlbyname(name_str, old_ptr,
                                         oldlen_ptr, new_ptr, (size_t)arg6));
        }
        break;

    case TARGET_MACOS_NR_getaudit_addr:
        /*
         * getaudit_addr(auditinfo_addr_t *auditinfo_addr, u_int length)
         *
         * Retrieve audit session state.  LaunchServices needs the
         * audit session ID (ai_asid) to determine the login session.
         * Forward to host kernel with guest→host pointer translation.
         */
        ret = get_errno(syscall(SYS_getaudit_addr,
                                g2h_untagged(arg1), (unsigned int)arg2));
        break;

    case TARGET_MACOS_NR_csops:
    case TARGET_MACOS_NR_csops_audittoken:
        /*
         * csops(pid, ops, useraddr, usersize) — code signing operations.
         * Forward to host kernel so dyld gets valid code signing status.
         */
        {
            void *useraddr = NULL;
            if (arg3) {
                useraddr = g2h_untagged(arg3);
            }
            if ((pid_t)arg1 == getpid() &&
                (unsigned int)arg2 == CS_OPS_DER_ENTITLEMENTS_BLOB &&
                useraddr && (size_t)arg4 >=
                sizeof(qemu_macos_user_der_entitlements)) {
                memcpy(useraddr, qemu_macos_user_der_entitlements,
                       sizeof(qemu_macos_user_der_entitlements));
                ret = 0;
            } else {
                ret = get_errno(csops((pid_t)arg1, (unsigned int)arg2,
                                      useraddr, (size_t)arg4));
            }
        }
        break;

    case TARGET_MACOS_NR_shared_region_check_np:
        /*
         * shared_region_check_np(uint64_t *start_address)
         *
         * If the shared cache has been mapped via our
         * shared_region_map_and_slide_2_np handler, return
         * the base address.  Otherwise return EINVAL.
         * Special case: arg1 == -1 is disablePageInLinking.
         */
        if (arg1 == (abi_ulong)-1) {
            ret = 0;
        } else if (guest_shared_cache_addr && arg1) {
            uint64_t addr = guest_shared_cache_addr;
            memcpy(g2h_untagged(arg1), &addr, sizeof(addr));
            ret = 0;
        } else {
            ret = -TARGET_EINVAL;
        }
        break;

    case TARGET_MACOS_NR_crossarch_trap:
        /*
         * crossarch_trap(uint32_t name)
         * Used for cross-architecture traps. Returns ENOTSUP in XNU.
         */
        ret = -TARGET_ENOSYS;
        break;

    case TARGET_MACOS_NR_audit_session_self:
        /*
         * audit_session_self(void)
         *
         * LaunchServices uses the current audit session while checking in
         * GUI apps and constructing its per-session XPC service connection.
         */
        ret = get_errno(syscall(SYS_audit_session_self));
        break;

    case TARGET_MACOS_NR___mac_syscall:
        /*
         * __mac_syscall(const char *policy, int call, void *arg)
         * MAC framework syscall — used for sandbox checks.
         * Return 0 (no restrictions) in emulation.
         */
        ret = 0;
        break;

    case TARGET_MACOS_NR_fsgetpath:
        /*
         * fsgetpath(char *buf, size_t buflen, fsid_t *fsid, uint64_t objid)
         * Convert filesystem ID + object ID to a path.
         * Forward to host kernel with proper guest pointer translation.
         */
        {
            char *buf = arg1 ? (char *)g2h_untagged(arg1) : NULL;
            void *fsid = arg3 ? g2h_untagged(arg3) : NULL;
            ret = get_errno(syscall(SYS_fsgetpath, buf, (size_t)arg2,
                                    fsid, (uint64_t)arg4));
        }
        break;

    case 483: /* __nexus_register — stub */
        ret = -TARGET_ENOSYS;
        break;

    case 336: /* proc_info */
        /*
         * proc_info(int callnum, int pid, uint32_t flavor,
         *           uint64_t arg, void *buffer, int buffersize)
         * Forward most calls to host; stub SET_DYLD_IMAGES (callnum 15)
         * which notifies the kernel about loaded images.
         */
        {
            int callnum = (int)arg1;
            if (callnum == 0xf) {
                /* PROC_INFO_CALL_SET_DYLD_IMAGES — stub success */
                ret = 0;
            } else {
                void *buf = arg5 ? g2h_untagged(arg5) : NULL;
                ret = get_errno(syscall(336, callnum, (int)arg2,
                                        (uint32_t)arg3, (uint64_t)arg4,
                                        buf, (int)arg6));
            }
        }
        break;

    case TARGET_MACOS_NR_shared_region_map_and_slide_2_np:
        /*
         * shared_region_map_and_slide_2_np(files_count, files,
         *                                  mappings_count, mappings)
         *
         * Two-pass emulation of the XNU shared-region syscall:
         *  Pass 1 - mmap every segment (with PROT_WRITE for those
         *           needing fixups).
         *  Pass 2 - read the slide info from the now-mapped memory
         *           (sms_slide_start is a guest VA, like the kernel's
         *           copyin), apply chained fixups + PAC signing, then
         *           set final protection.
         */
        {
            uint32_t files_count = (uint32_t)arg1;
            uint32_t mappings_count = (uint32_t)arg3;

            if (!arg2 || !arg4 || files_count == 0 || mappings_count == 0) {
                ret = -TARGET_EINVAL;
                break;
            }

            struct {
                int32_t  sf_fd;
                uint32_t sf_mappings_count;
                uint32_t sf_slide;
            } *files_arr = g2h_untagged(arg2);

            struct {
                uint64_t sms_address;
                uint64_t sms_size;
                uint64_t sms_file_offset;
                uint64_t sms_slide_size;
                uint64_t sms_slide_start;
                int32_t  sms_max_prot;
                int32_t  sms_init_prot;
            } *maps_arr = g2h_untagged(arg4);

            /*
             * Build a per-mapping slide value from the per-file slide.
             * We need this in pass 2, so compute it now.
             */
            uint32_t *slide_per_map = g_new0(uint32_t, mappings_count);
            {
                uint32_t mi2 = 0;
                for (uint32_t fi = 0;
                     fi < files_count && mi2 < mappings_count; fi++) {
                    uint32_t cnt = files_arr[fi].sf_mappings_count;
                    for (uint32_t j = 0;
                         j < cnt && mi2 < mappings_count; j++, mi2++) {
                        slide_per_map[mi2] = files_arr[fi].sf_slide;
                    }
                }
            }

            /* ---- Pass 1: map every segment ---- */
            uint32_t mi = 0;
            ret = 0;
            for (uint32_t fi = 0; fi < files_count && mi < mappings_count; fi++) {
                int fd = files_arr[fi].sf_fd;
                uint32_t count = files_arr[fi].sf_mappings_count;
                for (uint32_t j = 0; j < count && mi < mappings_count; j++, mi++) {
                    uint64_t addr = maps_arr[mi].sms_address;
                    uint64_t size = maps_arr[mi].sms_size;
                    uint64_t off  = maps_arr[mi].sms_file_offset;
                    int iprot     = maps_arr[mi].sms_init_prot;
                    bool has_slide = (maps_arr[mi].sms_slide_size > 0 &&
                                     maps_arr[mi].sms_slide_start > 0);

                    int host_prot = 0;
                    if (iprot & 1) host_prot |= PROT_READ;
                    if (iprot & 2) host_prot |= PROT_WRITE;
                    if (iprot & 4) host_prot |= PROT_EXEC;

                    /* Need PROT_WRITE to apply fixups in pass 2 */
                    int map_prot = has_slide ?
                        (host_prot | PROT_WRITE) : host_prot;

                    void *host_addr = g2h_untagged(addr);
                    void *p;

                    if ((iprot & 0x10) || fd < 0) {
                        p = mmap(host_addr, size,
                                 PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                 -1, 0);
                        if (p != MAP_FAILED && fd < 0 && off != 0) {
                            void *src = g2h_untagged(off);
                            memcpy(p, src, size);
                        }
                        if (p != MAP_FAILED && host_prot &&
                            host_prot != (PROT_READ | PROT_WRITE)) {
                            mprotect(p, size, host_prot);
                        }
                    } else {
                        p = mmap(host_addr, size, map_prot,
                                 MAP_PRIVATE | MAP_FIXED, fd, off);
                    }

                    if (p == MAP_FAILED) {
                        fprintf(stderr, "qemu: shared_region mmap failed: "
                                "mi=%u addr=0x%llx size=0x%llx "
                                "off=0x%llx fd=%d prot=0x%x errno=%d\n",
                                mi,
                                (unsigned long long)addr,
                                (unsigned long long)size,
                                (unsigned long long)off,
                                fd, iprot, errno);
                        ret = -TARGET_ENOMEM;
                        break;
                    }

                    int qf = PAGE_VALID;
                    if (host_prot & PROT_READ)  qf |= PAGE_READ;
                    if (host_prot & PROT_WRITE) qf |= PAGE_WRITE;
                    if (host_prot & PROT_EXEC)  qf |= PAGE_EXEC;
                    mmap_lock();
                    page_set_flags(addr, addr + size - 1, qf, ~0);
                    mmap_unlock();
                }
            }

            /*
             * ---- Pass 2: apply chained fixups ----
             * sms_slide_start is a guest VA (the kernel uses copyin).
             * All mappings are now established so we can read the
             * slide info via g2h.
             */
            if (ret == 0) {
                for (mi = 0; mi < mappings_count; mi++) {
                    uint64_t slide_info_addr =
                        maps_arr[mi].sms_slide_start;
                    uint64_t slide_info_size =
                        maps_arr[mi].sms_slide_size;

                    if (slide_info_size == 0 || slide_info_addr == 0) {
                        continue;
                    }

                    void *slide_buf = g2h_untagged(slide_info_addr);
                    void *mapped = g2h_untagged(
                        maps_arr[mi].sms_address);

                    apply_slide_info_v5(
                        (CPUARMState *)cpu_env,
                        slide_buf, slide_info_size,
                        mapped,
                        maps_arr[mi].sms_address,
                        maps_arr[mi].sms_size,
                        slide_per_map[mi]);

                    if (do_strace) {
                        fprintf(stderr,
                                "qemu: applied slide fixups at "
                                "0x%llx (size=0x%llx)\n",
                                (unsigned long long)
                                    maps_arr[mi].sms_address,
                                (unsigned long long)
                                    maps_arr[mi].sms_size);
                    }

                    /* Restore read-only protection if needed */
                    int iprot = maps_arr[mi].sms_init_prot;
                    int host_prot = 0;
                    if (iprot & 1) host_prot |= PROT_READ;
                    if (iprot & 2) host_prot |= PROT_WRITE;
                    if (iprot & 4) host_prot |= PROT_EXEC;
                    if (!(host_prot & PROT_WRITE)) {
                        mprotect(mapped, maps_arr[mi].sms_size,
                                 host_prot);
                    }
                }
            }

            g_free(slide_per_map);

            /* Record the cache base for shared_region_check_np */
            if (ret == 0 && mappings_count > 0) {
                guest_shared_cache_addr = maps_arr[0].sms_address;
            }
        }
        break;

    case TARGET_MACOS_NR_shared_region_map_and_slide_np:
        /*
         * shared_region_map_and_slide_np (older variant)
         * Return ENOENT to force dyld's private mapping fallback.
         */
        ret = -TARGET_ENOENT;
        break;

    case TARGET_MACOS_NR_socket:
        /* socket(domain, type, protocol) — pass through to host */
        ret = get_errno(socket((int)arg1, (int)arg2, (int)arg3));
        break;

    case TARGET_MACOS_NR_connect:
    case TARGET_MACOS_NR_connect_nocancel:
        /* connect(fd, addr, addrlen) */
        {
            void *host_addr = g2h_untagged(arg2);
            ret = get_errno(connect((int)arg1,
                                    (struct sockaddr *)host_addr,
                                    (socklen_t)arg3));
        }
        break;

    case TARGET_MACOS_NR_sendto:
    case TARGET_MACOS_NR_sendto_nocancel:
        /* sendto(fd, buf, len, flags, dest_addr, addrlen) */
        {
            void *host_buf = g2h_untagged(arg2);
            void *host_dest = arg5 ? g2h_untagged(arg5) : NULL;
            ret = get_errno(sendto((int)arg1, host_buf, (size_t)arg3,
                                   (int)arg4,
                                   (struct sockaddr *)host_dest,
                                   (socklen_t)arg6));
        }
        break;

    case TARGET_MACOS_NR_sendmsg:
    case TARGET_MACOS_NR_sendmsg_nocancel:
        /* sendmsg(fd, msg, flags) — simplified: pass through */
        {
            struct msghdr *host_msg = g2h_untagged(arg2);
            ret = get_errno(sendmsg((int)arg1, host_msg, (int)arg3));
        }
        break;

    case TARGET_MACOS_NR_recvfrom:
    case TARGET_MACOS_NR_recvfrom_nocancel:
        /* recvfrom(fd, buf, len, flags, from, fromlen) */
        {
            void *host_buf = g2h_untagged(arg2);
            void *host_from = arg5 ? g2h_untagged(arg5) : NULL;
            void *host_fromlen = arg6 ? g2h_untagged(arg6) : NULL;
            ret = get_errno(recvfrom((int)arg1, host_buf, (size_t)arg3,
                                     (int)arg4,
                                     (struct sockaddr *)host_from,
                                     (socklen_t *)host_fromlen));
        }
        break;

    case TARGET_MACOS_NR_recvmsg:
    case TARGET_MACOS_NR_recvmsg_nocancel:
        /* recvmsg(fd, msg, flags) — simplified: pass through */
        {
            struct msghdr *host_msg = g2h_untagged(arg2);
            ret = get_errno(recvmsg((int)arg1, host_msg, (int)arg3));
        }
        break;

    case TARGET_MACOS_NR_select:
    case TARGET_MACOS_NR_select_nocancel:
        /* select(nfds, readfds, writefds, exceptfds, timeout) */
        {
            fd_set *rfds = arg2 ? g2h_untagged(arg2) : NULL;
            fd_set *wfds = arg3 ? g2h_untagged(arg3) : NULL;
            fd_set *efds = arg4 ? g2h_untagged(arg4) : NULL;
            struct timeval *tv = arg5 ? g2h_untagged(arg5) : NULL;
            ret = get_errno(select((int)arg1, rfds, wfds, efds, tv));
        }
        break;

    case TARGET_MACOS_NR_poll:
    case TARGET_MACOS_NR_poll_nocancel:
        /* poll(fds, nfds, timeout) */
        {
            struct pollfd *host_fds = g2h_untagged(arg1);
            ret = get_errno(poll(host_fds, (nfds_t)arg2, (int)arg3));
        }
        break;

    case TARGET_MACOS_NR_shm_open:
        /* shm_open(name, oflag, mode) */
        {
            char *name = lock_user_string(arg1);
            if (!name) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(shm_open(name, (int)arg2, (mode_t)arg3));
                unlock_user(name, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getdirentries64:
        /*
         * getdirentries64(fd, buf, bufsize, position)
         * Returns directory entries in struct dirent format.
         */
        {
            void *buf = lock_user(VERIFY_WRITE, arg2, arg3, 0);
            if (!buf) {
                ret = -TARGET_EFAULT;
            } else {
                /*
                 * macOS getdirentries is __getdirentries64 under the hood.
                 * Use the SYS_getdirentries64 syscall directly.
                 */
                off_t basep = 0;
                ret = get_errno(syscall(SYS_getdirentries64,
                                        (int)arg1, buf, arg3, &basep));
                if (arg4 && ret >= 0) {
                    *(uint64_t *)g2h_untagged(arg4) = basep;
                }
                unlock_user(buf, arg2, ret > 0 ? ret : 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getattrlist:
        /*
         * getattrlist(path, attrlist, attrbuf, attrbufsize, options)
         * Used by libc for various file operations.
         */
        {
            char *path = lock_user_string(arg1);
            void *attrlist = g2h_untagged(arg2);
            void *attrbuf = lock_user(VERIFY_WRITE, arg3, arg4, 0);
            if (!path || !attrbuf) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(getattrlist(path, attrlist,
                                            attrbuf, arg4,
                                            (unsigned int)arg5));
            }
            if (path) {
                unlock_user(path, arg1, 0);
            }
            if (attrbuf) {
                unlock_user(attrbuf, arg3, ret == 0 ? arg4 : 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fgetattrlist:
        /*
         * fgetattrlist(fd, attrlist, attrbuf, attrbufsize, options)
         */
        {
            void *attrlist = g2h_untagged(arg2);
            void *attrbuf = lock_user(VERIFY_WRITE, arg3, arg4, 0);
            if (!attrbuf) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(fgetattrlist((int)arg1, attrlist,
                                             attrbuf, arg4,
                                             (unsigned int)arg5));
                unlock_user(attrbuf, arg3, ret == 0 ? arg4 : 0);
            }
        }
        break;

    case TARGET_MACOS_NR_setattrlist:
        /*
         * setattrlist(path, attrlist, attrbuf, attrbufsize, options)
         */
        {
            char *path = lock_user_string(arg1);
            void *attrlist = g2h_untagged(arg2);
            void *attrbuf = g2h_untagged(arg3);
            if (!path) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(setattrlist(path, attrlist,
                                            attrbuf, arg4,
                                            (unsigned int)arg5));
                unlock_user(path, arg1, 0);
            }
        }
        break;

    case TARGET_MACOS_NR_getattrlistbulk:
        /*
         * getattrlistbulk(dirfd, attrlist, attrbuf, attrbufsize, options)
         * Returns multiple directory entries with attributes.
         */
        {
            void *attrlist = g2h_untagged(arg2);
            void *attrbuf = lock_user(VERIFY_WRITE, arg3, arg4, 0);
            if (!attrbuf) {
                ret = -TARGET_EFAULT;
            } else {
                ret = get_errno(getattrlistbulk((int)arg1, attrlist,
                                                attrbuf, arg4,
                                                (uint64_t)arg5));
                unlock_user(attrbuf, arg3, ret > 0 ? arg4 : 0);
            }
        }
        break;

    case TARGET_MACOS_NR_fstatfs64:
        /*
         * fstatfs64(fd, buf)
         */
        {
            struct statfs host_buf;
            ret = get_errno(fstatfs((int)arg1, &host_buf));
            if (ret == 0) {
                void *buf = lock_user(VERIFY_WRITE, arg2,
                                      sizeof(struct statfs), 0);
                if (!buf) {
                    ret = -TARGET_EFAULT;
                } else {
                    memcpy(buf, &host_buf, sizeof(struct statfs));
                    unlock_user(buf, arg2, sizeof(struct statfs));
                }
            }
        }
        break;

    case TARGET_MACOS_NR_getfsstat64:
        /*
         * getfsstat64(buf, bufsize, flags)
         */
        {
            if (arg1 == 0) {
                /* Query count only */
                ret = get_errno(getfsstat(NULL, 0, (int)arg3));
            } else {
                void *buf = lock_user(VERIFY_WRITE, arg1, arg2, 0);
                if (!buf) {
                    ret = -TARGET_EFAULT;
                } else {
                    ret = get_errno(getfsstat(buf, (int)arg2, (int)arg3));
                    unlock_user(buf, arg1, arg2);
                }
            }
        }
        break;

    case TARGET_MACOS_NR_abort_with_payload:
    case TARGET_MACOS_NR_terminate_with_payload:
        /*
         * abort_with_payload(reason_namespace, reason_code,
         *                    payload, payload_size,
         *                    reason_string, reason_flags)
         */
        {
            const char *reason = arg5
                ? (const char *)g2h_untagged(arg5) : "(null)";
            CPUArchState *env = (CPUArchState *)cpu_env;
            abi_ulong tsd_base = env->cp15.tpidrro_el[0];
            uint64_t pthread_self_slot = 0;
            uint64_t mach_self_slot = 0;
            uint64_t ptr_munge_slot = 0;
            uint64_t pthread_sig = 0;

            if (tsd_base &&
                guest_range_valid_untagged(tsd_base, 8 * sizeof(uint64_t))) {
                uint64_t *tsd = g2h_untagged(tsd_base);
                pthread_self_slot = tsd[0];
                mach_self_slot = tsd[3];
                ptr_munge_slot = tsd[7];
                if (pthread_self_slot &&
                    guest_range_valid_untagged(pthread_self_slot,
                                               sizeof(uint64_t))) {
                    pthread_sig = *(uint64_t *)g2h_untagged(pthread_self_slot);
                }
            }
            fprintf(stderr, "abort_with_payload: ns=%lu code=0x%lx "
                    "reason=\"%s\" tpidr=0x%llx tpidrro=0x%llx "
                    "pthread_self=0x%llx sig=0x%llx mach_self=0x%llx "
                    "ptr_munge=0x%llx\n",
                    (unsigned long)arg1, (unsigned long)arg2, reason,
                    (unsigned long long)env->cp15.tpidr_el[0],
                    (unsigned long long)tsd_base,
                    (unsigned long long)pthread_self_slot,
                    (unsigned long long)pthread_sig,
                    (unsigned long long)mach_self_slot,
                    (unsigned long long)ptr_munge_slot);
        }
        _exit(arg1 ? (int)arg1 : 1);
        break;

    default:
        qemu_log_mask(LOG_UNIMP, "Unsupported macOS syscall: %d\n", num);
        ret = -TARGET_ENOSYS;
        break;
    }

    if (do_strace) {
        print_syscall_ret(cpu, num, ret, arg1, arg2, arg3, arg4, arg5, arg6);
    }

    return ret;
}
