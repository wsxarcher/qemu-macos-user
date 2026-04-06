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
#include <mach/mach_vm.h>
#include "qemu.h"
#include "user/guest-host.h"
#include "user-internals.h"
#include "strace.h"
#include "signal-common.h"
#include "exec/mmap-lock.h"
#include "user/page-protection.h"

/* csops is a private syscall, declare it here */
extern int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

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
#define EVFILT_WORKLOOP_PRIVATE (-17)

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

/*
 * Workloop → port mapping.  When kevent_id registers a MACHPORT on a
 * workloop, we record the (workloop_id, port) pair so the monitor thread
 * can deliver MACHPORT events as workloop-thread events.
 */
#define MAX_WORKLOOP_PORTS 64
typedef struct {
    uint64_t workloop_id;
    mach_port_t port;
} workloop_port_entry;

static workloop_port_entry workloop_ports[MAX_WORKLOOP_PORTS];
static int workloop_port_count = 0;
static pthread_mutex_t workloop_port_lock = PTHREAD_MUTEX_INITIALIZER;

static void add_workloop_port(uint64_t wl_id, mach_port_t port)
{
    pthread_mutex_lock(&workloop_port_lock);
    /* Update existing entry for this port */
    for (int i = 0; i < workloop_port_count; i++) {
        if (workloop_ports[i].port == port) {
            workloop_ports[i].workloop_id = wl_id;
            pthread_mutex_unlock(&workloop_port_lock);
            return;
        }
    }
    if (workloop_port_count < MAX_WORKLOOP_PORTS) {
        workloop_ports[workloop_port_count].workloop_id = wl_id;
        workloop_ports[workloop_port_count].port = port;
        workloop_port_count++;
    }
    pthread_mutex_unlock(&workloop_port_lock);
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
                               abi_ulong wq_sbot, abi_ulong wq_tsd);

static void deliver_kevents_to_thread(struct kevent_qos_s *events,
                                      int nevents);
static void deliver_workloop_events_to_thread(uint64_t workloop_id,
                                               struct kevent_qos_s *events,
                                               int nevents);

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
        if (changelist[i].filter == EVFILT_MACHPORT) {
            struct kevent64_s k64;
            kqos_to_k64(&changelist[i], &k64);
            int rc = kevent64(kq, &k64, 1, NULL, 0, 0, NULL);
            if (rc < 0) {
                if (do_strace) {
                    fprintf(stderr, "  workq_kqueue_register: "
                            "MACHPORT ident=0x%llx failed errno=%d\n",
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
static abi_ulong prereceive_one_msg(mach_port_t port,
                                    mach_msg_size_t hint_size)
{
    mach_msg_size_t buf_size = hint_size + MAX_TRAILER_SIZE;
    if (buf_size < 4096) {
        buf_size = 4096;
    }
    void *buf = g_malloc0(buf_size);
    mach_msg_header_t *hdr = (mach_msg_header_t *)buf;

    kern_return_t kr = mach_msg(hdr,
        MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
        0, buf_size, port, 100 /* 100ms timeout */, MACH_PORT_NULL);

    if (kr == MACH_RCV_TOO_LARGE) {
        buf_size = hdr->msgh_size + MAX_TRAILER_SIZE;
        buf = g_realloc(buf, buf_size);
        hdr = (mach_msg_header_t *)buf;
        kr = mach_msg(hdr, MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_TIMEOUT,
                      0, buf_size, port, 100, MACH_PORT_NULL);
    }

    if (kr != KERN_SUCCESS) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    mach_msg_size_t received_size = hdr->msgh_size + MAX_TRAILER_SIZE;
    mmap_lock();
    abi_ulong guest_buf = target_mmap(0, received_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    mmap_unlock();

    if (guest_buf == (abi_ulong)-1) {
        g_free(buf);
        return (abi_ulong)-1;
    }

    memcpy(g2h_untagged(guest_buf), buf, received_size);

    /* Fix up OOL descriptors */
    if (guest_base && (hdr->msgh_bits & MACH_MSGH_BITS_COMPLEX)) {
        mach_msg_header_t *gh =
            (mach_msg_header_t *)g2h_untagged(guest_buf);
        mach_msg_body_t *body = (mach_msg_body_t *)(gh + 1);
        uint8_t *dp = (uint8_t *)(body + 1);
        for (uint32_t i = 0; i < body->msgh_descriptor_count; i++) {
            mach_msg_type_descriptor_t *td =
                (mach_msg_type_descriptor_t *)dp;
            if (td->type == MACH_MSG_OOL_DESCRIPTOR ||
                td->type == MACH_MSG_OOL_VOLATILE_DESCRIPTOR) {
                mach_msg_ool_descriptor_t *ool =
                    (mach_msg_ool_descriptor_t *)dp;
                void *host_addr = ool->address;
                mach_msg_size_t sz = ool->size;
                if (host_addr && sz > 0) {
                    mmap_lock();
                    abi_long ga = target_mmap(0, sz,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    mmap_unlock();
                    if (ga > 0) {
                        memcpy(g2h_untagged(ga), host_addr, sz);
                        munmap(host_addr, sz);
                        ool->address = (void *)(uintptr_t)ga;
                    }
                }
                dp += sizeof(mach_msg_ool_descriptor_t);
            } else if (td->type == MACH_MSG_OOL_PORTS_DESCRIPTOR) {
                dp += sizeof(mach_msg_ool_ports_descriptor_t);
            } else if (td->type == MACH_MSG_PORT_DESCRIPTOR) {
                dp += sizeof(mach_msg_port_descriptor_t);
            } else {
                dp += sizeof(mach_msg_type_descriptor_t);
            }
        }
    }

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: prereceived port 0x%x "
                "msg_size=%u id=%u -> guest 0x%llx\n",
                port, hdr->msgh_size, hdr->msgh_id,
                (unsigned long long)guest_buf);
    }

    g_free(buf);
    return guest_buf;
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
    mach_port_t port = (mach_port_t)template_kev->ident;
    mach_msg_size_t hint = (mach_msg_size_t)template_kev->data;
    int count = 0;

    while (count < max_events) {
        abi_ulong guest_buf = prereceive_one_msg(port, hint);
        if (guest_buf == (abi_ulong)-1) {
            break;
        }
        /* Build kevent for this message */
        out_events[count] = *template_kev;
        out_events[count].fflags = 0;
        mach_msg_header_t *gh =
            (mach_msg_header_t *)g2h_untagged(guest_buf);
        out_events[count].data = gh->msgh_size;
        out_events[count].ext[0] = (uint64_t)guest_buf;
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

    rcu_register_thread();

    while (1) {
        int n = kevent64(kq, NULL, 0, events64, 8, 0, NULL);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            usleep(10000);
            continue;
        }
        if (n == 0) {
            continue;
        }

        /* Convert to kevent_qos_s for the guest */
        for (int i = 0; i < n; i++) {
            k64_to_kqos(&events64[i], &events_qos[i]);
        }

        if (do_strace) {
            fprintf(stderr, "  workq_monitor: %d events fired\n", n);
            for (int i = 0; i < n; i++) {
                fprintf(stderr, "    event[%d]: filter=%d ident=0x%llx "
                        "flags=0x%x fflags=0x%x data=%lld\n",
                        i, events_qos[i].filter,
                        (unsigned long long)events_qos[i].ident,
                        events_qos[i].flags, events_qos[i].fflags,
                        (long long)events_qos[i].data);
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
        struct kevent_qos_s drain_buf[16];
        int total_drained = 0;

        for (int i = 0; i < n; i++) {
            if (events_qos[i].filter == EVFILT_MACHPORT) {
                int got = prereceive_machport_drain(&events_qos[i],
                    &drain_buf[total_drained],
                    16 - total_drained);
                if (got > 0) {
                    total_drained += got;
                } else if (total_drained < 16) {
                    /* Pre-receive failed — deliver raw event anyway */
                    drain_buf[total_drained++] = events_qos[i];
                }

                /*
                 * Re-arm the kevent (EV_ENABLE) so it fires again if
                 * more messages arrive.  EVFILT_MACHPORT with
                 * EV_DISPATCH is one-shot; we must re-enable it.
                 */
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
            } else {
                /* Non-MACHPORT event, pass through */
                if (total_drained < 16) {
                    drain_buf[total_drained++] = events_qos[i];
                }
            }
        }

        if (total_drained > 0) {
            /*
             * Check if ANY of the fired ports belong to a workloop.
             * If so, deliver as workloop events (WQ_FLAG_THREAD_WORKLOOP).
             * Otherwise deliver as regular kevent events.
             */
            uint64_t wl_id = 0;
            for (int i = 0; i < n; i++) {
                if (events_qos[i].filter == EVFILT_MACHPORT) {
                    wl_id = find_workloop_for_port(
                        (mach_port_t)events_qos[i].ident);
                    if (wl_id) break;
                }
            }
            if (wl_id) {
                deliver_workloop_events_to_thread(wl_id,
                    drain_buf, total_drained);
            } else {
                deliver_kevents_to_thread(drain_buf, total_drained);
            }
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
        }

        pthread_mutex_lock(&pk->mutex);
        pk->has_work = true;
        pthread_cond_signal(&pk->cond);
        pthread_mutex_unlock(&pk->mutex);
        return;
    }

    /* No parked kevent thread — create a new workqueue thread */
    if (!saved_wqthread || !workq_monitor_parent_env) {
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

    /* Copy events onto the new thread's stack (below stack_top) */
    size_t events_sz = nevents * sizeof(struct kevent_qos_s);
    abi_ulong sp = stack_top;
    sp -= events_sz;
    sp &= ~(abi_ulong)0xF;
    memcpy(g2h_untagged(sp), events, events_sz);
    abi_ulong keventlist = sp;

    sp -= 256;  /* headroom */
    sp &= ~(abi_ulong)0xF;

    uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                   | WQ_FLAG_THREAD_TSD_BASE_SET
                   | WQ_FLAG_THREAD_PRIO_QOS
                   | WQ_FLAG_THREAD_KEVENT
                   | 4;  /* QoS default */

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: creating kevent thread "
                "self=0x%lx sp=0x%lx keventlist=0x%lx "
                "nevents=%d flags=0x%x\n",
                (unsigned long)self_addr, (unsigned long)sp,
                (unsigned long)keventlist, nevents, flags);
    }

    create_guest_thread(
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
        stack_bottom, tsd_base);
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
    /* Try to wake a parked workloop thread first */
    parked_workloop_wq *pw = NULL;
    pthread_mutex_lock(&parked_workloop_lock);
    if (parked_workloop_list) {
        pw = parked_workloop_list;
        parked_workloop_list = pw->next;
        pw->next = NULL;
    }
    pthread_mutex_unlock(&parked_workloop_lock);

    if (pw) {
        pw->delivered_events = (events && nevents > 0)
            ? g_memdup2(events, nevents * sizeof(struct kevent_qos_s))
            : NULL;
        pw->delivered_nevents = nevents;
        pw->workloop_id = workloop_id;

        if (do_strace) {
            fprintf(stderr, "  workq_monitor: waking parked workloop "
                    "thread self=0x%lx wl=0x%llx with %d events\n",
                    (unsigned long)pw->self_addr,
                    (unsigned long long)workloop_id, nevents);
        }

        pthread_mutex_lock(&pw->mutex);
        pw->has_work = true;
        pthread_cond_signal(&pw->cond);
        pthread_mutex_unlock(&pw->mutex);
        return;
    }

    /* No parked workloop thread — create a new one */
    if (!saved_wqthread || !workq_monitor_parent_env) {
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
    size_t events_sz = nevents * sizeof(struct kevent_qos_s);
    abi_ulong sp = stack_top;
    /* Reserve space for kqueue_id_t + events */
    sp -= sizeof(uint64_t) + events_sz;
    sp &= ~(abi_ulong)0xF;

    /* Write kqueue_id_t first, then events */
    abi_ulong kqid_addr = sp;
    abi_ulong keventlist = sp + sizeof(uint64_t);
    *(uint64_t *)g2h_untagged(kqid_addr) = workloop_id;
    if (events && events_sz > 0) {
        memcpy(g2h_untagged(keventlist), events, events_sz);
    }

    sp -= 256;  /* headroom */
    sp &= ~(abi_ulong)0xF;

    uint32_t flags = WQ_FLAG_THREAD_NEWSPI
                   | WQ_FLAG_THREAD_TSD_BASE_SET
                   | WQ_FLAG_THREAD_PRIO_QOS
                   | WQ_FLAG_THREAD_WORKLOOP
                   | 4;  /* QoS default */

    if (do_strace) {
        fprintf(stderr, "  workq_monitor: creating workloop thread "
                "self=0x%lx sp=0x%lx keventlist=0x%lx "
                "wl=0x%llx nevents=%d flags=0x%x\n",
                (unsigned long)self_addr, (unsigned long)sp,
                (unsigned long)keventlist,
                (unsigned long long)workloop_id, nevents, flags);
    }

    create_guest_thread(
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
        stack_bottom, tsd_base);
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

/*
 * Host thread function for new guest threads.
 * Clones CPU state and enters cpu_loop.
 */
static void *guest_thread_func(void *arg)
{
    new_thread_info *info = arg;
    CPUArchState *env;
    CPUState *cpu;
    TaskState *ts;

    rcu_register_thread();
    tcg_register_thread();

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
    }

    /*
     * Set x1 = mach_thread_self() for this thread.
     * XNU sets kport to the new thread's own Mach port.
     * We must call mach_thread_self() here (on the worker thread)
     * rather than from the parent, otherwise os_unfair_lock sees the
     * main thread's port and falsely detects recursion.
     */
    env->xregs[1] = (abi_ulong)mach_thread_self();

    /* Signal parent that we're ready */
    pthread_mutex_lock(&info->mutex);
    pthread_cond_broadcast(&info->cond);
    pthread_mutex_unlock(&info->mutex);

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
                               abi_ulong wq_sbot, abi_ulong wq_tsd)
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
     * Set up TPIDRRO_EL0 for the new thread.
     * For workqueue threads, tsd_base = self + tsd_offset.
     * The kernel sets this via thread_set_tsd_base().
     */
    new_env->cp15.tpidrro_el[0] = tsd_base;

    /* Prepare thread info for synchronization */
    memset(&info, 0, sizeof(info));
    pthread_mutex_init(&info.mutex, NULL);
    pthread_mutex_lock(&info.mutex);
    pthread_cond_init(&info.cond, NULL);
    info.env = new_env;
    info.parent_ts = parent_ts;
    info.is_workqueue = is_workqueue;
    info.wq_self_addr = wq_self;
    info.wq_stack_top = wq_stop;
    info.wq_stack_bottom = wq_sbot;
    info.wq_tsd_base = wq_tsd;

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
    /* dyld_cache_slide_info5 header (20 bytes) */
    if (slide_len < 20) {
        return;
    }
    uint32_t version, page_size, page_starts_count;
    uint64_t value_add;
    memcpy(&version, slide_buf, 4);
    memcpy(&page_size, slide_buf + 4, 4);
    memcpy(&page_starts_count, slide_buf + 8, 4);
    /* 4 bytes padding at offset 12 */
    memcpy(&value_add, slide_buf + 16, 8);

    if (version != 5 || page_size == 0 || page_starts_count == 0) {
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
        if (page_off + start >= region_size) {
            break;
        }

        uint8_t *loc = (uint8_t *)mapped_host + page_off;
        uint64_t delta = start;

        do {
            loc += delta;
            uint64_t raw;
            memcpy(&raw, loc, 8);

            /* Extract chain-next delta (bits 62:52, in 8-byte units) */
            delta = ((raw & 0x7FF0000000000000ULL) >> 52) * 8;

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
                        (uint64_t)((uint8_t *)loc - (uint8_t *)mapped_host);
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
        } while (delta != 0);
    }
}

/* Syscall implementation */

/* Guest address of the mapped shared cache (0 = not yet mapped) */
static uint64_t guest_shared_cache_addr;

abi_long do_macos_syscall(void *cpu_env, int num, abi_long arg1,
                          abi_long arg2, abi_long arg3, abi_long arg4,
                          abi_long arg5, abi_long arg6, abi_long arg7,
                          abi_long arg8)
{
    CPUState *cpu = env_cpu(cpu_env);
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
        /* gettimeofday(struct timeval *tv, struct timezone *tz) */
        {
            struct timeval tv;
            ret = get_errno(gettimeofday(&tv, NULL));
            if (!is_error(ret)) {
                if (arg1 && copy_to_user_timeval(arg1, &tv)) {
                    ret = -TARGET_EFAULT;
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
         * Used by pthread_cond_wait/timed-wait internals.  The semaphore
         * arguments are Mach port names.  We can't forward these to the
         * host kernel because the port namespace is guest-local.
         *
         * If there's a timeout, sleep for the requested duration and
         * return ETIMEDOUT.  Otherwise do a short sleep and return EINTR
         * to let the caller retry.
         */
        {
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
                /* Tiny sleep to avoid busy-spinning */
                struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000000 };
                nanosleep(&ts, NULL);
                ret = -TARGET_EINTR;
            }
        }
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
        /* __ulock_wait(uint32_t op, void *addr, uint64_t value,
         *              uint32_t timeout_us) */
        ret = get_errno(syscall(SYS_ulock_wait,
                                (uint32_t)arg1,
                                g2h_untagged(arg2),
                                (uint64_t)arg3,
                                (uint32_t)arg4));
        break;

    case TARGET_MACOS_NR_ulock_wake:
        /* __ulock_wake(uint32_t op, void *addr, uint64_t wake_value) */
        ret = get_errno(syscall(SYS_ulock_wake,
                                (uint32_t)arg1,
                                g2h_untagged(arg2),
                                (uint64_t)arg3));
        break;

    case TARGET_MACOS_NR_ulock_wait2:
        /* __ulock_wait2(uint32_t op, void *addr, uint64_t value,
         *               uint64_t timeout_ns, uint64_t value2) */
        ret = get_errno(syscall(SYS_ulock_wait2,
                                (uint32_t)arg1,
                                g2h_untagged(arg2),
                                (uint64_t)arg3,
                                (uint64_t)arg4,
                                (uint64_t)arg5));
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

            /* Allocate a guest stack */
            abi_ulong stack_top = alloc_thread_stack(WQ_STACK_SIZE);
            if (!stack_top) {
                ret = -TARGET_ENOMEM;
                break;
            }
            abi_ulong stack_bottom = stack_top - WQ_STACK_SIZE;
            abi_ulong sp = stack_top & ~0xFULL;

            TaskState *parent_ts = get_task_state(
                env_cpu((CPUArchState *)cpu_env));

            /*
             * threadstart calling convention:
             *   x0 = pthread_self (use the thread pointer arg4)
             *   x1 = mach_thread_self port
             *   x2 = start function (arg1)
             *   x3 = start arg (arg2)
             *   x4 = stacksize
             *   x5 = flags (arg5)
             */
            int rc = create_guest_thread(
                (CPUArchState *)cpu_env,
                saved_threadstart,  /* PC = threadstart callback */
                sp,
                arg4 ? arg4 : stack_bottom, /* x0 = pthread_self */
                0,                          /* x1 = kport (set by worker) */
                arg1,                       /* x2 = start func */
                arg2,                       /* x3 = start arg */
                WQ_STACK_SIZE,              /* x4 = stacksize */
                arg5,                       /* x5 = flags */
                arg4 ? arg4 : stack_bottom, /* tsd_base = self */
                parent_ts,
                false, 0, 0, 0, 0);        /* not a wq thread */

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
                        stack_bottom, tsd_base);

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
                 * Thread is done with work.  The real kernel parks the
                 * thread (blocks it) until new work arrives, rather than
                 * destroying it.  We emulate this with a condvar wait.
                 *
                 * When WQOPS_QUEUE_REQTHREADS finds a parked thread,
                 * it fills in new_flags and signals the condvar.  The
                 * thread then re-enters the wqthread entry point with
                 * WQ_FLAG_THREAD_REUSE set.
                 */
                parked_wq_thread pw;
                memset(&pw, 0, sizeof(pw));
                pthread_mutex_init(&pw.mutex, NULL);
                pthread_cond_init(&pw.cond, NULL);
                pw.env = (CPUArchState *)cpu_env;
                pw.has_work = false;

                /* Read stack geometry from TaskState */
                TaskState *ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));
                pw.self_addr = ts->wq_self_addr;
                pw.stack_top = ts->wq_stack_top;
                pw.stack_bottom = ts->wq_stack_bottom;
                pw.tsd_base = ts->wq_tsd_base;

                /* Add to parked list */
                pthread_mutex_lock(&parked_lock);
                pw.next = parked_list;
                parked_list = &pw;
                pthread_mutex_unlock(&parked_lock);

                /* Wait for new work */
                pthread_mutex_lock(&pw.mutex);
                while (!pw.has_work) {
                    pthread_cond_wait(&pw.cond, &pw.mutex);
                }
                pthread_mutex_unlock(&pw.mutex);

                /* Re-dispatch: set up registers for wqthread re-entry */
                CPUArchState *env = (CPUArchState *)cpu_env;
                env->pc = saved_wqthread;
                env->xregs[31] = pw.stack_top;
                env->xregs[0] = pw.self_addr;
                env->xregs[1] = (abi_ulong)mach_thread_self();
                env->xregs[2] = pw.stack_bottom;
                env->xregs[3] = 0;  /* keventlist */
                env->xregs[4] = pw.new_flags;
                env->xregs[5] = 0;  /* nkevents */
                env->xregs[29] = 0; /* FP */
                env->xregs[30] = 0; /* LR */

                pthread_mutex_destroy(&pw.mutex);
                pthread_cond_destroy(&pw.cond);

                ret = -TARGET_EJUSTRETURN;
                break;
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

                if (do_strace) {
                    fprintf(stderr, "  WQOPS_THREAD_WORKLOOP_RETURN: "
                            "nchanges=%d\n", nchanges);
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

                TaskState *ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));
                pw.self_addr = ts->wq_self_addr;
                pw.stack_top = ts->wq_stack_top;
                pw.stack_bottom = ts->wq_stack_bottom;
                pw.tsd_base = ts->wq_tsd_base;

                pthread_mutex_lock(&parked_workloop_lock);
                pw.next = parked_workloop_list;
                parked_workloop_list = &pw;
                pthread_mutex_unlock(&parked_workloop_lock);

                /* Wait for events from monitor thread */
                pthread_mutex_lock(&pw.mutex);
                while (!pw.has_work) {
                    pthread_cond_wait(&pw.cond, &pw.mutex);
                }
                pthread_mutex_unlock(&pw.mutex);

                /* Copy delivered events to guest stack with wl ID */
                CPUArchState *env = (CPUArchState *)cpu_env;
                size_t ev_sz = pw.delivered_nevents
                             * sizeof(struct kevent_qos_s);
                abi_ulong sp = pw.stack_top;
                sp -= sizeof(uint64_t) + ev_sz;
                sp &= ~(abi_ulong)0xF;

                abi_ulong kqid_addr = sp;
                abi_ulong keventlist = sp + sizeof(uint64_t);
                *(uint64_t *)g2h_untagged(kqid_addr) = pw.workloop_id;
                memcpy(g2h_untagged(keventlist),
                       pw.delivered_events, ev_sz);
                sp -= 256;
                sp &= ~(abi_ulong)0xF;

                uint32_t reuse_flags = WQ_FLAG_THREAD_WORKLOOP
                    | WQ_FLAG_THREAD_REUSE
                    | WQ_FLAG_THREAD_NEWSPI
                    | WQ_FLAG_THREAD_PRIO_QOS | 4;

                env->pc = saved_wqthread;
                env->xregs[31] = sp;
                env->xregs[0] = pw.self_addr;
                env->xregs[1] = (abi_ulong)mach_thread_self();
                env->xregs[2] = pw.stack_bottom;
                env->xregs[3] = keventlist;
                env->xregs[4] = reuse_flags;
                env->xregs[5] = pw.delivered_nevents;
                env->xregs[29] = 0;
                env->xregs[30] = 0;

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

                /* Copy delivered events to guest stack */
                CPUArchState *env = (CPUArchState *)cpu_env;
                size_t ev_sz = pk.delivered_nevents
                             * sizeof(struct kevent_qos_s);
                abi_ulong sp = pk.stack_top;
                sp -= ev_sz;
                sp &= ~(abi_ulong)0xF;
                memcpy(g2h_untagged(sp), pk.delivered_events, ev_sz);
                abi_ulong keventlist = sp;
                sp -= 256;
                sp &= ~(abi_ulong)0xF;

                uint32_t reuse_flags = WQ_FLAG_THREAD_KEVENT
                    | WQ_FLAG_THREAD_REUSE
                    | WQ_FLAG_THREAD_NEWSPI
                    | WQ_FLAG_THREAD_PRIO_QOS | 4;

                env->pc = saved_wqthread;
                env->xregs[31] = sp;
                env->xregs[0] = pk.self_addr;
                env->xregs[1] = (abi_ulong)mach_thread_self();
                env->xregs[2] = pk.stack_bottom;
                env->xregs[3] = keventlist;
                env->xregs[4] = reuse_flags;
                env->xregs[5] = pk.delivered_nevents;
                env->xregs[29] = 0;
                env->xregs[30] = 0;

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
        /*
         * kevent_qos(int kq, const struct kevent_qos_s *changelist,
         *            int nchanges, struct kevent_qos_s *eventlist,
         *            int nevents, void *data_out,
         *            size_t *data_available, unsigned int flags)
         *
         * When fd == -1 and flags & KEVENT_FLAG_WORKQ, libdispatch is
         * using the per-process workqueue kqueue.  Forward event
         * registrations to our workq kqueue and start the monitor
         * thread which creates workqueue threads when events fire.
         */
        int kq = (int)arg1;
        unsigned int flags = (unsigned int)arg8;

        if (kq == -1 && (flags & KEVENT_FLAG_WORKQ)) {
            /*
             * Workqueue kqueue: libdispatch registers events here.
             * Return success without registering on kqueue.
             * MACHPORT events from kevent_id are handled separately;
             * kevent_qos WORKQ ports may overlap with MIG reply ports
             * and must NOT be put on our kqueue.
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
                                "ident=0x%llx fflags=0x%x\n",
                                i, cl[i].filter,
                                (unsigned long long)cl[i].ident,
                                cl[i].fflags);
                    }
                }
            }

            ret = 0;
            if (do_strace) {
                fprintf(stderr, "    kevent_qos WORKQ -> 0 (no-op)\n");
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
                            "fflags=0x%x ext0=0x%llx\n",
                            i, cl[i].filter,
                            (unsigned long long)cl[i].ident,
                            cl[i].flags, cl[i].fflags,
                            (unsigned long long)cl[i].ext[0]);
                }
            }
        }

        /*
         * kevent_id: register MACHPORT events on our workq kqueue so
         * the monitor thread can detect incoming messages and create
         * guest workqueue threads.  These ports are dispatch-internal
         * (not in CFRunLoop port sets), so kqueue monitoring is safe.
         *
         * WORKLOOP (EVFILT_WORKLOOP) events remain no-ops for now.
         * Serial queues that rely on workloop thread requests don't
         * work yet — this requires emulating the kernel's workloop
         * thread scheduling, which is complex.  Global queue dispatch
         * and dispatch_apply work because they use WQOPS_QUEUE_REQTHREADS.
         */
        if (cl && nchanges > 0) {
            bool have_machport = false;
            for (int i = 0; i < nchanges; i++) {
                if (cl[i].filter == EVFILT_MACHPORT) {
                    have_machport = true;
                    break;
                }
            }
            if (have_machport) {
                TaskState *ts = get_task_state(
                    env_cpu((CPUArchState *)cpu_env));
                ensure_workq_monitor((CPUArchState *)cpu_env, ts);
                int kq = get_workq_kqueue();

                for (int i = 0; i < nchanges; i++) {
                    if (cl[i].filter == EVFILT_MACHPORT) {
                        struct kevent64_s k64;
                        kqos_to_k64(&cl[i], &k64);
                        int rc = kevent64(kq, &k64, 1, NULL, 0, 0, NULL);
                        add_workloop_port(arg1,
                            (mach_port_t)cl[i].ident);
                        if (do_strace) {
                            fprintf(stderr, "    MACHPORT ident=0x%llx"
                                    " -> kqueue reg rc=%d wl=0x%llx%s\n",
                                    (unsigned long long)cl[i].ident,
                                    rc, (unsigned long long)arg1,
                                    rc < 0 ? " (FAILED)" : "");
                        }
                    } else {
                        if (do_strace) {
                            fprintf(stderr,
                                    "    WORKLOOP ident=0x%llx -> no-op\n",
                                    (unsigned long long)cl[i].ident);
                        }
                    }
                }
            } else {
                if (do_strace) {
                    for (int i = 0; i < nchanges; i++) {
                        fprintf(stderr, "    WORKLOOP ident=0x%llx"
                                " -> no-op\n",
                                (unsigned long long)cl[i].ident);
                    }
                }
            }
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
            if (arg3) useraddr = g2h_untagged(arg3);
            ret = get_errno(csops((pid_t)arg1, (unsigned int)arg2,
                                  useraddr, (size_t)arg4));
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
         * abort_with_payload / terminate_with_payload
         * These terminate the process with a crash reason.
         * Just exit with a non-zero status.
         */
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
