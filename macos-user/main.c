/*
 *  qemu macOS user mode main
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "qemu/help-texts.h"
#include "qemu/units.h"
#include "qemu/accel.h"
#include "qemu-version.h"

#include "qapi/error.h"
#include "qemu.h"
#include "user-internals.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/path.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "user/guest-base.h"
#include "user/page-protection.h"
#include "exec/mmap-lock.h"
#include "accel/accel-ops.h"
#include "tcg/startup.h"
#include "qemu/timer.h"
#include <sys/random.h>
#include "qemu/envlist.h"
#include "qemu/cutils.h"
#include "exec/log.h"
#include "trace/control.h"
#include "crypto/init.h"
#include "qemu/guest-random.h"
#include "gdbstub/user.h"
#include "exec/page-vary.h"

#include "target_arch_cpu.h"

#include <mach-o/loader.h>

uintptr_t qemu_host_page_size;
intptr_t qemu_host_page_mask;

static bool opt_one_insn_per_tb;
static unsigned long opt_tb_size;
uintptr_t guest_base;
bool have_guest_base;

unsigned long reserved_va;
unsigned long guest_addr_max;

const char *interp_prefix = "";
const char *qemu_uname_release;

unsigned long target_maxtsiz = 256 * 1024 * 1024;   /* max text size */
unsigned long target_dfldsiz = 128 * 1024 * 1024;   /* initial data size limit */
unsigned long target_maxdsiz = 512 * 1024 * 1024;   /* max data size */
unsigned long target_dflssiz = 8 * 1024 * 1024;     /* initial stack size limit */
unsigned long target_maxssiz = 64 * 1024 * 1024;    /* max stack size */
unsigned long target_sgrowsiz = 128 * 1024;         /* amount to grow stack */

__thread CPUState *thread_cpu;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

/* Fork handling */
void fork_start(void)
{
    start_exclusive();
    mmap_fork_start();
    cpu_list_lock();
    qemu_plugin_user_prefork_lock();
    gdbserver_fork_start();
}

void fork_end(pid_t pid)
{
    bool child = pid == 0;

    qemu_plugin_user_postfork(child);
    mmap_fork_end(child);
    if (child) {
        CPUState *cpu, *next_cpu;
        CPU_FOREACH_SAFE(cpu, next_cpu) {
            if (cpu != thread_cpu) {
                QTAILQ_REMOVE_RCU(&cpus_queue, cpu, node);
            }
        }
        qemu_init_cpu_list();
        TaskState *ts = get_task_state(thread_cpu);
        ts->ts_tid = qemu_get_thread_id();
    } else {
        cpu_list_unlock();
    }
    gdbserver_fork_end(thread_cpu, pid);
    end_exclusive();
}

void cpu_loop(CPUArchState *env)
{
    target_cpu_loop(env);
}

/*
 * Guest address space constant.
 *
 * guest_base is the host-address offset applied to every guest address.
 * We choose a value high enough that the guest's shared cache region
 * (starting at 0x180000000) lands well above the host's own shared
 * cache at the same virtual address.
 *
 * 64 GiB keeps both the guest binary (typically loaded at 0x100000000)
 * and the shared cache region (0x180000000..0x2E459C000) safely away
 * from the host's occupancy.
 */
#define GUEST_BASE_OFFSET  0x10000000000ULL   /* 64 GiB */

/*
 * The guest address space spans from 0 to GUEST_ADDR_SPACE.  We reserve
 * this range at (host) address guest_base..guest_base+GUEST_ADDR_SPACE
 * with PROT_NONE so that no host allocation can land there.
 *
 * Must be large enough to cover the commpage at 0xFFFFFC000 (~4 GiB)
 * and the shared cache region ending at ~0x2E459C000 (~12 GiB).
 */
#define GUEST_ADDR_SPACE   0x1000000000ULL    /* 64 GiB */

/*
 * macOS arm64 commpage — a read-only page the kernel maps at a fixed
 * address containing system constants (timing, CPU features, etc.).
 * Guest code (especially dyld) reads the commpage directly.
 * With guest_base != 0, we mirror the host commpage content.
 */
#define COMMPAGE_GUEST_ADDR  0xFFFFF0000ULL
#define COMMPAGE_SIZE        0x10000          /* 64 KiB */

static void usage(void)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION
           "\n" QEMU_COPYRIGHT "\n"
           "usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "macOS CPU emulator (compiled for %s emulation)\n"
           "\n"
           "Standard options:\n"
           "-h                print this help\n"
           "-L path           set the library root path\n"
           "-s size           set the stack size in bytes (default=%ld)\n"
           "-cpu model        select CPU (-cpu help for list)\n"
           "-E var=value      sets/modifies targets environment variable(s)\n"
           "-U var            unsets targets environment variable(s)\n"
           "\n"
           "Debug options:\n"
           "-d item1[,...]    enable logging of specified items\n"
           "-D logfile        write logs to 'logfile' (default stderr)\n"
           "-strace           log system calls\n"
           "\n"
           QEMU_HELP_BOTTOM "\n"
           ,
           TARGET_NAME,
           target_dflssiz);
    exit(1);
}

static void handle_arg_help(const char *arg)
{
    usage();
}

static void handle_arg_log(const char *arg)
{
    int mask = qemu_str_to_log_mask(arg);
    if (!mask) {
        qemu_print_log_usage(stdout);
        exit(EXIT_FAILURE);
    }
    qemu_set_log(mask, &error_fatal);
}

static void handle_arg_log_filename(const char *arg)
{
    qemu_set_log_filename(arg, &error_fatal);
}

static void handle_arg_strace(const char *arg)
{
    do_strace = 1;
}

static void handle_arg_cpu(const char *arg)
{
    cpu_model = arg;
}

static void handle_arg_stack_size(const char *arg)
{
    char *p;
    target_dflssiz = strtoul(arg, &p, 0);
    if (target_dflssiz == 0) {
        usage();
    }
    if (*p == 'M') {
        target_dflssiz *= 1024 * 1024;
    } else if (*p == 'k' || *p == 'K') {
        target_dflssiz *= 1024;
    }
    target_maxssiz = target_dflssiz;
}

struct qemu_argument {
    const char *argv;
    const char *env;
    bool has_arg;
    void (*handle_opt)(const char *arg);
    const char *example;
    const char *help;
};

static const struct qemu_argument arg_table[] = {
    {"h",          "",                 false, handle_arg_help,
     "",           "print this help"},
    {"d",          "QEMU_LOG",         true,  handle_arg_log,
     "item[,...]", "enable logging of specified items "
     "(use '-d help' for a list of items)"},
    {"D",          "QEMU_LOG_FILENAME", true, handle_arg_log_filename,
     "logfile",    "write logs to 'logfile' (default stderr)"},
    {"strace",     "QEMU_STRACE",      false, handle_arg_strace,
     "",           "log system calls"},
    {"s",          "QEMU_STACK_SIZE",  true,  handle_arg_stack_size,
     "size",       "set the stack size to 'size' bytes"},
    {"cpu",        "QEMU_CPU",         true,  handle_arg_cpu,
     "model",      "select CPU model (-cpu help for list)"},
    {NULL, NULL, false, NULL, NULL, NULL}
};

static void handle_arg_panic(const char *arg)
{
    /* Ignore for now */
}

void init_task_state(TaskState *ts)
{
    ts->ts_tid = 0;
    ts->next = NULL;
    ts->bprm = NULL;
    ts->info = NULL;
    sigemptyset(&ts->signal_mask);
}

/*
 * Build the initial stack in the layout the XNU kernel uses.
 *
 * For dynamic binaries (dyld present) the layout is:
 *
 *  SP →  [mach_header of main binary]   (8 bytes)
 *        [argc]                          (8 bytes)
 *        [argv[0] ptr] ... [argv[argc-1] ptr] [NULL]
 *        [envp[0] ptr] ... [envp[envc-1] ptr] [NULL]
 *        [apple[0] ptr] ... [apple[n] ptr] [NULL]
 *        ... string data for argv, envp, apple ...
 *
 * For static binaries, the mach_header slot is omitted and
 * the layout starts with argc.
 */
static abi_ulong setup_arg_pages(struct image_info *info,
                                  abi_ulong stack_base,
                                  struct target_pt_regs *regs,
                                  char **argv, char **envp)
{
    int argc = 0, envc = 0;
    size_t str_size = 0;
    bool is_dynamic = (info->interp_entry != 0);

    while (argv[argc]) {
        str_size += strlen(argv[argc]) + 1;
        argc++;
    }
    while (envp[envc]) {
        str_size += strlen(envp[envc]) + 1;
        envc++;
    }

    /* Build "apple" strings: kernel-provided parameters */
    char exec_path_str[PATH_MAX + 32];
    snprintf(exec_path_str, sizeof(exec_path_str),
             "executable_path=%s", argv[0]);

    /*
     * The XNU kernel provides random tokens on the initial stack.
     * ptr_munge is used by libpthread for pointer obfuscation.
     * stack_guard is the stack canary value.
     * libpthread asserts that ptr_munge is non-zero.
     */
    char ptr_munge_str[64];
    char stack_guard_str[64];
    {
        uint64_t ptr_munge_val = 0, stack_guard_val = 0;
        getentropy(&ptr_munge_val, sizeof(ptr_munge_val));
        getentropy(&stack_guard_val, sizeof(stack_guard_val));
        if (ptr_munge_val == 0) {
            ptr_munge_val = 0xDEADBEEF12345678ULL;
        }
        /* XNU format: "ptr_munge=0x<hex>" — note the 0x prefix */
        snprintf(ptr_munge_str, sizeof(ptr_munge_str),
                 "ptr_munge=0x%llx", (unsigned long long)ptr_munge_val);
        snprintf(stack_guard_str, sizeof(stack_guard_str),
                 "stack_guard=0x%llx", (unsigned long long)stack_guard_val);
    }

    const char *apple_strings[] = {
        exec_path_str,
        ptr_munge_str,
        stack_guard_str,
        NULL
    };
    int applec = 0;
    while (apple_strings[applec]) {
        str_size += strlen(apple_strings[applec]) + 1;
        applec++;
    }

    /*
     * Calculate space needed:
     * - mach_header pointer (dynamic only)
     * - argc
     * - argv pointers + NULL
     * - envp pointers + NULL
     * - apple pointers + NULL
     * - all string data
     */
    size_t ptrs_size = sizeof(abi_ulong) * (
        (is_dynamic ? 1 : 0) +      /* mach_header */
        1 +                           /* argc */
        (argc + 1) +                  /* argv + NULL */
        (envc + 1) +                  /* envp + NULL */
        (applec + 1)                  /* apple + NULL */
    );

    abi_ulong sp = stack_base;
    sp -= str_size;
    sp -= ptrs_size;
    sp &= ~15;  /* ARM64 16-byte alignment */

    abi_ulong ptr_pos = sp;
    abi_ulong str_pos = sp + ptrs_size;

    /* Helper: write a pointer-sized value to guest memory */
    #define PUT_PTR(val) do { \
        abi_ulong _v = (val); \
        memcpy(g2h_untagged(ptr_pos), &_v, sizeof(_v)); \
        ptr_pos += sizeof(abi_ulong); \
    } while (0)

    /* [mach_header] — only for dynamic binaries */
    if (is_dynamic) {
        PUT_PTR(info->mach_header_addr);
    }

    /* [argc] */
    PUT_PTR((abi_ulong)argc);

    /* [argv pointers] */
    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]) + 1;
        memcpy(g2h_untagged(str_pos), argv[i], len);
        PUT_PTR(str_pos);
        str_pos += len;
    }
    PUT_PTR(0); /* argv NULL terminator */

    /* [envp pointers] */
    for (int i = 0; i < envc; i++) {
        size_t len = strlen(envp[i]) + 1;
        memcpy(g2h_untagged(str_pos), envp[i], len);
        PUT_PTR(str_pos);
        str_pos += len;
    }
    PUT_PTR(0); /* envp NULL terminator */

    /* [apple pointers] */
    for (int i = 0; i < applec; i++) {
        size_t len = strlen(apple_strings[i]) + 1;
        memcpy(g2h_untagged(str_pos), apple_strings[i], len);
        PUT_PTR(str_pos);
        str_pos += len;
    }
    PUT_PTR(0); /* apple NULL terminator */

    #undef PUT_PTR

    regs->sp = sp;
    return sp;
}

int main(int argc, char **argv, char **envp)
{
    struct target_pt_regs regs;
    struct image_info info;
    TaskState *ts;
    CPUArchState *env;
    CPUState *cpu;
    int optind;
    char **target_argv;
    char **target_envp = NULL;
    int ret;
    int i;
    const char *gdbstub = NULL;

    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_TRACE);
    module_call_init(MODULE_INIT_QOM);

    envlist = envlist_create();
    if (envlist == NULL) {
        fprintf(stderr, "Unable to allocate envlist\n");
        exit(EXIT_FAILURE);
    }

    /* Parse environment */
    for (i = 0; envp[i] != NULL; i++) {
        envlist_setenv(envlist, envp[i]);
    }

    /* Initialize host page size */
    qemu_host_page_size = getpagesize();
    qemu_host_page_mask = -(intptr_t)qemu_host_page_size;

    /*
     * Match the target page size to the host (macOS uses 16K pages).
     * Must be called before any page table operations.
     */
    set_preferred_target_page_bits(ctz32(qemu_host_page_size));
    finalize_target_page_bits();

    optind = 1;
    for (;;) {
        if (optind >= argc) {
            break;
        }
        const char *r = argv[optind];
        const struct qemu_argument *arginfo;

        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;

        if (!strcmp(r, "-")) {
            break;
        }

        for (arginfo = arg_table; arginfo->argv != NULL; arginfo++) {
            if (!strcmp(r, arginfo->argv)) {
                if (arginfo->has_arg) {
                    if (optind >= argc) {
                        fprintf(stderr, "Option '%s' requires an argument\n", r);
                        usage();
                    }
                    arginfo->handle_opt(argv[optind]);
                    optind++;
                } else {
                    arginfo->handle_opt(NULL);
                }
                break;
            }
        }

        if (arginfo->argv == NULL) {
            fprintf(stderr, "Unknown option '%s'\n", r);
            usage();
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "No program specified\n");
        usage();
    }

    const char *filename = argv[optind];
    target_argv = &argv[optind];

    /* Set up guest address space limit */
    if (reserved_va != 0) {
        guest_addr_max = reserved_va;
    } else if (MIN(TARGET_VIRT_ADDR_SPACE_BITS, TARGET_ABI_BITS) <= 32) {
        guest_addr_max = UINT32_MAX;
    } else {
        guest_addr_max = ~0ul;
    }

    /* Zero the BSS */
    memset(&info, 0, sizeof(info));

    if (cpu_model == NULL) {
        cpu_model = TARGET_DEFAULT_CPU_MODEL;
    }

    const char *cpu_type = parse_cpu_option(cpu_model);

    /* init tcg before creating CPUs and to get qemu_host_page_size */
    {
        AccelState *accel = current_accel();
        AccelClass *ac = ACCEL_GET_CLASS(accel);

        accel_init_interfaces(ac);
        ac->init_machine(accel, NULL);
    }

    /* Create CPU */
    cpu = cpu_create(cpu_type);
    env = cpu_env(cpu);
    cpu_reset(cpu);

    thread_cpu = cpu;

    /* Initialize task state */
    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    ts->info = &info;
    cpu->opaque = ts;

    /* Set up binary program info for gdb */
    struct macos_binprm *bprm = g_new0(struct macos_binprm, 1);
    bprm->filename = g_strdup(filename);
    bprm->fullpath = realpath(filename, NULL);
    ts->bprm = bprm;

    /*
     * Set up guest_base for dynamic binaries.
     *
     * For dynamically linked binaries, guest dyld needs to privately map
     * the shared cache at 0x180000000 (SHARED_REGION_BASE).  The host
     * process has its own shared cache at the same virtual address.
     * By setting guest_base, all guest virtual addresses are translated
     * to host addresses by adding guest_base, so the guest's 0x180000000
     * maps to a different (unused) host address.
     *
     * We also inject DYLD_SHARED_REGION=private so that dyld maps the
     * cache itself instead of expecting the kernel to have mapped it.
     *
     * For static binaries, guest_base stays 0 and addresses are 1:1.
     */
    {
        /*
         * Peek at the Mach-O to detect LC_LOAD_DYLINKER without loading.
         * Alternatively, we could always set guest_base, but for static
         * binaries it introduces unnecessary overhead.
         */
        int peek_fd = open(filename, O_RDONLY);
        bool is_dynamic = false;
        if (peek_fd >= 0) {
            struct mach_header_64 mh;
            if (read(peek_fd, &mh, sizeof(mh)) == sizeof(mh)) {
                uint8_t *cmdbuf = g_malloc(mh.sizeofcmds);
                if (read(peek_fd, cmdbuf, mh.sizeofcmds) ==
                    (ssize_t)mh.sizeofcmds) {
                    uint8_t *p = cmdbuf;
                    for (uint32_t ci = 0; ci < mh.ncmds; ci++) {
                        struct load_command *lc = (struct load_command *)p;
                        if (lc->cmd == LC_LOAD_DYLINKER) {
                            is_dynamic = true;
                            break;
                        }
                        p += lc->cmdsize;
                    }
                }
                g_free(cmdbuf);
            }
            close(peek_fd);
        }

        if (is_dynamic) {
            /*
             * Reserve a region of host virtual address space for the
             * guest.  MAP_FIXED ensures we get exactly this address.
             */
            void *reservation = mmap((void *)GUEST_BASE_OFFSET,
                                     GUEST_ADDR_SPACE,
                                     PROT_NONE,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                                     -1, 0);
            if (reservation == MAP_FAILED) {
                fprintf(stderr, "qemu: unable to reserve guest address "
                        "space at 0x%llx: %s\n",
                        (unsigned long long)GUEST_BASE_OFFSET,
                        strerror(errno));
                _exit(EXIT_FAILURE);
            }
            guest_base = (uintptr_t)reservation;
            have_guest_base = true;

            /*
             * Tell guest dyld to map the shared cache privately instead
             * of expecting the kernel to have set up the shared region.
             */
            envlist_setenv(envlist, "DYLD_SHARED_REGION=private");

            /*
             * Provide a ptr_munge token via the environment fallback.
             * libpthread checks PTHREAD_PTR_MUNGE_TOKEN in envp when
             * the apple[] kernel token is missing or zero.
             */
            {
                uint64_t munge_val = 0;
                getentropy(&munge_val, sizeof(munge_val));
                if (munge_val == 0) {
                    munge_val = 0xDEADBEEF12345678ULL;
                }
                char munge_env[64];
                snprintf(munge_env, sizeof(munge_env),
                         "PTHREAD_PTR_MUNGE_TOKEN=%016llx",
                         (unsigned long long)munge_val);
                envlist_setenv(envlist, munge_env);
            }

            /*
             * Mirror the host commpage into the guest address space.
             * The commpage is a read-only page at a fixed address
             * containing timing and CPU feature constants.  dyld and
             * libc read it directly; without it the guest faults.
             */
            void *cp_host = g2h_untagged(COMMPAGE_GUEST_ADDR);
            void *cp = mmap(cp_host, COMMPAGE_SIZE,
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                            -1, 0);
            if (cp != MAP_FAILED) {
                /*
                 * The 64 KiB commpage region has two readable 16 KiB
                 * sub-regions (text at +0x4000, data at +0xC000) with
                 * unmapped gaps.  Copy only the readable parts.
                 */
                memcpy(cp + 0x4000, (void *)(COMMPAGE_GUEST_ADDR + 0x4000),
                       0x4000);
                memcpy(cp + 0xC000, (void *)(COMMPAGE_GUEST_ADDR + 0xC000),
                       0x4000);
                mprotect(cp, COMMPAGE_SIZE, PROT_READ);
                mmap_lock();
                page_set_flags(COMMPAGE_GUEST_ADDR,
                               COMMPAGE_GUEST_ADDR + COMMPAGE_SIZE - 1,
                               PAGE_VALID | PAGE_READ, ~0);
                mmap_unlock();
            }
        }
    }

    /* Load the binary */
    char *memp = NULL;
    target_envp = envlist_to_environ(envlist, NULL);
    ret = loader_exec(filename, target_argv, target_envp, &regs, &info, &memp);
    if (ret != 0) {
        fprintf(stderr, "Error loading %s: %s\n", filename, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    /* Setup stack */
    abi_ulong stack_size = target_dflssiz;

    /*
     * Allocate the guest stack via target_mmap which handles both
     * guest_base != 0 (dynamic) and guest_base == 0 (static) cases.
     * For static binaries, target_mmap will pick a host address
     * itself rather than trying to MAP_FIXED at a low guest address
     * that macOS won't allow.
     */
    abi_ulong guest_stack_base;
    if (have_guest_base) {
        /* Dynamic: allocate at a known guest address above loaded segments */
        guest_stack_base = TARGET_PAGE_ALIGN(info.start_mmap);
        void *stack = mmap(g2h_untagged(guest_stack_base),
                          stack_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1, 0);
        if (stack == MAP_FAILED) {
            fprintf(stderr, "Unable to allocate stack\n");
            _exit(EXIT_FAILURE);
        }
    } else {
        /* Static: let target_mmap find a suitable address */
        abi_long result = target_mmap(0, stack_size,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS,
                                       -1, 0);
        if (result == -1) {
            fprintf(stderr, "Unable to allocate stack\n");
            _exit(EXIT_FAILURE);
        }
        guest_stack_base = (abi_ulong)result;
    }

    abi_ulong stack_top = guest_stack_base + stack_size;

    info.start_stack = stack_top;
    info.stack_limit = guest_stack_base;

    /* Register stack pages with QEMU page table (guest addresses) */
    mmap_lock();
    page_set_flags(guest_stack_base, stack_top - 1,
                   PAGE_VALID | PAGE_READ | PAGE_WRITE, ~0);
    mmap_unlock();

    /* Setup arguments on stack */
    if (target_envp == NULL) {
        target_envp = envlist_to_environ(envlist, NULL);
    }
    regs.sp = setup_arg_pages(&info, stack_top, &regs, target_argv,
                              target_envp);

    /*
     * Now that we've loaded the binary, GUEST_BASE is fixed.  Delay
     * generating the prologue until now so that the prologue can take
     * the real value of GUEST_BASE into account.
     */
    tcg_prologue_init();

    /* Initialize CPU state */
    target_cpu_init(env, &regs);

    /*
     * Set up TPIDRRO_EL0 with a minimal thread descriptor.
     * On macOS, the kernel initializes this register to point to a
     * per-thread structure.  libsystem_pthread places the pthread_t
     * at *negative* offsets from this pointer, and TLS slots at
     * positive offsets.  We allocate a generous region around the
     * pointer so both areas are writable.
     */
    {
        /*
         * Allocate 8 pages: 4 pages below the TSD pointer (for the
         * pthread struct, typically ~4 KB) and 4 pages above (for
         * TLS slots and other per-thread data).
         */
        size_t page_sz = qemu_real_host_page_size();
        size_t below = 4 * page_sz;  /* space below the pointer */
        size_t above = 4 * page_sz;  /* space above the pointer */
        size_t total = below + above;
        abi_ulong region_start = ROUND_UP(stack_top + 0x10000, page_sz);
        abi_ulong tsd_ptr = region_start + below;

        void *tsd = mmap(g2h_untagged(region_start), total,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                         -1, 0);
        if (tsd != MAP_FAILED) {
            mmap_lock();
            page_set_flags(region_start, region_start + total - 1,
                           PAGE_VALID | PAGE_READ | PAGE_WRITE, ~0);
            mmap_unlock();
            env->cp15.tpidrro_el[0] = (uint64_t)tsd_ptr;
        }
    }

    /* Initialize signals */
    signal_init();

    if (gdbstub) {
        gdbserver_start(gdbstub, &error_fatal);
    }

    /* Start CPU loop */
    cpu_loop(env);

    /* Never reached */
    return 0;
}
