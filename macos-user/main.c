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
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/path.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/plugin.h"
#include "user/guest-base.h"
#include "user/page-protection.h"
#include "accel/accel-ops.h"
#include "tcg/startup.h"
#include "qemu/timer.h"
#include "qemu/envlist.h"
#include "qemu/cutils.h"
#include "exec/log.h"
#include "trace/control.h"
#include "crypto/init.h"
#include "qemu/guest-random.h"
#include "gdbstub/user.h"
#include "exec/page-vary.h"

#include "target_arch_cpu.h"

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

CPUArchState *thread_cpu;
bool qemu_cpu_is_self(CPUState *cpu)
{
    return true;
}

void qemu_cpu_kick(CPUState *cpu)
{
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

THREAD CPUState *thread_cpu;

bool qemu_plugin_user_exit(void)
{
    return false;
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

void qemu_init_cpu_list(void)
{
    QTAILQ_INIT_RCU(&cpus_queue);
}

void init_task_state(TaskState *ts)
{
    ts->ts_tid = 0;
    ts->next = NULL;
    ts->info = NULL;
    sigemptyset(&ts->signal_mask);
}

/* Setup initial stack and registers */
static abi_ulong setup_arg_pages(struct image_info *info,
                                  abi_ulong stack_base,
                                  struct target_pt_regs *regs,
                                  char **argv, char **envp)
{
    abi_ulong sp = stack_base;
    int argc = 0;
    int envc = 0;

    /* Count arguments */
    while (argv[argc]) argc++;
    while (envp[envc]) envc++;

    /* Allocate space for arguments on stack */
    sp -= (argc + 1) * sizeof(abi_ulong);  /* argv */
    sp -= (envc + 1) * sizeof(abi_ulong);  /* envp */
    sp -= 2 * sizeof(abi_ulong);           /* argc and argv ptr */

    /* Align stack to 16 bytes (ARM64 requirement) */
    sp &= ~15;

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
    int gdbstub = 0;

    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_TRACE);
    module_call_init(MODULE_INIT_QOM);

    if ((envlist = envlist_create()) == NULL) {
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

    /* Zero the BSS */
    memset(&info, 0, sizeof(info));

    /* Initialize TCG */
    tcg_exec_init(0, false);

    if (cpu_model == NULL) {
        cpu_model = TARGET_DEFAULT_CPU_MODEL;
    }

    /* Create CPU */
    cpu = cpu_create(cpu_model);
    if (!cpu) {
        fprintf(stderr, "Unable to create CPU\n");
        exit(EXIT_FAILURE);
    }
    env = cpu_env(cpu);

    thread_cpu = cpu;

    /* Initialize task state */
    ts = g_new0(TaskState, 1);
    init_task_state(ts);
    ts->info = &info;
    cpu->opaque = ts;

    /* Load the binary */
    char *memp = NULL;
    ret = loader_exec(filename, target_argv, envp, &regs, &info, &memp);
    if (ret != 0) {
        fprintf(stderr, "Error loading %s: %s\n", filename, strerror(-ret));
        _exit(EXIT_FAILURE);
    }

    /* Setup stack */
    abi_ulong stack_base = TARGET_PAGE_ALIGN(0x7ffffffff000ULL);
    abi_ulong stack_size = target_dflssiz;

    /* Allocate stack */
    void *stack = mmap((void *)(uintptr_t)(stack_base - stack_size),
                      stack_size,
                      PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                      -1, 0);
    if (stack == MAP_FAILED) {
        fprintf(stderr, "Unable to allocate stack\n");
        _exit(EXIT_FAILURE);
    }

    info.start_stack = stack_base;
    info.stack_limit = stack_base - stack_size;

    /* Setup arguments on stack */
    regs.sp = setup_arg_pages(&info, stack_base, &regs, target_argv, envp);

    /* Initialize CPU state */
    target_cpu_init(env, &regs);

    /* Initialize signals */
    signal_init();

    if (gdbstub) {
        gdbserver_start(gdbstub);
    }

    /* Start CPU loop */
    cpu_loop(env);

    /* Never reached */
    return 0;
}
