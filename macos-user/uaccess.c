/*
 * User memory access helpers
 */

#include "qemu/osdep.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/guest-host.h"
#include "user/page-protection.h"

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

        if (sig == 5 && env->xregs[1] && env->xregs[0] > 0 &&
            env->xregs[0] < 4096 &&
            page_check_range(env->xregs[1], env->xregs[0], PAGE_READ)) {
            const unsigned char *payload = g2h_untagged(env->xregs[1]);
            size_t len = env->xregs[0];

            fprintf(stderr, "SIGTRAP payload: \"");
            for (size_t i = 0; i < len; i++) {
                unsigned char c = payload[i];
                fputc(c >= 0x20 && c < 0x7f ? c : '.', stderr);
            }
            fprintf(stderr, "\"\n");
        }

        if (sig == 5 && env->xregs[0] &&
            page_check_range(env->xregs[0], 1, PAGE_READ)) {
            const unsigned char *str = g2h_untagged(env->xregs[0]);
            fprintf(stderr, "SIGTRAP x0 string: \"");
            for (size_t i = 0; i < 256; i++) {
                unsigned char c = str[i];
                if (!c) {
                    break;
                }
                fputc(c >= 0x20 && c < 0x7f ? c : '.', stderr);
            }
            fprintf(stderr, "\"\n");
        }

        if (sig == 11 && env->xregs[19] &&
            page_check_range(env->xregs[19], 12 * sizeof(uint64_t),
                             PAGE_READ)) {
            const uint64_t *words = g2h_untagged(env->xregs[19]);
            fprintf(stderr,
                    "SIGSEGV x19 @0x%llx: %016llx %016llx %016llx %016llx "
                    "%016llx %016llx %016llx %016llx %016llx %016llx "
                    "%016llx %016llx\n",
                    (unsigned long long)env->xregs[19],
                    (unsigned long long)words[0],
                    (unsigned long long)words[1],
                    (unsigned long long)words[2],
                    (unsigned long long)words[3],
                    (unsigned long long)words[4],
                    (unsigned long long)words[5],
                    (unsigned long long)words[6],
                    (unsigned long long)words[7],
                    (unsigned long long)words[8],
                    (unsigned long long)words[9],
                    (unsigned long long)words[10],
                     (unsigned long long)words[11]);
        }

        if (sig == 6 && env->xregs[31] &&
            page_check_range(env->xregs[31], 96 * sizeof(uint64_t),
                             PAGE_READ)) {
            const uint64_t *words = g2h_untagged(env->xregs[31]);
            fprintf(stderr, "SIGABRT stack @0x%llx:\n",
                    (unsigned long long)env->xregs[31]);
            for (int i = 0; i < 96; i += 4) {
                fprintf(stderr,
                        "  +0x%02x: %016llx %016llx %016llx %016llx\n",
                        i * 8,
                        (unsigned long long)words[i],
                        (unsigned long long)words[i + 1],
                        (unsigned long long)words[i + 2],
                        (unsigned long long)words[i + 3]);
            }
            for (int i = 0; i < 96; i++) {
                abi_ulong ptr = words[i];
                if (ptr && page_check_range(ptr, 1, PAGE_READ)) {
                    const unsigned char *s = g2h_untagged(ptr);
                    int printable = 0;

                    for (int j = 0; j < 64; j++) {
                        unsigned char c = s[j];
                        if (!c) {
                            break;
                        }
                        if (c >= 0x20 && c < 0x7f) {
                            printable++;
                        }
                    }
                    if (printable >= 4) {
                        unsigned long long bad_ptr = 0;
                        fprintf(stderr, "SIGABRT stack ptr +0x%02x 0x%llx: \"",
                                i * 8, (unsigned long long)ptr);
                        for (int j = 0; j < 160; j++) {
                            unsigned char c = s[j];
                            if (!c) {
                                break;
                            }
                            fputc(c >= 0x20 && c < 0x7f ? c : '.', stderr);
                        }
                        fprintf(stderr, "\"\n");
                        if (sscanf((const char *)s,
                                   "%*[^:]: *** error for object 0x%llx:",
                                   &bad_ptr) == 1 &&
                            page_check_range((abi_ulong)bad_ptr, 64,
                                             PAGE_READ)) {
                            const uint64_t *bp =
                                g2h_untagged((abi_ulong)bad_ptr);
                            fprintf(stderr,
                                    "SIGABRT bad object 0x%llx: "
                                    "%016llx %016llx %016llx %016llx "
                                    "%016llx %016llx %016llx %016llx\n",
                                    bad_ptr,
                                    (unsigned long long)bp[0],
                                    (unsigned long long)bp[1],
                                    (unsigned long long)bp[2],
                                    (unsigned long long)bp[3],
                                    (unsigned long long)bp[4],
                                    (unsigned long long)bp[5],
                                    (unsigned long long)bp[6],
                                    (unsigned long long)bp[7]);
                        }
                    }
                }
            }
        }

        if (sig == 4 && env->pc == 0 && env->xregs[30] &&
            page_check_range(env->xregs[30] - 16, 32, PAGE_READ)) {
            const uint32_t *insn = g2h_untagged(env->xregs[30] - 16);

            fprintf(stderr,
                    "SIGILL caller @0x%llx: %08x %08x %08x %08x "
                    "%08x %08x %08x %08x\n",
                    (unsigned long long)(env->xregs[30] - 16),
                    insn[0], insn[1], insn[2], insn[3],
                    insn[4], insn[5], insn[6], insn[7]);
        }

        if (sig == 4 && env->pc == 0 && env->xregs[25] &&
            page_check_range(env->xregs[25], 96, PAGE_READ)) {
            const uint64_t *words = g2h_untagged(env->xregs[25]);

            fprintf(stderr,
                    "SIGILL x25 @0x%llx: %016llx %016llx %016llx %016llx "
                    "%016llx %016llx %016llx %016llx %016llx %016llx "
                    "%016llx %016llx\n",
                    (unsigned long long)env->xregs[25],
                    (unsigned long long)words[0],
                    (unsigned long long)words[1],
                    (unsigned long long)words[2],
                    (unsigned long long)words[3],
                    (unsigned long long)words[4],
                    (unsigned long long)words[5],
                    (unsigned long long)words[6],
                    (unsigned long long)words[7],
                    (unsigned long long)words[8],
                    (unsigned long long)words[9],
                    (unsigned long long)words[10],
                    (unsigned long long)words[11]);
        }

        /* Walk guest frame pointer chain for backtrace */
        fprintf(stderr, "Guest backtrace:\n");
        fprintf(stderr, "  [0] PC=0x%lx\n", (unsigned long)env->pc);
        fprintf(stderr, "  [1] LR=0x%lx\n", (unsigned long)env->xregs[30]);
        uint64_t fp = env->xregs[29];
        for (int i = 2; i < 32 && fp != 0; i++) {
            uint64_t *frame = g2h_untagged(fp);
            uint64_t saved_fp = frame[0];
            uint64_t saved_lr = frame[1];
            fprintf(stderr, "  [%d] 0x%lx\n", i, (unsigned long)saved_lr);
            if (saved_fp <= fp) break;
            fp = saved_fp;
        }
    }
    abort();
}
