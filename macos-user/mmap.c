/*
 *  macOS memory management
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "qemu/osdep.h"
#include "exec/mmap-lock.h"
#include "qemu.h"
#include "user-internals.h"
#include "user/guest-host.h"
#include "user/guest-base.h"

static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int mmap_lock_count;

/*
 * Simple bump allocator for guest address space.
 * When target_mmap is called without an address hint (start == 0)
 * and guest_base is active, we allocate from this region instead
 * of letting the host kernel pick a random address outside the
 * guest reservation.
 */
static abi_ulong guest_mmap_next = 0x400000000ULL;  /* 16 GiB */

static int prot_to_page_flags(int prot)
{
    int page_flags = PAGE_VALID;

    if (prot & PROT_READ) {
        page_flags |= PAGE_READ;
    }
    if (prot & PROT_WRITE) {
        page_flags |= PAGE_WRITE;
    }
    if (prot & PROT_EXEC) {
        page_flags |= PAGE_EXEC;
    }
    return page_flags;
}

static abi_ulong find_guest_mmap_hole(abi_ulong hint, abi_ulong len,
                                      abi_ulong align)
{
    abi_ulong min = hint ? hint : guest_mmap_next;
    vaddr found;

    min = ROUND_UP(min, align);
    if (len - 1 > guest_addr_max || min > guest_addr_max - len + 1) {
        if (hint && guest_mmap_next <= guest_addr_max - len + 1) {
            min = ROUND_UP(guest_mmap_next, align);
        } else {
            return (abi_ulong)-1;
        }
    }

    if (hint && min == ROUND_UP(hint, align) &&
        min <= guest_addr_max - len + 1 &&
        page_check_range_empty(min, min + len - 1)) {
        return min;
    }

    found = page_find_range_empty(min, guest_addr_max, len, align);
    if (found == (vaddr)-1 && hint) {
        min = ROUND_UP(guest_mmap_next, align);
        if (min <= guest_addr_max - len + 1) {
            found = page_find_range_empty(min, guest_addr_max, len, align);
        }
    }

    return found == (vaddr)-1 ? (abi_ulong)-1 : (abi_ulong)found;
}

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        pthread_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    assert(mmap_lock_count > 0);
    if (--mmap_lock_count == 0) {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

void mmap_fork_start(void)
{
    if (mmap_lock_count) {
        abort();
    }
    pthread_mutex_lock(&mmap_mutex);
}

void mmap_fork_end(int child)
{
    if (child) {
        pthread_mutex_init(&mmap_mutex, NULL);
    } else {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

/* Memory mapping implementation */
abi_long target_mmap(abi_ulong start, abi_ulong len, int prot,
                     int flags, int fd, off_t offset)
{
    void *ret;
    void *host_addr;
    abi_ulong guest_hint = start;
    bool bump_alloc = false;

    /*
     * Align to host page boundaries.  macOS on Apple Silicon uses 16 KB
     * pages while QEMU's TARGET_PAGE_SIZE is 4 KB for arm64.  The host
     * kernel rejects mmap(MAP_FIXED) on non-host-page-aligned addresses.
     */
    abi_ulong page_size = MAX(TARGET_PAGE_SIZE,
                              (abi_ulong)qemu_real_host_page_size());
    abi_ulong page_mask = ~(page_size - 1);
    start = (start + page_size - 1) & page_mask;
    len = (len + page_size - 1) & page_mask;

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    mmap_lock();

    if (guest_base) {
        /*
         * The host has pre-reserved the whole guest VA range.  Therefore
         * host mmap hints cannot be used directly: without MAP_FIXED the host
         * would avoid the reservation and return an address outside the guest.
         * Pick a free guest range ourselves, then materialise it with
         * MAP_FIXED inside the reservation.
         */
        if (!(flags & MAP_FIXED)) {
            start = find_guest_mmap_hole(start, len, page_size);
            if (start == (abi_ulong)-1) {
                mmap_unlock();
                return -TARGET_ENOMEM;
            }
            bump_alloc = guest_hint == 0;
        }
        host_addr = g2h_untagged(start);
        flags |= MAP_FIXED;
    } else if (flags & MAP_FIXED) {
        host_addr = g2h_untagged(start);
    } else if (start != 0) {
        host_addr = g2h_untagged(start);
    } else {
        host_addr = NULL;
    }

    /* Perform the mapping */
    ret = mmap(host_addr, len, prot, flags, fd, offset);

    if (ret == MAP_FAILED) {
        if (do_strace) {
            fprintf(stderr, "qemu: target_mmap FAILED start=0x%llx len=0x%llx "
                    "prot=%d flags=0x%x fd=%d host=%p bump=0x%llx errno=%d\n",
                    (unsigned long long)start, (unsigned long long)len,
                    prot, flags, fd, host_addr,
                    (unsigned long long)guest_mmap_next, errno);
        }
        mmap_unlock();
        return -TARGET_ENOMEM;
    }

    /* Register pages in QEMU's internal page table */
    abi_ulong guest_ret = h2g(ret);
    page_set_flags(guest_ret, guest_ret + len - 1,
                   prot_to_page_flags(prot), ~0);

    if (bump_alloc) {
        guest_mmap_next = guest_ret + len;
    }

    mmap_unlock();

    return guest_ret;
}

int target_munmap(abi_ulong start, abi_ulong len)
{
    int ret;
    abi_ulong page_size = MAX(TARGET_PAGE_SIZE,
                              (abi_ulong)qemu_real_host_page_size());
    abi_ulong page_mask = page_size - 1;

    /* Align to page boundaries */
    if (start & page_mask) {
        return -TARGET_EINVAL;
    }
    len = (len + page_size - 1) & ~page_mask;

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    mmap_lock();
    if (guest_base) {
        /*
         * Keep the pre-reserved guest VA range backed by a host VMA.  Large
         * PROT_NONE Mach reservations rely on later mprotect() demand-faults;
         * a real munmap() would punch holes that mprotect() cannot promote.
         */
        void *addr = g2h_untagged(start);
        void *got = mmap(addr, len, PROT_NONE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        ret = got == addr ? 0 : -1;
    } else {
        ret = munmap(g2h_untagged(start), len);
    }
    if (ret == 0) {
        page_set_flags(start, start + len - 1, 0, ~0);
    }
    mmap_unlock();
    return ret == 0 ? 0 : -TARGET_EINVAL;
}

int target_mprotect(abi_ulong start, abi_ulong len, int prot)
{
    int ret;

    /* Align to page boundaries */
    start = TARGET_PAGE_ALIGN(start);
    len = TARGET_PAGE_ALIGN(len);

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    mmap_lock();
    ret = mprotect(g2h_untagged(start), len, prot);
    if (ret == 0) {
        page_set_flags(start, start + len - 1,
                       prot_to_page_flags(prot), PAGE_RWX);
    }
    mmap_unlock();
    return ret == 0 ? 0 : -TARGET_EACCES;
}

int target_msync(abi_ulong start, abi_ulong len, int flags)
{
    int ret;

    /* Align to page boundaries */
    start = TARGET_PAGE_ALIGN(start);
    len = TARGET_PAGE_ALIGN(len);

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    ret = msync(g2h_untagged(start), len, flags);
    return ret == 0 ? 0 : -TARGET_EINVAL;
}

abi_long target_mremap(abi_ulong old_addr, abi_ulong old_size,
                       abi_ulong new_size, unsigned long flags,
                       abi_ulong new_addr)
{
    /* mremap not supported on macOS */
    return -TARGET_ENOSYS;
}
