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

    if (flags & MAP_FIXED) {
        host_addr = g2h_untagged(start);
        /* Unmap any existing mapping at this host address */
        munmap(host_addr, len);
    } else if (start != 0) {
        host_addr = g2h_untagged(start);
    } else if (guest_base) {
        /*
         * No address hint with guest_base active: allocate from guest
         * address space using a bump allocator.  The guest region was
         * pre-reserved with PROT_NONE in main(), so MAP_FIXED here
         * simply overwrites the reservation.
         */
        abi_ulong alloc = (guest_mmap_next + page_size - 1) & page_mask;
        guest_mmap_next = alloc + len;
        host_addr = g2h_untagged(alloc);
        flags |= MAP_FIXED;
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
        return -TARGET_ENOMEM;
    }

    /* Register pages in QEMU's internal page table */
    abi_ulong guest_ret = h2g(ret);
    int page_flags = PAGE_VALID;
    if (prot & PROT_READ)  page_flags |= PAGE_READ;
    if (prot & PROT_WRITE) page_flags |= PAGE_WRITE;
    if (prot & PROT_EXEC)  page_flags |= PAGE_EXEC;
    page_set_flags(guest_ret, guest_ret + len - 1, page_flags, ~0);

    return guest_ret;
}

int target_munmap(abi_ulong start, abi_ulong len)
{
    int ret;

    /* Align to page boundaries */
    start = TARGET_PAGE_ALIGN(start);
    len = TARGET_PAGE_ALIGN(len);

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    ret = munmap(g2h_untagged(start), len);
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

    ret = mprotect(g2h_untagged(start), len, prot);
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
