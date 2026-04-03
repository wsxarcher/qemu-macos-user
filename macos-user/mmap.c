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

static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int mmap_lock_count;

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

    /* Align to page boundaries */
    start = TARGET_PAGE_ALIGN(start);
    len = TARGET_PAGE_ALIGN(len);

    if (len == 0) {
        return -TARGET_EINVAL;
    }

    /* Handle MAP_FIXED */
    if (flags & MAP_FIXED) {
        /* Unmap any existing mapping at this address */
        munmap((void *)(uintptr_t)start, len);
    }

    /* Perform the mapping */
    ret = mmap((void *)(uintptr_t)start, len, prot, flags, fd, offset);

    if (ret == MAP_FAILED) {
        return -TARGET_ENOMEM;
    }

    return (abi_ulong)(uintptr_t)ret;
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

    ret = munmap((void *)(uintptr_t)start, len);
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

    ret = mprotect((void *)(uintptr_t)start, len, prot);
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

    ret = msync((void *)(uintptr_t)start, len, flags);
    return ret == 0 ? 0 : -TARGET_EINVAL;
}

abi_long target_mremap(abi_ulong old_addr, abi_ulong old_size,
                       abi_ulong new_size, unsigned long flags,
                       abi_ulong new_addr)
{
    /* mremap not supported on macOS */
    return -TARGET_ENOSYS;
}
