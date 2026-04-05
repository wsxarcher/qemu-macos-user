#include "qemu/osdep.h"
#include "system/cpu-timers.h"
#include "qemu/main-loop.h"
#include "qemu/timer.h"

int64_t cpu_get_clock(void)
{
#ifdef __APPLE__
#include <mach/mach_time.h>
    /*
     * On macOS, return mach_absolute_time() * period_ns so that the CNTVCT_EL0
     * computation (cpu_get_clock() / period_ns) yields the host's exact
     * mach_absolute_time().  This is critical because:
     *
     *   1. The commpage's timebase_info {125,3} matches the host's 24 MHz counter
     *   2. mk_timer_arm deadlines must be in the host's counter space
     *   3. The integer truncation in period_ns (1e9/24e6 = 41, not 41.667)
     *      would otherwise cause 1.6% drift (~25 min error per day of uptime)
     *
     * By multiplying mach_absolute_time by period_ns, the division in
     * gt_virt_cnt_read cancels out exactly: mat * 41 / 41 = mat.
     */
    static int64_t period_ns;
    if (!period_ns) {
        mach_timebase_info_data_t info;
        mach_timebase_info(&info);
        /* period = 1e9 / cntfrq.  For 24 MHz: 41 (truncated). */
        uint64_t cntfrq_hz = 1000000000ULL * info.denom / info.numer;
        period_ns = 1000000000LL / cntfrq_hz;
    }
    return (int64_t)mach_absolute_time() * period_ns;
#else
    return get_clock();
#endif
}
