#define _POSIX_C_SOURCE 200809L
#include "cpucycles.h"
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <x86intrin.h>

#ifdef CLOCK_MONOTONIC_RAW
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

uint64_t cpucycles(void)
{
    uint64_t result;

    __asm__ volatile("" ::: "memory");
    _mm_lfence();
    result = __rdtsc();
    _mm_lfence();
    __asm__ volatile("" ::: "memory");

    return result;
}

uint64_t cpucycles_overhead(void)
{
    uint64_t overhead = UINT64_MAX;

    for (size_t i = 0; i < 10000; ++i) {
        const uint64_t t0 = cpucycles();
        const uint64_t t1 = cpucycles();
        const uint64_t delta = t1 - t0;
        if (delta < overhead)
            overhead = delta;
    }
    return overhead;
}

static double timespec_diff_seconds(const struct timespec *end,
                                    const struct timespec *begin)
{
    return (double)(end->tv_sec - begin->tv_sec)
         + (double)(end->tv_nsec - begin->tv_nsec) * 1e-9;
}

static uint64_t tsc_at_clock_read(struct timespec *ts)
{
    const uint64_t before = cpucycles();
    if (clock_gettime(BENCH_CLOCK, ts) != 0)
        return 0;
    const uint64_t after = cpucycles();
    return before + (after - before) / 2;
}

static int cmp_double(const void *a, const void *b)
{
    const double x = *(const double *)a;
    const double y = *(const double *)b;
    return (x > y) - (x < y);
}

double cpucycles_per_second(void)
{
    static double cached_hz = 0.0;
    double samples[5];

    if (cached_hz > 0.0)
        return cached_hz;

    for (size_t i = 0; i < 5; ++i) {
        struct timespec begin, end;
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000L };
        const uint64_t c0 = tsc_at_clock_read(&begin);

        if (c0 == 0)
            return 0.0;

        while (nanosleep(&delay, &delay) != 0) {
            if (errno != EINTR)
                return 0.0;
        }

        const uint64_t c1 = tsc_at_clock_read(&end);
        const double seconds = timespec_diff_seconds(&end, &begin);
        if (c1 <= c0 || seconds <= 0.0)
            return 0.0;

        samples[i] = (double)(c1 - c0) / seconds;
    }

    qsort(samples, 5, sizeof(samples[0]), cmp_double);
    cached_hz = samples[2];
    return cached_hz;
}
