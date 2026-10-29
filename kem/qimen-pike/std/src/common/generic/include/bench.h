// SPDX-License-Identifier: Apache-2.0

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#if defined(TARGET_OS_UNIX) &&                                                                     \
    (defined(TARGET_ARM) || defined(TARGET_ARM64) || defined(TARGET_OTHER))
#include <time.h>
#endif
#if (defined(TARGET_ARM) || defined(TARGET_ARM64) || defined(TARGET_S390X) || defined(TARGET_OTHER))
#define print_bench_unit printf("nsec\n");
#else
#define print_bench_unit printf("cycles\n");
#endif

#if (defined(TARGET_ARM) || defined(TARGET_ARM64) || defined(TARGET_S390X))
#define BENCH_UNITS "nsec"
#else
#define BENCH_UNITS "cycles"
#endif

static inline int64_t
cpucycles(void)
{
#if (defined(TARGET_AMD64) || defined(TARGET_X86))
    unsigned int hi, lo;

    asm volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((int64_t)lo) | (((int64_t)hi) << 32);
#elif (defined(TARGET_S390X))
    uint64_t tod;
    asm volatile("stckf %0\n" : "=Q"(tod) : : "cc");
    return (tod * 1000 / 4096);
#else
    struct timespec time;
    clock_gettime(CLOCK_REALTIME, &time);
    return (int64_t)(time.tv_sec * 1e9 + time.tv_nsec);
#endif
}

static inline int
cmpfunc(const void *a, const void *b)
{
    return (*(uint64_t *)a - *(uint64_t *)b);
}

#define BENCH_CODE_1(r)                                                                            \
    cycles = 0;                                                                                    \
    for (i = 0; i < (r); ++i) {                                                                    \
        cycles1 = cpucycles();

#define BENCH_CODE_2(name, csv)                                                                    \
    cycles2 = cpucycles();                                                                         \
    if (i < LIST_SIZE)                                                                             \
        cycles_list[i] = (cycles2 - cycles1);                                                      \
    cycles = cycles + (cycles2 - cycles1);                                                         \
    }                                                                                              \
    qsort(cycles_list, (runs < LIST_SIZE) ? runs : LIST_SIZE, sizeof(uint64_t), cmpfunc);          \
    if (csv)                                                                                       \
        printf("%2" PRId64 ",", cycles_list[(runs < LIST_SIZE) ? runs / 2 : LIST_SIZE / 2]);       \
    else {                                                                                         \
        printf("  %-20s-> median: %2" PRId64 ", average: %2" PRId64 " ",                           \
               name,                                                                               \
               cycles_list[(runs < LIST_SIZE) ? runs / 2 : LIST_SIZE / 2],                         \
               (cycles / runs));                                                                   \
        printf("%s\n", BENCH_UNITS);                                                               \
    }
