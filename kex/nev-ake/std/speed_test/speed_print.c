#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpucycles.h"
#include "speed_print.h"

static int cmp_ull(const void *a, const void *b)
{
    const unsigned long long x = *(const unsigned long long *)a;
    const unsigned long long y = *(const unsigned long long *)b;
    return (x > y) - (x < y);
}

/* This function sorts its input. Pass it a copy when the original order matters. */
static unsigned long long median(unsigned long long *values, size_t count)
{
    qsort(values, count, sizeof(*values), cmp_ull);

    if ((count & 1U) != 0U)
        return values[count / 2];

    const unsigned long long lo = values[count / 2 - 1];
    const unsigned long long hi = values[count / 2];

    /* Avoid overflow in (lo + hi) / 2. */
    return lo + (hi - lo) / 2;
}

static long double average_ticks(const uint64_t *values,
                                 size_t count)
{
    long double sum = 0.0L;

    for (size_t i = 0; i < count; ++i)
        sum += (long double)values[i];

    return sum / (long double)count;
}

/*
 * Convert the average elapsed TSC ticks in values[] to milliseconds.
 * cpucycles_per_second() returns TSC ticks per second.
 */
static double mtime(const uint64_t *values, size_t count)
{
    const double tsc_hz = cpucycles_per_second();

    if (values == NULL || count == 0 || tsc_hz <= 0.0)
        return -1.0;

    const long double avg = average_ticks(values, count);
    return (double)(avg * 1000.0L / (long double)tsc_hz);
}

void print_results(const char *label,
                   uint64_t *values,
                   size_t count)
{
    unsigned long long *sorted;
    unsigned long long med;
    long double avg;
    double ms;

    if (label == NULL || values == NULL || count == 0) {
        fprintf(stderr, "ERROR: No benchmark samples provided.\n");
        return;
    }

    if (count > SIZE_MAX / sizeof(*sorted)) {
        fprintf(stderr, "ERROR: Too many benchmark samples.\n");
        return;
    }

    sorted = malloc(count * sizeof(*sorted));
    if (sorted == NULL) {
        perror("malloc");
        return;
    }

    memcpy(sorted, values, count * sizeof(*sorted));

    avg = average_ticks(values, count);
    ms = mtime(values, count);
    med = median(sorted, count);

    printf("%s\n", label);
    printf("median: %llu cycles\n", med);
    printf("average: %.2Lf cycles\n", avg);

    if (ms >= 0.0) {
        printf("ms per operation: %.9f\n", ms);

        if (ms > 0.0)
            printf("operations per second: %.3f\n", 1000.0 / ms);
        else
            printf("operations per second: N/A\n");
    } else {
        printf("ms per operation: N/A\n");
        printf("operations per second: N/A\n");
        fprintf(stderr, "WARNING: Could not determine the TSC frequency.\n");
    }

    putchar('\n');
    free(sorted);
}
