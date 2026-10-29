#include <stdio.h>
#include <time.h>

static clock_t global_timer;

clock_t
tic()
{
    global_timer = clock();
    return global_timer;
}

float
tac()
{
    float ms = (1000. * (float)(clock() - global_timer) / CLOCKS_PER_SEC);
    return ms;
}

float
TAC(const char *str)
{
    float ms = (1000. * (float)(clock() - global_timer) / CLOCKS_PER_SEC);
#ifndef NDEBUG
    printf("%s [%d ms]\n", str, (int)ms);
#endif
    return ms;
}

float
toc(const clock_t t)
{
    float ms = (1000. * (float)(clock() - t) / CLOCKS_PER_SEC);
    return ms;
}

float
TOC(const clock_t t, const char *str)
{
    float ms = (1000. * (float)(clock() - t) / CLOCKS_PER_SEC);
    printf("%s [%d ms]\n", str, (int)ms);
    return ms;
    // printf("%s [%ld]\n",str,clock()-t);
    // return (float) (clock()-t);
}

float
TOC_clock(const clock_t t, const char *str)
{
    printf("%s [%ld]\n", str, clock() - t);
    return (float)(clock() - t);
}

clock_t
dclock(const clock_t t)
{
    return (clock() - t);
}

float
clock_to_time(const clock_t t, const char *str)
{
    float ms = (1000. * (float)(t) / CLOCKS_PER_SEC);
    printf("%s [%d ms]\n", str, (int)ms);
    return ms;
    // printf("%s [%ld]\n",str,t);
    // return (float) (t);
}

float
clock_print(const clock_t t, const char *str)
{
    printf("%s [%ld]\n", str, t);
    return (float)(t);
}

int
two_adic_valuation(int n)
{
    if (n == 0)
        return 0; // 2-adic valuation of 0 is 0

    int count = 0;
    while ((n & 1) == 0) {
        n >>= 1; // Right shift by 1 is equivalent to division by 2
        count++;
    }
    return count;
}