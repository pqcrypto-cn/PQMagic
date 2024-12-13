#ifndef _BENCHTIME_H_
#define _BENCHTIME_H_


// #define BENCHTIME

#ifdef BENCHTIME
#include <time.h>
#define TIME(code)      \
    do {                \
        clock_t s, e;   \
        s = clock();    \
        code;           \
        e = clock() - s;    \
        printf("%s --- running ---- %lfms\n", #code, (double)e/1000);\
    } while(0)
#else
#define TIME(code) code
#endif

#endif