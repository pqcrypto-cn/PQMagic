#ifndef ALIGN_H
#define ALIGN_H

#if defined(_WIN32) || defined(_WIN64)
#define ALIGN(N) __declspec(align(N)) 
#else
#define ALIGN(N) __attribute__((aligned(N)))
#endif

#endif
