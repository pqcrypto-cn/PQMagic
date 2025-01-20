#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#include <stdint.h>

#if (defined(__i386__)) || (defined(__x86_64__)) // x86/64

# ifdef USE_RDPMC  /* Needs echo 2 > /sys/devices/cpu/rdpmc */

static inline uint64_t cpucycles(void) {
  const uint32_t ecx = (1U << 30) + 1;
  uint64_t result;

  __asm__ volatile ("rdpmc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : "c" (ecx) : "rdx");

  return result;
}

# else

static inline uint64_t cpucycles(void) {
  uint64_t result;

  __asm__ volatile ("rdtsc; shlq $32,%%rdx; orq %%rdx,%%rax"
    : "=a" (result) : : "%rdx");

  return result;
}

# endif

#elif (defined(__arm__)) || (defined(__aarch64__)) // arm

static inline uint64_t cpucycles(void) {
  uint64_t result;

  /*
    * According to ARM DDI 0487F.c, from Armv8.0 to Armv8.5 inclusive, the
    * system counter is at least 56 bits wide; from Armv8.6, the counter
    * must be 64 bits wide.  So the system counter could be less than 64
    * bits wide and it is attributed with the flag 'cap_user_time_short'
    * is true.
    */
  __asm__ volatile("mrs %0, cntvct_el0" : "=r" (result));

  return result;
}

#endif

uint64_t cpucycles_overhead(void);

#endif
