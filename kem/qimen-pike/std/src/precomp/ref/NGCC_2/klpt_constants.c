#include <stddef.h>
#include <stdint.h>
#include <klpt_constants.h>
#if 0
#elif 8*DIGIT_LEN == 16
const short SMALL_PRIMES_1MOD4[11] = {0x5, 0xd, 0x11, 0x1d, 0x25, 0x29, 0x35, 0x3d, 0x49, 0x59, 0x61};
const ibz_t PROD_SMALL_PRIMES_3MOD4 = {{._mp_alloc = 0, ._mp_size = 4, ._mp_d = (mp_limb_t[]) {0x173b,0x80bd,0xa9d7,0xa185}}};
#elif 8*DIGIT_LEN == 32
const short SMALL_PRIMES_1MOD4[11] = {0x5, 0xd, 0x11, 0x1d, 0x25, 0x29, 0x35, 0x3d, 0x49, 0x59, 0x61};
const ibz_t PROD_SMALL_PRIMES_3MOD4 = {{._mp_alloc = 0, ._mp_size = 2, ._mp_d = (mp_limb_t[]) {0x80bd173b,0xa185a9d7}}};
#elif 8*DIGIT_LEN == 64
const short SMALL_PRIMES_1MOD4[11] = {0x5, 0xd, 0x11, 0x1d, 0x25, 0x29, 0x35, 0x3d, 0x49, 0x59, 0x61};
const ibz_t PROD_SMALL_PRIMES_3MOD4 = {{._mp_alloc = 0, ._mp_size = 1, ._mp_d = (mp_limb_t[]) {0xa185a9d780bd173b}}};
#endif
