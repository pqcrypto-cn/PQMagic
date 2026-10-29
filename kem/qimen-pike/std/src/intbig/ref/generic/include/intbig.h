/** @file
 *
 * @authors Luca De Feo, Sina Schaeffler
 *
 * @brief Declarations for big integers in the reference implementation
 */

#ifndef INTBIG_H
#define INTBIG_H

#include <gmp.h>
#include <stdint.h>
#include <tutil.h>
#include <pike_hash.h>

/** @defgroup ibz_all Signed big integers
 * @{
 */

/** @defgroup ibz_t Precise number types
 * @{
 */

/** @brief Type for signed long integers
 *
 * @typedef ibz_t
 *
 * For integers of arbitrary size, used by intbig module, using gmp
 */
typedef mpz_t ibz_t;

/** @brief Type for fractions of integers
 *
 * @typedef ibq_t
 *
 * For fractions of integers of arbitrary size, used by intbig module, using gmp
 */
typedef mpq_t ibq_t;

/** @brief Type for vector of 2 big integers
 *
 * @typedef ibz_vec_2_t
 */
typedef ibz_t ibz_vec_2_t[2];

/** @}
 */

/********************************************************************/

/** @defgroup ibz_c Constants
 * @{
 */

/**
 * Constant zero
 */
extern const ibz_t ibz_const_zero;

/**
 * Constant one
 */
extern const ibz_t ibz_const_one;

/**
 * Constant two
 */
extern const ibz_t ibz_const_two;

/**
 * Constant three
 */
extern const ibz_t ibz_const_three;

/**
 * Constant five
 */
extern const ibz_t ibz_const_five;


/**
 * Constant seven
 */
extern const ibz_t ibz_const_seven;

/** @}
 */

/* constructors/destructors (possibly no-ops) */

/** @defgroup ibz_c Constructors and Destructors
 * @{
 */

void ibz_init(ibz_t *x);
void ibq_init(ibq_t *x);
void ibz_vec_2_init(ibz_vec_2_t *vec);

void ibz_finalize(ibz_t *x);
void ibq_finalize(ibq_t *x);
void ibz_vec_2_finalize(ibz_vec_2_t *vec);

/** @brief overwrites memory before freeing it
 */
void ibz_secure_finalize(ibz_t *x);

/** @brief overwrites memory before freeing it
 */
void ibq_secure_finalize(ibq_t *x);

/** @brief overwrites memory before freeing it
 */
void ibz_vec_2_secure_finalize(ibz_vec_2_t *vec);

/** @}
 */

/** @defgroup ibz_za Basic integer arithmetic
 * @{
 */

/** @brief sum=a+b
 */
void ibz_add(ibz_t *sum, const ibz_t *a, const ibz_t *b);

/** @brief diff=a-b
 */
void ibz_sub(ibz_t *diff, const ibz_t *a, const ibz_t *b);

/** @brief prod=a*b
 */
void ibz_mul(ibz_t *prod, const ibz_t *a, const ibz_t *b);

/** @brief prod=a*2^exp
 */
void ibz_mul_2exp(ibz_t *prod, const ibz_t *a, uint64_t exp);

/** @brief neg=-a
 */
void ibz_neg(ibz_t *neg, const ibz_t *a);

/** @brief abs=|a|
 */
void ibz_abs(ibz_t *abs, const ibz_t *a);

/** @brief Euclidean division of a by b
 *
 * Computes quotient, remainder so that remainder+quotient*b = a where 0<=|remainder|<|b|
 * The quotient is rounded towards zero.
 */
void ibz_div(ibz_t *quotient, ibz_t *remainder, const ibz_t *a, const ibz_t *b);

/** @brief Euclidean division of a by b
 *
 * Computes quotient, remainder so that remainder+quotient*b = a where 0<=|remainder|<|b|
 * The quotient is rounded towards minus infinity.
 */
void ibz_div_floor(ibz_t *q, ibz_t *r, const ibz_t *n, const ibz_t *d);

/** @brief Euclidean division of a by 2^exp
 *
 * Computes a right shift of abs(a) by exp bits, then sets sign(quotient) to sign(a).
 *
 * Division and rounding is as in ibz_div.
 */
void ibz_div_2exp(ibz_t *quotient, const ibz_t *a, uint64_t exp);

/** @brief r = a mod b
 *
 * Assumes valid inputs
 * The sign of the divisor is ignored, the result is always non-negative
 */
void ibz_mod(ibz_t *r, const ibz_t *a, const ibz_t *b);

unsigned long int ibz_mod_ui(const mpz_t *n, unsigned long int d);

/** @brief Test if a = 0 mod b
 */
int ibz_divides(const ibz_t *a, const ibz_t *b);

/** @brief pow=x^e
 *
 * Assumes valid inputs, The case 0^0 yields 1.
 */
void ibz_pow(ibz_t *pow, const ibz_t *x, int64_t e);

/** @brief pow=(x^e) mod m
 *
 * Assumes valid inputs
 */
void ibz_pow_mod(ibz_t *pow, const ibz_t *x, const ibz_t *e, const ibz_t *m);

/** @brief Compare a and b
 *
 * @returns a positive value if a > b, zero if a = b, and a negative value if a < b
 */
int ibz_cmp(const ibz_t *a, const ibz_t *b);

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 */
int ibz_is_zero(const ibz_t *x);

/** @brief Test if x is 1
 *
 * @returns 1 if x=1, 0 otherwise
 */
int ibz_is_one(const ibz_t *x);

/** @brief Test if x is even
 *
 * @returns 1 if x is even, 0 otherwise
 */
int ibz_is_even(const ibz_t *x);

/** @brief set i to value x
 */
void ibz_set(ibz_t *i, int64_t x);

/** @brief set i to integer ontained in string when read as number in base
 *
 * Base should be 10 or 16, and the number should be written without ponctuation or whitespaces
 *
 * Case for base 16 does not matter
 *
 * @returns  1 if the string could be converted to an integer, 0 otherwise
 */
int ibz_set_from_str(ibz_t *i, const char *str, int base);

/** @brief Copy value into target
 */
void ibz_copy(ibz_t *target, const ibz_t *value);

/** @brief Exchange values of a and b
 */
void ibz_swap(ibz_t *a, ibz_t *b);

/** @brief Copy dig array to target, given digits and the length of the dig array
 *
 *  @param target Target ibz_t element
 *  @param dig array of digits
 *  @param dig_len length of the digits array
 */
void ibz_copy_digits(ibz_t *target, const digit_t *dig, int dig_len);
#define ibz_copy_digit_array(I, T)                                                                 \
    do {                                                                                           \
        ibz_copy_digits((I), (T), sizeof(T) / sizeof(*(T)));                                       \
    } while (0)

/** @brief Copy an ibz_t to target digit_t array.
 *  Restrictions: ibz >= 0 and target must hold sufficient elements to hold ibz
 *
 *  @param target Target digit_t array
 *  @param ibz ibz source ibz_t element
 */
void ibz_to_digits(digit_t *target, const ibz_t *ibz);
#define ibz_to_digit_array(T, I)                                                                   \
    do {                                                                                           \
        memset((T), 0, sizeof(T));                                                                 \
        ibz_to_digits((T), (I));                                                                   \
    } while (0)

/** @brief get int64_t equal to the lowest bits of i
 */
int64_t ibz_get(const ibz_t *i);

// void ibz_printf(const char* format, ...);
#define ibz_printf gmp_printf

/** @brief generate random value in [a, b]
 *  assumed that a >= 0 and b >= 0 and a < b
 * @returns 1 on success, 0 on failiure
 */
int ibz_rand_interval_with_state(ibz_t *rand, const ibz_t *a, const ibz_t *b, pike_xof_ctx_t *state);

/** @brief generate random value in [a, b]
 *  assumed that a >= 0 and b >= 0 and a < b
 * @returns 1 on success, 0 on failiure
 */
int ibz_rand_interval(ibz_t *rand, const ibz_t *a, const ibz_t *b);

/** @brief generate random value in [a, b]
 *  assumed that a >= 0, b >= 0 and a < b
 * @returns 1 on success, 0 on failiure
 */
int ibz_rand_interval_i(ibz_t *rand, int64_t a, int64_t b);

/** @brief generate random value in [-m, m]
 *  assumed that m > 0 and bitlength of m < 64 bit
 * @returns 1 on success, 0 on failiure
 */
int ibz_rand_interval_minm_m(ibz_t *rand, int64_t m);

/** @brief Bitsize of a.
 *
 *  @returns Bitsize of a.
 *
 */
int ibz_bitsize(const ibz_t *a);

/* etc....*/

/** @}
 */

/** @defgroup ibz_qa Basic fraction arithmetic
 * @{
 */

/** @brief sum=a+b
 */
void ibq_add(ibq_t *sum, const ibq_t *a, const ibq_t *b);

/** @brief diff=a-b
 */
void ibq_sub(ibq_t *diff, const ibq_t *a, const ibq_t *b);

/** @brief neg=-x
 */
void ibq_neg(ibq_t *neg, const ibq_t *x);

/** @brief abs=|x|
 */
void ibq_abs(ibq_t *abs, const ibq_t *x);

/** @brief prod=a*b
 */
void ibq_mul(ibq_t *prod, const ibq_t *a, const ibq_t *b);

/** @brief inv=1/x
 *
 * @returns 0 if x is 0, 1 if inverse exists and was computed
 */
int ibq_inv(ibq_t *inv, const ibq_t *x);

/** @brief quot = a/b
 * @param quot Output a/b
 * @param a
 * @param b must not be 0
 */
void ibq_div(ibq_t *quot, const ibq_t *a, const ibq_t *b);

/** @brief Compare a and b
 *
 * @returns a positive value if a > b, zero if a = b, and a negative value if a < b
 */
int ibq_cmp(const ibq_t *a, const ibq_t *b);

/** @brief Test if x is 0
 *
 * @returns 1 if x=0, 0 otherwise
 */
int ibq_is_zero(const ibq_t *x);

/** @brief Test if x is 1
 *
 * @returns 1 if x=1, 0 otherwise
 */
int ibq_is_one(const ibq_t *x);

/** @brief Set q to a/b if b not 0
 *
 * @returns 1 if b not 0 and q is set, 0 otherwise
 */
int ibq_set(ibq_t *q, const ibz_t *a, const ibz_t *b);

/** @brief Set x to 0
 *
 * Assumes x is initialized
 */
void ibq_set_zero(ibq_t *x);

/** @brief Set x to 1
 *
 * Assumes x is initialized
 */
void ibq_set_one(ibq_t *x);

/** @brief Copy value into target
 */
void ibq_copy(ibq_t *target, const ibq_t *value);

/** @brief Exchange values of a and b
 */
void ibq_swap(ibq_t *a, ibq_t *b);

/** @brief Denominator of x
 */
void ibq_denom(ibz_t *d, const ibq_t *x);

/** @brief Numerator of x
 */
void ibq_num(ibz_t *n, const ibq_t *x);

/** @brief Checks if q is an integer
 *
 * @returns 1 if yes, 0 if not
 */
int ibq_is_ibz(const ibq_t *q);

/**
 * @brief Converts a fraction q to an integer y, if q is an integer.
 *
 * @returns 1 if z is an integer, 0 if not
 */
int ibq_to_ibz(ibz_t *z, const ibq_t *q);

/** @}
 */

/** @defgroup ibz_n Number theory functions
 * @{
 */

/**
 * @brief Probabilistic primality test
 *
 * @param n The number to test
 * @param reps Number of Miller-Rabin repetitions. The more, the slower and the less likely are
 * false positives
 * @return 1 if probably prime, 0 if certainly not prime, 2 if certainly prime
 *
 * Using GMP's implementation:
 *
 * From GMP's documentation: "This function performs some trial divisions, a Baillie-PSW probable
 * prime test, then reps-24 Miller-Rabin probabilistic primality tests."
 */
int ibz_probab_prime(const ibz_t *n, int reps);

/**
 * @brief Greatest common divisor
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param a
 * @param b
 */
void ibz_gcd(ibz_t *gcd, const ibz_t *a, const ibz_t *b);

/**
 * @brief GCD and Bézout coefficients u, v such that ua + bv = gcd
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param u Output: integer such that ua+bv=gcd
 * @param v Output: Integer such that ua+bv=gcd
 * @param a
 * @param b
 */
void ibz_xgcd(ibz_t *gcd, ibz_t *u, ibz_t *v, const ibz_t *a, const ibz_t *b);

/**
 * @brief GCD, Bézout coefficients u, v such that ua + bv = gcd, and annihilators s, t such that sa
 * + bt = 0
 *
 * @param gcd Output: Set to the gcd of a and b
 * @param s Output: integer such that sa+bt=0
 * @param t Output: Integer such that sa+bt=0
 * @param u Output: integer such that ua+bv=gcd
 * @param v Output: Integer such that ua+bv=gcd
 * @param a
 * @param b
 */
void
ibz_xgcd_ann(ibz_t *gcd, ibz_t *s, ibz_t *t, ibz_t *u, ibz_t *v, const ibz_t *a, const ibz_t *b);

/**
 * @brief Modular inverse
 *
 * @param inv Output: Set to the integer in [0,mod[ such that a*inv = 1 mod (mod) if it exists
 * @param a
 * @param mod
 * @returns 1 if inverse exists and was computed, 0 otherwise
 */
int ibz_invmod(ibz_t *inv, const ibz_t *a, const ibz_t *mod);

/**
 * @brief Chinese remainders
 *
 * @param crt Output: Set so that crt = a mod (mod_a), crt = b mod (mod_b)
 * @param a
 * @param b
 * @param mod_a
 * @param mod_b
 */
void ibz_crt(ibz_t *crt, const ibz_t *a, const ibz_t *b, const ibz_t *mod_a, const ibz_t *mod_b);

/**
 * @brief Kronecker symbol of a mod b
 *
 * @returns Kronecker symbol of a mod b
 * @param a
 * @param b
 *
 * Uses GMP's implementation
 */
int ibz_kronecker(const ibz_t *a, const ibz_t *b);

/**
 * @brief Jacobi symbol of a mod odd
 *
 * @returns jacobi symbol of a mod odd
 * @param a
 * @param odd assumed odd
 *
 * Uses GMP's implementation
 *
 * If output is -1, a is a not a square mod odd
 */
int ibz_jacobi(const ibz_t *a, const ibz_t *odd);

/**
 * @brief Legendre symbol of a mod p
 *
 * @returns Legendre symbol of a mod p
 * @param a
 * @param p assumed prime
 *
 * Uses GMP's implementation
 *
 * If output is 1, a is a square mod p, if -1, not. If 0, it is divisible by p
 */
int ibz_legendre(const ibz_t *a, const ibz_t *p);

/**
 * @brief Integer square root of a perfect square
 *
 * @returns 1 if an integer square root of a exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a integer square root of a if any exist
 * @param a number of which an integer square root is searched
 */
int ibz_sqrt(ibz_t *sqrt, const ibz_t *a);

/**
 * @brief Floor of Integer square root
 *
 * @param sqrt Output: Set to the floor of an integer square root
 * @param a number of which a floor of an integer square root is searched
 */
void ibz_sqrt_floor(ibz_t *sqrt, const ibz_t *a);

/**
 * @brief Square root modulo a prime
 *
 * @returns 1 if square root of a mod p exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root of a mod p if any exist
 * @param a number of which a square root mod p is searched
 * @param p assumed prime
 */
int ibz_sqrt_mod_p(ibz_t *sqrt, const ibz_t *a, const ibz_t *p);

/**
 * @brief Square root modulo a the double of a given prime
 *
 * @returns 1 if square root of a mod (2p) exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root of a mod (2p) if any exist
 * @param a number of which a square root mod (2p) is searched
 * @param p assumed prime
 */
int ibz_sqrt_mod_2p(ibz_t *sqrt, const ibz_t *a, const ibz_t *p);

/**
 * @brief Square root modulo 2power
 * outputs sqrt(a) (mod 2power)
 *
 * @returns 1 if square root exists and was computed, 0 otherwise
 * @param sqrt Output: Set to a square root if any exist
 * @param a number of which a square root is searched
 * @param e assumed power
 */
int ibz_sqrt_mod_2e(ibz_t *sqrt, const ibz_t *a, int e);


/** @}
 */

void ibz_vec_2_set(ibz_vec_2_t *vec, int a0, int a1);

// end of ibz_all
/** @}
 */
#endif
