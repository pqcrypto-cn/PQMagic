// TODO this should be its own module
#include "mp.h"
#include <assert.h>

// The below functions were taken from the GF module

void
MUL(digit_t *out, const digit_t a, const digit_t b)
{ // Digit multiplication, digit*digit -> 2-digit result
  // Inputs: a, b in [0, 2^w-1], where w is the computer wordsize
  // Output: 0 < out < 2^(2w)-1
    register digit_t al, ah, bl, bh, temp;
    digit_t albl, albh, ahbl, ahbh, res1, res2, res3, carry;
    digit_t mask_low = (digit_t)(-1) >> (sizeof(digit_t) * 4), mask_high = (digit_t)(-1)
                                                                           << (sizeof(digit_t) * 4);

    al = a & mask_low;               // Low part
    ah = a >> (sizeof(digit_t) * 4); // High part
    bl = b & mask_low;
    bh = b >> (sizeof(digit_t) * 4);

    albl = al * bl;
    albh = al * bh;
    ahbl = ah * bl;
    ahbh = ah * bh;
    out[0] = albl & mask_low; // out00

    res1 = albl >> (sizeof(digit_t) * 4);
    res2 = ahbl & mask_low;
    res3 = albh & mask_low;
    temp = res1 + res2 + res3;
    carry = temp >> (sizeof(digit_t) * 4);
    out[0] ^= temp << (sizeof(digit_t) * 4); // out01

    res1 = ahbl >> (sizeof(digit_t) * 4);
    res2 = albh >> (sizeof(digit_t) * 4);
    res3 = ahbh & mask_low;
    temp = res1 + res2 + res3 + carry;
    out[1] = temp & mask_low; // out10
    carry = temp & mask_high;
    out[1] ^= (ahbh & mask_high) + carry; // out11
}

void
mp_add(digit_t *c, const digit_t *a, const digit_t *b, const unsigned int nwords)
{ // Multiprecision addition
    unsigned int i, carry = 0;

    for (i = 0; i < nwords; i++) {
        ADDC(c[i], carry, a[i], b[i], carry);
    }
}

digit_t
mp_shiftr(digit_t *x, const unsigned int shift, const unsigned int nwords)
{ // Multiprecision right shift
    digit_t bit_out = x[0] & 1;

    for (unsigned int i = 0; i < nwords - 1; i++) {
        SHIFTR(x[i + 1], x[i], shift, x[i], RADIX);
    }
    x[nwords - 1] >>= shift;
    return bit_out;
}

void
mp_shiftl(digit_t *x, const unsigned int shift, const unsigned int nwords)
{ // Multiprecision left shift of at most 64

    for (int i = nwords - 1; i > 0; i--) {
        SHIFTL(x[i], x[i - 1], shift, x[i], RADIX);
    }
    x[0] <<= shift;
}

void
multiple_mp_shiftl(digit_t *x, const unsigned int shift, const unsigned int nwords)
{
    int t = shift;
    while (t > 60) {
        mp_shiftl(x, 60, nwords);
        t = t - 60;
    }
    mp_shiftl(x, t, nwords);
}

// The below functions were taken from the EC module

void
mp_sub(digit_t *c, const digit_t *a, const digit_t *b, const unsigned int nwords)
{ // Multiprecision subtraction, assuming a > b
    unsigned int i, borrow = 0;

    for (i = 0; i < nwords; i++) {
        SUBC(c[i], borrow, a[i], b[i], borrow);
    }
}

void
select_ct(digit_t *c, const digit_t *a, const digit_t *b, const digit_t mask, const int nwords)
{ // Select c <- a if mask = 0, select c <- b if mask = 1...1

    for (int i = 0; i < nwords; i++) {
        c[i] = ((a[i] ^ b[i]) & mask) ^ a[i];
    }
}

void
swap_ct(digit_t *a, digit_t *b, const digit_t option, const int nwords)
{ // Swap entries
  // If option = 0 then P <- P and Q <- Q, else if option = 0xFF...FF then a <- b and b <- a
    digit_t temp;

    for (int i = 0; i < nwords; i++) {
        temp = option & (a[i] ^ b[i]);
        a[i] = temp ^ a[i];
        b[i] = temp ^ b[i];
    }
}

int
mp_compare(digit_t *a, digit_t *b, unsigned int nwords)
{ // Multiprecision comparison, a=b? : (1) a>b, (0) a=b, (-1) a<b

    for (int i = nwords - 1; i >= 0; i--) {
        if (a[i] > b[i])
            return 1;
        else if (a[i] < b[i])
            return -1;
    }
    return 0;
}

bool
mp_is_zero(const digit_t *a, unsigned int nwords)
{ // Is a multiprecision element zero?
  // Returns 1 (true) if a=0, 0 (false) otherwise
    digit_t r = 0;

    for (unsigned int i = 0; i < nwords; i++)
        r |= a[i] ^ 0;

    return (bool)is_digit_zero_ct(r);
}

void
mp_mul2(digit_t *c, const digit_t *a, const digit_t *b)
{ // Multiprecision multiplication fixed to two-digit operands
    unsigned int carry = 0;
    digit_t t0[2], t1[2], t2[2];

    MUL(t0, a[0], b[0]);
    MUL(t1, a[0], b[1]);
    ADDC(t0[1], carry, t0[1], t1[0], carry);
    ADDC(t1[1], carry, 0, t1[1], carry);
    MUL(t2, a[1], b[1]);
    ADDC(t2[0], carry, t2[0], t1[1], carry);
    ADDC(t2[1], carry, 0, t2[1], carry);
    c[0] = t0[0];
    c[1] = t0[1];
    c[2] = t2[0];
    c[3] = t2[1];
}

void
mp_mul_generic(digit_t *c, const digit_t *a, const digit_t b, unsigned int nwords)
{
    digit_t t[2], result[50] = {0,};
    assert(nwords < 50);
    unsigned int carry = 0;
    for(unsigned int i = 0; i < nwords; i++){
        MUL(t, a[i], b);
        ADDC(result[i], carry, result[i], t[0], carry);
        ADDC(result[i + 1], carry, result[i + 1], t[1], carry);
    }

    for(unsigned int i = 0; i < nwords ; i++) c[i] = result[i];
}

void
mp_mul_generic_md(digit_t *c, const digit_t *a, const digit_t *b, unsigned int nwords)
{
    digit_t t[2];
    digit_t result[100] = {0};
    assert(nwords < 50);

    for (unsigned int i = 0; i < nwords; i++) {
        digit_t carry = 0;

        for (unsigned int j = 0; j < nwords; j++) {
            digit_t c1, c2, s;

            MUL(t, a[i], b[j]);

            ADDC(s, c1, result[i + j], t[0], 0);
            ADDC(result[i + j], c2, s, carry, 0);

            carry = t[1] + c1 + c2;
        }

        // result[i + nwords] += carry
        unsigned int k = i + nwords;
        while (carry) {
            digit_t c1;
            ADDC(result[k], c1, result[k], carry, 0);
            carry = c1;
            k++;
        }
    }

    for (unsigned int i = 0; i < nwords; i++) {
        c[i] = result[i];
    }
}