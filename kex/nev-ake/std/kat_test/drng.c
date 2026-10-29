/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "drng.h"

#define OUTLEN (32)
#define DRNG_SUCCESS 0
#define DRNG_MEMORY_ALLOCATION_FAILED -2

#define MIN_INT(a, b) ((a) < (b) ? (a) : (b))
#define MAX_INT(a, b) ((a) > (b) ? (a) : (b))
#define DIVISION_ROUND_UP(dividend, divisor, result) \
    do                                               \
    {                                                \
        (result) = (dividend) / (divisor);           \
        if ((dividend) % (divisor))                  \
            (result)++;                              \
    } while (0)

#define HIGH_N_BIT_MASK(N) ((unsigned char)((~0U) << (8 - (N))))
#define FF1(x, y, z) ((x) ^ (y) ^ (z))
#define FF2(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define GG1(x, y, z) ((x) ^ (y) ^ (z))
#define GG2(x, y, z) ((((y) ^ (z)) & (x)) ^ (z))
#define L_SHIFT(a, n) ((a) << (n) | ((a) & 0xFFFFFFFF) >> (32 - (n)))
#define P0(x) ((x) ^ L_SHIFT((x), 9) ^ L_SHIFT((x), 17))
#define P1(x) ((x) ^ L_SHIFT((x), 15) ^ L_SHIFT((x), 23))
#define PUT32(a, b) ((a)[0] = (unsigned char)((b) >> 24), \
                     (a)[1] = (unsigned char)((b) >> 16), \
                     (a)[2] = (unsigned char)((b) >> 8),  \
                     (a)[3] = (unsigned char)(b))

static void sm3_bit_init(unsigned int *init_digest)
{
    init_digest[0] = 0x7380166F;
    init_digest[1] = 0x4914B2B9;
    init_digest[2] = 0x172442D7;
    init_digest[3] = 0xDA8A0600;
    init_digest[4] = 0xA96F30BC;
    init_digest[5] = 0x163138AA;
    init_digest[6] = 0xE38DEE4D;
    init_digest[7] = 0xB0FB0E4E;
}

static void sm3_bit_compress(unsigned int dgst[8], const unsigned char *msg, unsigned long long blocks)
{
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int W[68];
    unsigned int W_prime[64];
    unsigned int SS1, SS2, TT1, TT2;
    int i;
    while (blocks--)
    {
        /************************Round function************************/
        for (i = 0; i < 16; i++)
        {
            W[i] = ((unsigned int)(msg + i * 4)[0] << 24 | (unsigned int)(msg + i * 4)[1] << 16 | (unsigned int)(msg + i * 4)[2] << 8 | (unsigned int)(msg + i * 4)[3]);
        }
        for (; i < 68; i++)
        {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ L_SHIFT(W[i - 3], 15)) ^ L_SHIFT(W[i - 13], 7) ^ W[i - 6];
        }
        for (i = 0; i < 64; i++)
        {
            W_prime[i] = W[i] ^ W[i + 4];
        }
        A = dgst[0];
        B = dgst[1];
        C = dgst[2];
        D = dgst[3];
        E = dgst[4];
        F = dgst[5];
        G = dgst[6];
        H = dgst[7];
        for (i = 0; i < 64; i++)
        {
            if (i < 16)
            {
                SS1 = L_SHIFT(L_SHIFT(A, 12) + E + L_SHIFT(0x79cc4519U, i & 0x1F), 7);
            }
            else
            {
                SS1 = L_SHIFT(L_SHIFT(A, 12) + E + L_SHIFT(0x7a879d8aU, i & 0x1F), 7);
            }
            SS2 = SS1 ^ L_SHIFT(A, 12);
            if (i < 16)
            {
                TT1 = FF1(A, B, C) + D + SS2 + W_prime[i];
                TT2 = GG1(E, F, G) + H + SS1 + W[i];
            }
            else
            {
                TT1 = FF2(A, B, C) + D + SS2 + W_prime[i];
                TT2 = GG2(E, F, G) + H + SS1 + W[i];
            }
            D = C;
            C = L_SHIFT(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = L_SHIFT(F, 19);
            F = E;
            E = P0(TT2);
        }
        dgst[0] ^= A;
        dgst[1] ^= B;
        dgst[2] ^= C;
        dgst[3] ^= D;
        dgst[4] ^= E;
        dgst[5] ^= F;
        dgst[6] ^= G;
        dgst[7] ^= H;
        msg += 64;
    }
}

static void sm3_bit(const unsigned char *msg, unsigned long long msg_bitlen, unsigned char *dgst)
{
    unsigned long long block_num;
    unsigned long long remain;
    block_num = msg_bitlen / 512;
    remain = msg_bitlen & 0x1FF;
    /**********************Initializing value**********************/
    unsigned int digest[8];
    sm3_bit_init(digest);
    /************************Round function************************/
    if (block_num != 0)
    {
        sm3_bit_compress(digest, msg, block_num);
    }
    unsigned char block[64];
    memset(block, 0, 64);
    memcpy(block, msg + block_num * 64, (remain + 7) >> 3);
    block[remain >> 3] &= ((0xFF00 >> (remain & 0x7)) & 0xFF);
    block[remain >> 3] |= (1 << (7 - (remain & 0x7)));
    /***************************Padding****************************/
    if (remain <= 512 - 65)
    {
        memset(block + (remain >> 3) + 1, 0, (512 - remain - 65) >> 3);
    }
    else
    {
        memset(block + (remain >> 3) + 1, 0, (512 - remain - 1) >> 3);
        sm3_bit_compress(digest, block, 1);
        memset(block, 0, 64 - 8);
    }
    PUT32(block + 56, block_num >> 32 << 9);
    PUT32(block + 60, (block_num << 9) + (remain));
    /************************Round function************************/
    sm3_bit_compress(digest, block, 1);
    /**********************Output hash value***********************/
    for (int i = 0; i < 8; i++)
    {
        PUT32(dgst + i * 4, digest[i]);
    }
}

static void u32_to_u8_big_endian(unsigned int u32, unsigned char u8[4])
{
    u8[0] = (unsigned char)((u32 >> 24) & 0xFF);
    u8[1] = (unsigned char)((u32 >> 16) & 0xFF);
    u8[2] = (unsigned char)((u32 >> 8) & 0xFF);
    u8[3] = (unsigned char)((u32 >> 0) & 0xFF);
}

static void inc_Big_Number(unsigned char *BN, unsigned long long BN_len_bytes)
{
    for (; BN_len_bytes != 0; BN_len_bytes--)
    {
        BN[BN_len_bytes - 1] += 1;
        if (BN[BN_len_bytes - 1])
            break;
    }
}

static void plus_Big_Number(unsigned char *BN1, const unsigned char *BN2, const unsigned char *BN3, const unsigned char *BN4, unsigned long long BN_len_bytes)
{
    unsigned int sum;
    unsigned char carry = 0;

    for (; BN_len_bytes != 0; BN_len_bytes--)
    {
        sum = BN1[BN_len_bytes - 1] + BN2[BN_len_bytes - 1] + BN3[BN_len_bytes - 1] + BN4[BN_len_bytes - 1] + carry;
        carry = sum / (0xFFU + 1);
        BN1[BN_len_bytes - 1] = (unsigned char)(sum & 0xFFU);
    }
}

static int SM3_df(unsigned char *input_string, unsigned long long input_string_len_bytes)
{
    unsigned char temp[(1 + SEEDLEN / OUTLEN) * OUTLEN];
    unsigned long long len;
    unsigned char counter;
    unsigned char *data_to_SM3 = NULL;
    unsigned long long data_to_SM3_len_bytes;
    unsigned char sm3_dgst[OUTLEN];
    unsigned char number_of_bits_to_return_big_endian[4];

    memset(temp, 0, sizeof(temp));
    DIVISION_ROUND_UP(SEEDLEN, OUTLEN, len);
    counter = 0x01;
    for (unsigned long long i = 0; i < len; i++)
    {
        data_to_SM3_len_bytes = sizeof(counter) + sizeof(number_of_bits_to_return_big_endian) + input_string_len_bytes;
        data_to_SM3 = (unsigned char *)malloc(data_to_SM3_len_bytes);
        if (NULL == data_to_SM3)
        {
            fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
            return DRNG_MEMORY_ALLOCATION_FAILED;
        }
        data_to_SM3[0] = counter;
        u32_to_u8_big_endian(8 * SEEDLEN, number_of_bits_to_return_big_endian);
        memcpy(data_to_SM3 + sizeof(counter), number_of_bits_to_return_big_endian, sizeof(number_of_bits_to_return_big_endian));
        memcpy(data_to_SM3 + sizeof(counter) + sizeof(number_of_bits_to_return_big_endian), input_string, input_string_len_bytes);
        sm3_bit(data_to_SM3, data_to_SM3_len_bytes * 8, sm3_dgst);
        memcpy(temp + i * OUTLEN, sm3_dgst, OUTLEN);
        free(data_to_SM3);
        data_to_SM3 = NULL;
        counter++;
    }
    memcpy(input_string, temp, SEEDLEN);

    return DRNG_SUCCESS;
}

static int SM3_DRNG_Instantiate(DRNG_ctx *drng, const unsigned char *nonce, unsigned long long nonce_len_bytes)
{
    unsigned char *seed_material = NULL;
    unsigned char seed[SEEDLEN];
    unsigned char padded_V[1 + sizeof(drng->V)];

    memset(drng, 0, sizeof(*drng));
    seed_material = (unsigned char *)malloc(MAX_INT(nonce_len_bytes, SEEDLEN));
    if (NULL == seed_material)
    {
        fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
        return DRNG_MEMORY_ALLOCATION_FAILED;
    }
    memset(seed_material, 0, MAX_INT(nonce_len_bytes, SEEDLEN));
    memcpy(seed_material, nonce, nonce_len_bytes);
    SM3_df(seed_material, nonce_len_bytes);
    memcpy(seed, seed_material, sizeof(seed));
    memcpy(drng->V, seed, sizeof(drng->V));
    padded_V[0] = 0x00;
    memcpy(padded_V + 1, drng->V, sizeof(drng->V));
    SM3_df(padded_V, sizeof(padded_V));
    memcpy(drng->C, padded_V, sizeof(drng->C));
    inc_Big_Number(drng->reseed_counter, SEEDLEN);

    free(seed_material);
    return DRNG_SUCCESS;
}

static int SM3_DRNG_Generate(DRNG_ctx *drng, unsigned long long requested_no_of_bits, unsigned char *return_bits)
{
    unsigned long long m;
    unsigned char data[SEEDLEN];
    unsigned char w[OUTLEN];
    unsigned char padded_V[1 + sizeof(drng->V)];
    unsigned char H[SEEDLEN];
    unsigned long long requested_no_of_Byte;
    unsigned long long remainder_Byte;

    DIVISION_ROUND_UP(requested_no_of_bits, OUTLEN * 8, m);
    memcpy(data, drng->V, SEEDLEN);
    DIVISION_ROUND_UP(requested_no_of_bits, 8, requested_no_of_Byte);
    remainder_Byte = requested_no_of_Byte;
    for (unsigned long long i = 0; i < m; i++)
    {
        sm3_bit(data, SEEDLEN * 8, w);
        if (remainder_Byte >= sizeof(w))
        {
            memcpy(return_bits + OUTLEN * i, w, sizeof(w));
            remainder_Byte -= sizeof(w);
        }
        else
        {
            for (unsigned long long j = 0; j < sizeof(w); j++)
            {
                return_bits[OUTLEN * i + j] = w[j];
                remainder_Byte--;
                if (!remainder_Byte)
                {
                    break;
                }
            }
        }

        inc_Big_Number(data, SEEDLEN);
    }

    if (requested_no_of_Byte >= 1)
    {
        return_bits[requested_no_of_Byte - 1] &= HIGH_N_BIT_MASK(8 - (8 * requested_no_of_Byte - requested_no_of_bits));
    }
    memset(H, 0, sizeof(H));
    padded_V[0] = 0x03;
    memcpy(padded_V + 1, drng->V, sizeof(drng->V));
    sm3_bit(padded_V, sizeof(padded_V) * 8, H + (SEEDLEN - OUTLEN));
    plus_Big_Number(drng->V, H, drng->C, drng->reseed_counter, SEEDLEN);
    inc_Big_Number(drng->reseed_counter, SEEDLEN);

    return DRNG_SUCCESS;
}

int init_random_number(DRNG_ctx *drng, const unsigned char *seed, unsigned long long seed_len_bytes)
{
    return SM3_DRNG_Instantiate(drng, seed, seed_len_bytes);
}

int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}