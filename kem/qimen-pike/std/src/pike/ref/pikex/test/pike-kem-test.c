#include "pike.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <rng.h>
#include <bench.h>

int test_pike_kem(int bench_loops) {
    pike_sk_t sk = {0};
    pike_pk_t pk = {0};
    pike_ct_t ct = {0};
    unsigned char encap_key[PIKE_SHARED_SECRET_BYTES] = {0};
    unsigned char decap_key[PIKE_SHARED_SECRET_BYTES] = {0};
    size_t m_len = 0;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[3] = {0};
    uint8_t s[PIKE_SHARED_SECRET_BYTES] = {0};

    for(int i = 0; i < bench_loops; i++) {
        cycles1 = cpucycles();
        randombytes(s, PIKE_SHARED_SECRET_BYTES);
        keygen(&sk, &pk);
        cycles2 = cpucycles();
        cycle_runs[0] += cycles2 - cycles1;
        
        cycles1 = cpucycles();
        encaps(encap_key, &ct, &pk);
        cycles2 = cpucycles();
        cycle_runs[1] += cycles2 - cycles1;

        cycles1 = cpucycles();
        decaps(decap_key, &ct, &pk, &sk, s);
        cycles2 = cpucycles();
        cycle_runs[2] += cycles2 - cycles1;

        if (memcmp(encap_key, decap_key, PIKE_SHARED_SECRET_BYTES) != 0) {
            return 1;
        }
    }

    printf("test loops : %d\n", bench_loops);
    printf("  keygen takes .................................... %.6f %s\n",
            (double)(cycle_runs[0])/(bench_loops), BENCH_UNITS);
    printf("  encaps takes .................................... %.6f %s\n",
            (double)(cycle_runs[1])/(bench_loops), BENCH_UNITS);
    printf("  decaps takes .................................... %.6f %s\n",
            (double)(cycle_runs[2])/(bench_loops), BENCH_UNITS);

    return 0;
}

int test_pike_encode_decode(int bench_loops) {
    pike_sk_t sk = {0}, sk2 = {0};
    pike_pk_t pk = {0}, pk2 = {0};
    pike_ct_t ct = {0}, ct2 = {0};
    unsigned char pk_buf[PIKE_PK_ENCODED_BYTES];
    unsigned char sk_buf[PIKE_SK_ENCODED_BYTES];
    unsigned char ct_buf[PIKE_CT_ENCODED_BYTES];
    unsigned char ct_buf2[PIKE_CT_ENCODED_BYTES];
    unsigned char m[PIKE_SHARED_SECRET_BYTES], dec_m[PIKE_SHARED_SECRET_BYTES];
    size_t m_len = 0;

    for (int i = 0; i < bench_loops; i++) {
        randombytes(m, PIKE_SHARED_SECRET_BYTES);
        keygen(&sk, &pk);

        sk_encode(sk_buf, &sk);
        sk_decode(&sk2, sk_buf);
        if (memcmp(sk.deg, sk2.deg, sizeof(sk.deg)) != 0 ||
            memcmp(sk.alpha, sk2.alpha, sizeof(sk.alpha)) != 0 ||
            memcmp(sk.beta, sk2.beta, sizeof(sk.beta)) != 0 ||
            memcmp(sk.iota, sk2.iota, sizeof(sk.iota)) != 0) {
            return 1;
        }

        pk_encode(pk_buf, &pk);
        pk_decode(&pk2, pk_buf);
        {
            unsigned char pk_buf2[PIKE_PK_ENCODED_BYTES];
            pk_encode(pk_buf2, &pk2);
            if (memcmp(pk_buf, pk_buf2, PIKE_PK_ENCODED_BYTES) != 0) {
                return 1;
            }
        }

        encrypt(&ct, &pk, m, PIKE_SHARED_SECRET_BYTES, NULL, 0);
        ct_encode(ct_buf, &ct);
        ct_decode(&ct2, ct_buf);
        ct_encode(ct_buf2, &ct2);
        if (memcmp(ct_buf, ct_buf2, PIKE_CT_ENCODED_BYTES) != 0) {
            return 1;
        }

        decrypt(dec_m, &m_len, &ct, &sk);
        if (memcmp(m, dec_m, PIKE_SHARED_SECRET_BYTES) != 0) {
            return 1;
        }

        decrypt(dec_m, &m_len, &ct, &sk2);
        if (memcmp(m, dec_m, PIKE_SHARED_SECRET_BYTES) != 0) {
            return 1;
        }
    }

    printf("Encode/decode test loops : %d  -- all passed\n", bench_loops);
    return 0;
}

int main(int argc, char* argv[]) {
    int loops = 100;
    if (argc > 1) {
        loops = atoi(argv[1]);
    }
    if (test_pike_kem(loops) != 0) {
        return 1;
    }
    return test_pike_encode_decode(loops);
} 
