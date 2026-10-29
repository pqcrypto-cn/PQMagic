#include "pike.h"
#include <time.h>
#include <stdlib.h>
#include <rng.h>
#include <bench.h>

int test_pike(int bench_loops) {
    pike_sk_t sk = {0};
    pike_pk_t pk = {0};
    pike_ct_t ct = {0};
    unsigned char m[PIKE_SHARED_SECRET_BYTES] = {0};
    unsigned char dec_m[PIKE_SHARED_SECRET_BYTES] = {0};
    size_t m_len = 0;
    uint64_t cycles1, cycles2;
    uint64_t cycle_runs[3] = {0};

    for(int i = 0; i < bench_loops; i++) {
        randombytes(m, PIKE_SHARED_SECRET_BYTES);
        cycles1 = cpucycles();
        keygen(&sk, &pk);
        cycles2 = cpucycles();
        cycle_runs[0] += cycles2 - cycles1;
        
        cycles1 = cpucycles();
        encrypt(&ct, &pk, m, PIKE_SHARED_SECRET_BYTES, NULL, 0);
        cycles2 = cpucycles();
        cycle_runs[1] += cycles2 - cycles1;

        cycles1 = cpucycles();
        decrypt(dec_m, &m_len, &ct, &sk);
        cycles2 = cpucycles();
        cycle_runs[2] += cycles2 - cycles1;

        for (int j = 0; j < sizeof(m); j++) {
            if (m[j] != dec_m[j]) return 1;
        }
    }

    printf("test loops : %d\n", bench_loops);
    printf("  keygen takes .................................... %.6f %s\n",
            (double)(cycle_runs[0])/(bench_loops), BENCH_UNITS);
    printf("  encrypt takes .................................... %.6f %s\n",
            (double)(cycle_runs[1])/(bench_loops), BENCH_UNITS);
    printf("  decrypt takes .................................... %.6f %s\n",
            (double)(cycle_runs[2])/(bench_loops), BENCH_UNITS);

    return 0;
}

int main(int argc, char* argv[]) {
    int loops = 100;
    if (argc > 1) {
        loops = atoi(argv[1]);
    }
    return test_pike(loops);
} 
