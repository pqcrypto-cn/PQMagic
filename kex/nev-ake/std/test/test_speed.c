#include <stdio.h>
#include <time.h>

#include "ake.h"
#include "api.h"

#define ITERATIONS 10

static double milliseconds(clock_t begin, clock_t end)
{
    return 1000.0 * (double)(end - begin) / CLOCKS_PER_SEC / ITERATIONS;
}

int main(void)
{
    unsigned char initiator_pk[KEM_PUBLICKEYBYTES];
    unsigned char initiator_sk[KEM_SECRETKEYBYTES];
    unsigned char responder_pk[KEM_PUBLICKEYBYTES];
    unsigned char responder_sk[KEM_SECRETKEYBYTES];
    unsigned char first_message[AKE_M1_BYTES];
    unsigned char initiator_state[AKE_ST_BYTES];
    unsigned char second_message[AKE_M2_BYTES];
    unsigned char initiator_key[SEED_BYTES];
    unsigned char responder_key[SEED_BYTES];
    unsigned char initiator_id[SEED_BYTES] = {0};
    unsigned char responder_id[SEED_BYTES] = {0};
    clock_t begin;
    clock_t end;

    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        ake_keygen(initiator_pk, initiator_sk, responder_pk, responder_sk);
    end = clock();
    printf("NEV-AKE keygen: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        ake_init(first_message, initiator_state, initiator_sk, responder_pk);
    end = clock();
    printf("NEV-AKE init: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        ake_der_response(second_message, responder_key, initiator_id, responder_id,
                         responder_sk, initiator_pk, first_message);
    end = clock();
    printf("NEV-AKE response: %.3f ms/op\n", milliseconds(begin, end));
    begin = clock();
    for (int i = 0; i < ITERATIONS; ++i)
        ake_der_init(initiator_key, initiator_id, responder_id, initiator_sk,
                     responder_pk, initiator_state, second_message);
    end = clock();
    printf("NEV-AKE derive: %.3f ms/op\n", milliseconds(begin, end));
    return 0;
}
