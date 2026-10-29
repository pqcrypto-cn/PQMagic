#include <stdio.h>
#include <string.h>

#include "ake.h"
#include "api.h"

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

    ake_keygen(initiator_pk, initiator_sk, responder_pk, responder_sk);
    ake_init(first_message, initiator_state, initiator_sk, responder_pk);
    ake_der_response(second_message, responder_key, initiator_id, responder_id,
                     responder_sk, initiator_pk, first_message);
    ake_der_init(initiator_key, initiator_id, responder_id, initiator_sk,
                 responder_pk, initiator_state, second_message);

    if (memcmp(initiator_key, responder_key, sizeof(initiator_key)) != 0) {
        fputs("NEV-AKE session-key mismatch\n", stderr);
        return 1;
    }

    puts("NEV-AKE correctness test passed");
    return 0;
}
