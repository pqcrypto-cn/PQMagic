#ifndef INDCPA_H
#define INDCPA_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define gen_matrix ML_KEM_NAMESPACE(_gen_matrix)
void gen_matrix(polyvec *a, const uint8_t seed[ML_KEM_SYMBYTES], int transposed);
#define indcpa_keypair ML_KEM_NAMESPACE(_indcpa_keypair)
void indcpa_keypair(uint8_t pk[ML_KEM_INDCPA_PUBLICKEYBYTES],
                    uint8_t sk[ML_KEM_INDCPA_SECRETKEYBYTES],
                    const uint8_t coins[ML_KEM_SYMBYTES]);

#define indcpa_enc ML_KEM_NAMESPACE(_indcpa_enc)
void indcpa_enc(uint8_t c[ML_KEM_INDCPA_BYTES],
                const uint8_t m[ML_KEM_INDCPA_MSGBYTES],
                const uint8_t pk[ML_KEM_INDCPA_PUBLICKEYBYTES],
                const uint8_t coins[ML_KEM_SYMBYTES]);

#define indcpa_dec ML_KEM_NAMESPACE(_indcpa_dec)
void indcpa_dec(uint8_t m[ML_KEM_INDCPA_MSGBYTES],
                const uint8_t c[ML_KEM_INDCPA_BYTES],
                const uint8_t sk[ML_KEM_INDCPA_SECRETKEYBYTES]);

#endif
