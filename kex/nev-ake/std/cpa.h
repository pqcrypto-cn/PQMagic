#ifndef NEV_PKE_H
#define NEV_PKE_H
#include <stdint.h>

void kem_cpa_keygen(uint8_t *pk, uint8_t *sk);

void kem_cpa_enc(uint8_t *c, uint8_t *ss, const uint8_t *pk);

void kem_cpa_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

void pke_cpa_keygen(uint8_t *pk, uint8_t *sk);

void pke_cpa_enc(uint8_t *ct, const uint8_t *m, const uint8_t *pk);

void pke_cpa_dec(uint8_t *m, const uint8_t *ct, const uint8_t *sk);
#endif //NEV_PKE_H