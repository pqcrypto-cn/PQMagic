#ifndef NEV_AKE_REF_OWKEM_H
#define NEV_AKE_REF_OWKEM_H
#include <stdint.h>

void ow_kem_keygen(uint8_t *pk, uint8_t *sk);
void ow_kem_enc_internal(uint8_t *ss, uint8_t *ct, const uint8_t *pk, const uint8_t *rnd);
void ow_kem_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
void ow_kem_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);


#endif //NEV_AKE_REF_OWKEM_H