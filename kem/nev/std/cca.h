#ifndef NEV_KEM_H
#define NEV_KEM_H
#include <stdint.h>

int kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

void pke_cca_keygen(uint8_t *pk, uint8_t *sk);
void pke_cca_enc(uint8_t *ct, const uint8_t *mu, const uint8_t *pk);
int pke_cca_dec(uint8_t *mu, const uint8_t *ct, const uint8_t *sk);
#endif //NEV_KEM_H
