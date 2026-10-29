#ifndef NEV_AKE_REF_AKE_H
#define NEV_AKE_REF_AKE_H
#include <stdint.h>

#include "params.h"

#define AKE_DOMAIN_G 0x01
#define AKE_DOMAIN_H 0x02
#define AKE_DOMAIN_HI 0x03
#define AKE_DOMAIN_HR 0x04

int ake_party_keygen(uint8_t *pk, uint8_t *sk);
void ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void ake_init(uint8_t * M, uint8_t *st, const uint8_t *ski, const uint8_t *pkj);
void ake_der_response(uint8_t *M_prime, uint8_t *K_prime, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *M);
void ake_der_init(uint8_t *K, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *st, const uint8_t *M_prime);

void ake_hash_g(uint8_t *rho, const uint8_t *m);
void ake_hash_h(uint8_t *key, const uint8_t *mi, const uint8_t *mj, const uint8_t *kt, const uint8_t *idi, const uint8_t *idj, const uint8_t *M, const uint8_t *M_prime);
void ake_hash_hi(uint8_t *key, const uint8_t *si, const uint8_t *ci, const uint8_t *mj, const uint8_t *kt, const uint8_t *idi, const uint8_t *idj, const uint8_t *M, const uint8_t *M_prime);
void ake_hash_hr(uint8_t *key, const uint8_t *sj, const uint8_t *mi, const uint8_t *cj, const uint8_t *kt, const uint8_t *idi, const uint8_t *idj, const uint8_t *M, const uint8_t *M_prime);

#endif //NEV_AKE_REF_AKE_H
