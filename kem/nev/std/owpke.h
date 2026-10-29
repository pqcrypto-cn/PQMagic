#ifndef OWCPA_H
#define OWCPA_H

void ow_pke_keypair(uint8_t *pk, 
                   uint8_t *sk);

void ow_pke_enc_interal(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk,
               const uint8_t *rho);

void ow_pke_enc(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk);

void ow_pke_dec(uint8_t *m,
               const uint8_t *c,
               const uint8_t *sk);

#endif
