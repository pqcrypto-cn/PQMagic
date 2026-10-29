#ifndef OWCPA_H
#define OWCPA_H

#include <stdint.h>


void owcpa_keypair(uint8_t *pk, 
                   uint8_t *sk);

void owcpa_enc(uint8_t *c,
               const uint8_t *m,
               const uint8_t *pk,
               const uint8_t *coins);

void owcpa_dec(uint8_t *m,
               const uint8_t *c,
               const uint8_t *sk);

#endif
