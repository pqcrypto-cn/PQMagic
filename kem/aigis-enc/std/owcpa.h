#ifndef OWCPA_H
#define OWCPA_H

#include "params.h"

#define owcpa_keypair AIGIS_ENC_NAMESPACE(owcpa_keypair)
void owcpa_keypair(
    unsigned char *pk, 
    unsigned char *sk,
    const unsigned char *coins);

#define owcpa_enc AIGIS_ENC_NAMESPACE(owcpa_enc)
void owcpa_enc(unsigned char *c,
               const unsigned char *m,
               const unsigned char *pk,
               const unsigned char *coins);

#define owcpa_dec AIGIS_ENC_NAMESPACE(owcpa_dec)
void owcpa_dec(unsigned char *m,
               const unsigned char *c,
               const unsigned char *sk);

#endif
