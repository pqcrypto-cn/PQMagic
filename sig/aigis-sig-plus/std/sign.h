#ifndef SIGN_H
#define SIGN_H

#include "params.h"
#include "poly.h"
#include "polyvec.h"

int sig_keygen(unsigned char *pk, unsigned char *sk);

int sig_sign(unsigned char *sk, 
                   unsigned char *m, unsigned long long mlen, 
                   unsigned char *sm, unsigned long long *smlen);                     

int sig_verf(unsigned char *pk,
                   unsigned char *sm, unsigned long long smlen,
                   unsigned char *m, unsigned long long mlen);

#endif
