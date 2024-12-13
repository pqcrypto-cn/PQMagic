#ifndef PACKING_H
#define PACKING_H

#include "params.h"
#include "polyvec.h"

#define pack_pk AIGIS_SIG_NAMESPACE(pack_pk)
void pack_pk(unsigned char pk[PK_SIZE_PACKED],
             const unsigned char rho[SEEDBYTES], const polyveck *t1);
#define pack_sk AIGIS_SIG_NAMESPACE(pack_sk)
void pack_sk(unsigned char sk[SK_SIZE_PACKED],
             const unsigned char buf[2*SEEDBYTES + CRHBYTES],
             const polyvecl *s1,
             const polyveck *s2,
             const polyveck *t0);
#define pack_sig AIGIS_SIG_NAMESPACE(pack_sig)
void pack_sig(unsigned char sm[SIG_SIZE_PACKED],
              const polyvecl *z, const polyveck *h, const poly *c);

#define unpack_pk AIGIS_SIG_NAMESPACE(unpack_pk)
void unpack_pk(unsigned char rho[SEEDBYTES], polyveck *t1,
               const unsigned char pk[PK_SIZE_PACKED]);
#define unpack_sk AIGIS_SIG_NAMESPACE(unpack_sk)
void unpack_sk(unsigned char buf[2*SEEDBYTES + CRHBYTES],
               polyvecl *s1,
               polyveck *s2,
               polyveck *t0,
               const unsigned char sk[SK_SIZE_PACKED]);
#define unpack_sig AIGIS_SIG_NAMESPACE(unpack_sig)
int unpack_sig(polyvecl *z, polyveck *h, poly *c,
                const unsigned char sm[SIG_SIZE_PACKED]);

#endif
