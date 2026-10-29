/*
 *  SPDX-License-Identifier: MIT
 */

#include "SIG_AlgorithmInstance.h"
#include "drng.h"
#include "parameters.h"
#include "rsd.h"
#include "voleith_impl.h"
#include "instances.h"
#include "endian_compat.h"

#include <string.h>

extern DRNG_ctx drng_algorithm;

#ifdef PQMAGIC_USE_SYSTEM_RANDOM
#include "utils/randombytes.h"
#undef get_random_number
#define get_random_number(ctx, output, output_bits) \
  (randombytes((output), ((output_bits) + 7) / 8), 0)
#endif

#if 288 != (48 + 240)
#error "invalid public key size"
#endif

#if 96 != (48 + 384 / 8)
#error "invalid secret key size"
#endif

unsigned long long sig_get_pk_len_bytes(void) {
  return 288;
}

unsigned long long sig_get_sk_len_bytes(void) {
  return 96;
}

unsigned long long sig_get_sn_len_bytes(void) {
  return 31575;
}

int sig_keygen(
    unsigned char *pk, unsigned long long *pk_len_bytes,
    unsigned char *sk, unsigned long long *sk_len_bytes)
{
  if (!pk || !pk_len_bytes || !sk || !sk_len_bytes) {
    return -1;
  }

  const unsigned int csp          = 384;
  const unsigned int input_size   = 48;

  // memory layout of the secret key: public seed || secret seed
  unsigned char *seed_sk = sk + input_size;

  get_random_number(&drng_algorithm, seed_sk, csp);
  get_random_number(&drng_algorithm, sk, input_size * 8);

  const sig_paramset_t* params = sig_get_paramset(RESOLVED_ALPHA_384S);

  // memory layout of the public key: public seed || syndrome
  memcpy(pk, sk, input_size);
  rsd_owf(seed_sk, sk, pk + input_size, params);

  *pk_len_bytes = 288;
  *sk_len_bytes = 96;

  return 0;
}

int sig_sign(
    unsigned char *sk, unsigned long long sk_len_bytes,
    unsigned char *m, unsigned long long m_len_bytes,
    unsigned char *sn, unsigned long long *sn_len_bytes)
{
  if (!sk || !sn || !sn_len_bytes || (!m && m_len_bytes)) {
    return -1;
  }

  if (sk_len_bytes != 96) {
    return -1;
  }

  const unsigned int input_size = 48;

  unsigned char rho[384 / 8];
  get_random_number(&drng_algorithm, rho, 384);

  // Unpack secret key: public seed || secret seed
  const unsigned char *owf_input = sk;
  const unsigned char *owf_key   = sk + input_size;

  // Compute OWF output and witness
  unsigned char owf_output[240];
  const sig_paramset_t* params = sig_get_paramset(RESOLVED_ALPHA_384S);
  rsd_owf(owf_key, owf_input, owf_output, params);

  unsigned char witness[(2112 + 7) / 8];
  rsd_extend_witness(witness, owf_key, owf_input, params);

  *sn_len_bytes = 31575;
  voleith_sign(sn, m, m_len_bytes, owf_key, owf_input, owf_output, witness,
               rho, sizeof(rho), params);

  memset(witness, 0, sizeof(witness));
  memset(owf_output, 0, sizeof(owf_output));

  return 0;
}

int sig_verify(
    unsigned char *pk, unsigned long long pk_len_bytes,
    unsigned char *sn, unsigned long long sn_len_bytes,
    unsigned char *m, unsigned long long m_len_bytes)
{
  if (!pk || !sn || (!m && m_len_bytes)) {
    return -1;
  }

  if (pk_len_bytes != 288) {
    return -1;
  }

  if (sn_len_bytes != 31575) {
    return -1;
  }

  const sig_paramset_t* params = sig_get_paramset(RESOLVED_ALPHA_384S);
  return voleith_verify(m, m_len_bytes, sn, pk, pk + 48, params);
}
