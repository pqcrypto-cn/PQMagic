/*
 *  SPDX-License-Identifier: MIT
 */

#include "voleith_impl.h"

#include "quicksilver.h"
#include "rsd.h"
#include "universal_hashing.h"
#include "utils.h"
#include "vole.h"
#include "xof.h"

#include <string.h>

// helpers to compute position in signature (sign)

ATTR_PURE static inline unsigned int quicksilver_degree(const sig_paramset_t* params) {
  (void)params;
  return 2;
}

ATTR_PURE static inline unsigned int quicksilver_row_bits(const sig_paramset_t* params) {
  return params->lenwit + quicksilver_degree(params) * params->csp + UNIVERSAL_HASH_B_BITS;
}

ATTR_PURE static inline unsigned int ell_hat_bytes(const sig_paramset_t* params) {
  return (quicksilver_row_bits(params) + 7) / 8;
}

ATTR_PURE static inline unsigned int lenwit_bytes(const sig_paramset_t* params) {
  return (params->lenwit + 7) / 8;
}

ATTR_PURE static inline uint8_t* signature_c(uint8_t* base_ptr, unsigned int index,
                                             const sig_paramset_t* params) {
  return base_ptr + index * ell_hat_bytes(params);
}

ATTR_PURE static inline uint8_t* signature_u_tilde(uint8_t* base_ptr,
                                                   const sig_paramset_t* params) {
  return base_ptr + (params->tau - 1) * ell_hat_bytes(params);
}

ATTR_PURE static inline uint8_t* signature_d(uint8_t* base_ptr, const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes;
}

ATTR_PURE static inline uint8_t* signature_a1_tilde(uint8_t* base_ptr,
                                                    const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes +
         lenwit_bytes(params);
}

ATTR_PURE static inline uint8_t* signature_decom_i(uint8_t* base_ptr,
                                                   const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int atilde_bytes  = (quicksilver_degree(params) - 1) * lambda_bytes;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes +
         lenwit_bytes(params) +
         atilde_bytes;
}

ATTR_PURE static inline uint8_t* signature_chall_3(uint8_t* base_ptr,
                                                   const sig_paramset_t* params) {
  const unsigned int lambda_bytes = params->csp / 8;
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE - lambda_bytes;
}

ATTR_PURE static inline uint8_t* signature_iv(uint8_t* base_ptr, const sig_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE;
}

ATTR_PURE static inline uint8_t* signature_ctr(uint8_t* base_ptr, const sig_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t);
}

// helpers to compute position in signature (verify)

ATTR_PURE static inline const uint8_t* dsignature_c(const uint8_t* base_ptr, unsigned int index,
                                                    const sig_paramset_t* params) {
  return base_ptr + index * ell_hat_bytes(params);
}

ATTR_PURE static inline const uint8_t* dsignature_u_tilde(const uint8_t* base_ptr,
                                                          const sig_paramset_t* params) {
  return base_ptr + (params->tau - 1) * ell_hat_bytes(params);
}

ATTR_PURE static inline const uint8_t* dsignature_d(const uint8_t* base_ptr,
                                                    const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_a1_tilde(const uint8_t* base_ptr,
                                                           const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes +
         lenwit_bytes(params);
}

ATTR_PURE static inline const uint8_t* dsignature_decom_i(const uint8_t* base_ptr,
                                                          const sig_paramset_t* params) {
  const unsigned int lambda_bytes  = params->csp / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int atilde_bytes  = (quicksilver_degree(params) - 1) * lambda_bytes;

  return base_ptr + (params->tau - 1) * ell_hat_bytes(params) + utilde_bytes +
         lenwit_bytes(params) +
         atilde_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_chall_3(const uint8_t* base_ptr,
                                                          const sig_paramset_t* params) {
  const unsigned int lambda_bytes = params->csp / 8;
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE - lambda_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_iv(const uint8_t* base_ptr,
                                                     const sig_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE;
}

ATTR_PURE static inline const uint8_t* dsignature_ctr(const uint8_t* base_ptr,
                                                      const sig_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t);
}

static void hash_prefixed_final(uint8_t* out, size_t outlen, hash_context* ctx) {
  hash_final(ctx);
  hash_squeeze(ctx, out, outlen);
  hash_clear(ctx);
}

static void hash_mu_s(uint8_t* mu, uint8_t* s, const uint8_t* owf_input, size_t owf_input_size,
                      const uint8_t* owf_output, size_t owf_output_size, const uint8_t* msg,
                      size_t msglen, unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;
  const uint8_t domain            = 0;
  uint8_t output[3 * MAX_CSP_BYTES];

  hash_context ctx;
  hash_init(&ctx, lambda);
  hash_update(&ctx, &domain, sizeof(domain));
  hash_update(&ctx, owf_input, owf_input_size);
  hash_update(&ctx, owf_output, owf_output_size);
  hash_update(&ctx, msg, msglen);
  hash_prefixed_final(output, 3 * lambda_bytes, &ctx);

  memcpy(mu, output, 2 * lambda_bytes);
  memcpy(s, output + 2 * lambda_bytes, lambda_bytes);
}

static void hash_r_iv(uint8_t* root_key, uint8_t* iv, const uint8_t* owf_key,
                      const uint8_t* mu, const uint8_t* rho, size_t rho_size, unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;
  const uint8_t domain            = 1;

  hash_context ctx;
  hash_init(&ctx, lambda);
  hash_update(&ctx, &domain, sizeof(domain));
  hash_update(&ctx, owf_key, lambda_bytes);
  hash_update(&ctx, mu, lambda_bytes * 2);
  if (rho && rho_size) {
    hash_update(&ctx, rho, rho_size);
  }
  hash_final(&ctx);
  hash_squeeze(&ctx, root_key, lambda_bytes);
  hash_squeeze(&ctx, iv, IV_SIZE);
  hash_clear(&ctx);
}

static void hash_challenge_1(uint8_t* chall_1, const uint8_t* hcom, const uint8_t* c,
                             const sig_paramset_t* params) {
  const unsigned int lambda_bytes = params->csp / 8;
  const uint8_t domain            = 9;

  hash_context ctx;
  hash_init(&ctx, params->csp);
  hash_update(&ctx, &domain, sizeof(domain));
  hash_update(&ctx, hcom, lambda_bytes * 2);
  hash_update(&ctx, c, ell_hat_bytes(params) * (params->tau - 1));
  hash_prefixed_final(chall_1, 5 * lambda_bytes + 8, &ctx);
}

static void hash_challenge_2_init(hash_context* ctx, const uint8_t* chall_1,
                                  const uint8_t* u_tilde, unsigned int lambda) {
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int u_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;
  const uint8_t domain             = 10;

  hash_init(ctx, lambda);
  hash_update(ctx, &domain, sizeof(domain));
  hash_update(ctx, chall_1, 5 * lambda_bytes + 8);
  hash_update(ctx, u_tilde, u_tilde_bytes);
}

static void hash_challenge_2_update_v_tilde(hash_context* ctx, const uint8_t* v_tilde,
                                            unsigned int lambda) {
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int v_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;

  hash_update(ctx, v_tilde, v_tilde_bytes);
}

static void hash_challenge_2_finalize(uint8_t* chall_2, hash_context* ctx, const uint8_t* d,
                                      const unsigned lambda, unsigned int ell) {
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ell_bytes    = (ell + 7) / 8;

  hash_update(ctx, d, ell_bytes);
  hash_prefixed_final(chall_2, 3 * lambda_bytes + 8, ctx);
}

static void hash_challenge_3_update_prefix(hash_context* ctx, const uint8_t* chall_2,
                                           const uint8_t* a1_tilde, const uint8_t* a0_tilde,
                                           const sig_paramset_t* params) {
  const unsigned int lambda_bytes = params->csp / 8;
  const uint8_t domain            = 11;

  hash_init(ctx, params->csp);
  hash_update(ctx, &domain, sizeof(domain));
  hash_update(ctx, chall_2, 3 * lambda_bytes + 8);
  hash_update(ctx, a1_tilde, lambda_bytes);
  hash_update(ctx, a0_tilde, lambda_bytes);
}

static void hash_challenge_3_final(uint8_t* chall_3, const hash_context* ctx, uint32_t ctr,
                                   unsigned int lambda) {
  hash_context ctx_copy;
  hash_copy(&ctx_copy, ctx);
  hash_update_uint32_le(&ctx_copy, ctr);
  hash_prefixed_final(chall_3, lambda / 8, &ctx_copy);
}

static void hash_challenge_3(uint8_t* chall_3, const uint8_t* chall_2, const uint8_t* a1_tilde,
                             const uint8_t* a0_tilde, const uint8_t* ctr,
                             const sig_paramset_t* params) {
  hash_context ctx;
  hash_challenge_3_update_prefix(&ctx, chall_2, a1_tilde, a0_tilde, params);
  hash_update(&ctx, ctr, sizeof(uint32_t));
  hash_prefixed_final(chall_3, params->csp / 8, &ctx);
}

static bool check_challenge_3(const uint8_t* chall_3, unsigned int start, unsigned int lambda) {
  for (unsigned int bit_i = start; bit_i != lambda; ++bit_i) {
    if (ptr_get_bit(chall_3, bit_i)) {
      return false;
    }
  }
  return true;
}

static void free_pointer_array(uint8_t*** ptr) {
  free((*ptr)[0]);
  free(*ptr);
  *ptr = NULL;
}

// VOLEitH.Sign()
void voleith_sign(uint8_t* sig, const uint8_t* msg, size_t msg_len, const uint8_t* owf_key,
                  const uint8_t* owf_input, const uint8_t* owf_output, const uint8_t* witness,
                  const uint8_t* rho, size_t rholen, const sig_paramset_t* params) {
  const unsigned int ell            = params->lenwit;  const unsigned int ell_bytes      = (ell + 7) / 8;
  const unsigned int lambda         = params->csp;
  const unsigned int ell_hat        = quicksilver_row_bits(params);
  const unsigned int ell_hat_nbytes = ell_hat_bytes(params);
  const unsigned int w_grind        = params->POWLevel;

  // ::3
  uint8_t mu[MAX_CSP_BYTES * 2];
  uint8_t bavc_s[MAX_CSP_BYTES];
  hash_mu_s(mu, bavc_s, owf_input, params->owf_input_size, owf_output, params->owf_output_size, msg,
            msg_len, lambda);

  // ::4-5
  uint8_t rootkey[MAX_CSP_BYTES], iv[IV_SIZE];
  hash_r_iv(rootkey, signature_iv(sig, params), owf_key, mu, rho, rholen, lambda);
  memcpy(iv, signature_iv(sig, params), IV_SIZE);

  // ::6-7
  bavc_t bavc;
  uint8_t* u = malloc(ell_hat_nbytes);
  assert(u);
  // v has \hat \ell rows, \lambda columns, storing in column-major order
  uint8_t** V = malloc(lambda * sizeof(uint8_t*));
  assert(V);
  V[0] = calloc(lambda, ell_hat_nbytes);
  assert(V[0]);
  for (unsigned int i = 1; i < lambda; ++i) {
    V[i] = V[0] + i * ell_hat_nbytes;
  }
  vole_commit(rootkey, iv, mu, bavc_s, ell_hat, params, &bavc, signature_c(sig, 0, params), u,
              V);

  // ::8
  uint8_t chall_1[(5 * MAX_CSP_BYTES) + 8];
  hash_challenge_1(chall_1, bavc.h, signature_c(sig, 0, params), params);

  // ::9-10
  vole_hash_with_degree(signature_u_tilde(sig, params), chall_1, u, ell, lambda,
                         quicksilver_degree(params));

  // ::11-12
  // To save memory consumption, the chall_2 is computed in an
  // Init-Update-Finalize style as V_tilde is only fed into to the hash and not
  // used elsewhere.
  hash_context chall_2_ctx;
  hash_challenge_2_init(&chall_2_ctx, chall_1, signature_u_tilde(sig, params), lambda);
  {
    uint8_t V_tilde[MAX_CSP_BYTES + UNIVERSAL_HASH_B];
    for (unsigned int i = 0; i != lambda; ++i) {
      // Step 11
      vole_hash_with_degree(V_tilde, chall_1, V[i], ell, lambda,
                                quicksilver_degree(params));
      // Step 14
      hash_challenge_2_update_v_tilde(&chall_2_ctx, V_tilde, lambda);
    }
  }

  // ::13 witness provided by caller
  // ::14
  xor_u8_array(witness, u, signature_d(sig, params), ell_bytes);

  // :15
  uint8_t chall_2[3 * MAX_CSP_BYTES + 8];
  hash_challenge_2_finalize(chall_2, &chall_2_ctx, signature_d(sig, params), lambda, ell);

  // ::16-20
  uint8_t a0_tilde[MAX_CSP_BYTES];
  rsd_prover(a0_tilde, signature_a1_tilde(sig, params), witness, u + ell_bytes, V,
                        owf_input, owf_output, chall_2, params);

  free_pointer_array(&V);
  free(u);
  u = NULL;

  // ::21-22
  hash_context chall_3_ctx;
  hash_challenge_3_update_prefix(&chall_3_ctx, chall_2, signature_a1_tilde(sig, params), a0_tilde,
                                 params);

  uint32_t ctr = 0;
  for (; true; ++ctr) {
    uint8_t* chall_3 = signature_chall_3(sig, params);
    hash_challenge_3_final(chall_3, &chall_3_ctx, ctr, lambda);
    // ::23
    if (!check_challenge_3(chall_3, lambda - w_grind, lambda)) {
      continue;
    }

    // ::26
    uint16_t decoded_chall_3[MAX_TAU];
    if (!decode_all_chall_3(decoded_chall_3, chall_3, params)) {
      continue;
    }

    // :27
    if (bavc_open(signature_decom_i(sig, params), &bavc, decoded_chall_3, params)) {
      break;
    }
  }
  hash_clear(&chall_3_ctx);
  bavc_clear(&bavc);

  // copy counter to signature
  ctr = htole32(ctr);
  memcpy(signature_ctr(sig, params), &ctr, sizeof(ctr));
}

int voleith_verify(const uint8_t* msg, size_t msglen, const uint8_t* sig, const uint8_t* owf_input,
                   const uint8_t* owf_output, const sig_paramset_t* params) {
  const unsigned int ell            = params->lenwit;  const unsigned int lambda         = params->csp;
  const unsigned int lambda_bytes   = lambda / 8;
  const unsigned int ell_hat        = quicksilver_row_bits(params);
  const unsigned int ell_hat_nbytes = ell_hat_bytes(params);
  const unsigned int utilde_bytes   = lambda_bytes + UNIVERSAL_HASH_B;

  // ::4-5
  if (!check_challenge_3(dsignature_chall_3(sig, params), lambda - params->POWLevel, lambda)) {
    return -1;
  }

  // ::2
  uint8_t mu[MAX_CSP_BYTES * 2];
  uint8_t bavc_s[MAX_CSP_BYTES];
  hash_mu_s(mu, bavc_s, owf_input, params->owf_input_size, owf_output, params->owf_output_size, msg,
            msglen, lambda);

  // ::3
  const uint8_t* iv = dsignature_iv(sig, params);

  // Step: 6-7
  // q is a \hat \ell \times \lambda matrix
  uint8_t** q = malloc(lambda * sizeof(uint8_t*));
  assert(q);
  q[0] = calloc(lambda, ell_hat_nbytes);
  assert(q[0]);
  for (unsigned int i = 1; i < lambda; ++i) {
    q[i] = q[0] + i * ell_hat_nbytes;
  }
  uint8_t hcom[MAX_CSP_BYTES * 2];

  if (!vole_reconstruct(hcom, q, iv, dsignature_chall_3(sig, params),
                        dsignature_decom_i(sig, params), dsignature_c(sig, 0, params), mu, bavc_s,
                        ell_hat, params)) {
    free_pointer_array(&q);
    return -1;
  }

  // ::10
  uint8_t chall_1[5 * MAX_CSP_BYTES + 8];
  hash_challenge_1(chall_1, hcom, dsignature_c(sig, 0, params), params);

  // Step 12, 14 and 15
  hash_context chall_2_ctx;
  hash_challenge_2_init(&chall_2_ctx, chall_1, dsignature_u_tilde(sig, params), lambda);
  {
    const uint8_t* chall_3 = dsignature_chall_3(sig, params);
    uint8_t Q_tilde[MAX_CSP_BYTES + UNIVERSAL_HASH_B];
    for (unsigned int i = 0; i != lambda; ++i) {
      // Step 12
      vole_hash_with_degree(Q_tilde, chall_1, q[i], ell, lambda,
                                quicksilver_degree(params));
      // Step 14
      if (ptr_get_bit(chall_3, i)) {
        xor_u8_array(Q_tilde, dsignature_u_tilde(sig, params), Q_tilde, utilde_bytes);
      }

      // Step 15
      hash_challenge_2_update_v_tilde(&chall_2_ctx, Q_tilde, lambda);
    }
  }

  // Step 15
  uint8_t chall_2[3 * MAX_CSP_BYTES + 8];
  hash_challenge_2_finalize(chall_2, &chall_2_ctx, dsignature_d(sig, params), lambda, ell);

  // Step 18
  const uint8_t* d = dsignature_d(sig, params);
  uint8_t a0_tilde[MAX_CSP_BYTES];
  rsd_verifier(a0_tilde, d, q, owf_input, owf_output, chall_2,
                          dsignature_chall_3(sig, params), dsignature_a1_tilde(sig, params),
                          params);
  free_pointer_array(&q);

  // Step: 20
  uint8_t chall_3[MAX_CSP_BYTES];
  hash_challenge_3(chall_3, chall_2, dsignature_a1_tilde(sig, params), a0_tilde,
                   dsignature_ctr(sig, params), params);

  // Step 21
  if (memcmp(chall_3, dsignature_chall_3(sig, params), lambda_bytes) != 0) {
    return -1;
  }
  return 0;
}
