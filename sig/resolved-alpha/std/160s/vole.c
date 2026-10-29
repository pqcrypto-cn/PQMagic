/*
 *  SPDX-License-Identifier: MIT
 */

#include "vole.h"
#include "prg.h"
#include "utils.h"
#include "random_oracle.h"

#include <stdbool.h>
#include <string.h>

#if !defined(SIG_TESTS)
static
#endif
    unsigned int
    convert_to_vole(const uint8_t* iv, const uint8_t* sd, bool sd0_bot, unsigned int i,
                    unsigned int outlen, uint8_t* u, uint8_t* v, const sig_paramset_t* params) {
  const unsigned int lambda        = params->csp;
  const unsigned int tau_1         = params->tau1;
  const unsigned int k             = params->k;
  const unsigned int num_instances = bavc_max_node_index(i, tau_1, k);
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int depth         = bavc_max_node_depth(i, tau_1, k);

  // (depth + 1) x num_instances array of outlen; but we only need two rows at a time
  uint8_t* r = calloc(2 * num_instances, outlen);

#define R(row, column) (r + (((row) % 2) * num_instances + (column)) * outlen)
#define V(idx) (v + (idx) * outlen)

  const uint8_t tweak = (uint8_t)((2 * lambda + 127) / 128);

  // Step: 2
  if (!sd0_bot) {
    prg(sd, iv, tweak, R(0, 0), lambda, outlen);
  }

  // Step: 3..4
  for (unsigned int j = 1; j < num_instances; ++j) {
    prg(sd + lambda_bytes * j, iv, tweak, R(0, j), lambda, outlen);
  }

  // Step: 5..9
  memset(v, 0, depth * outlen);
  for (unsigned int j = 0; j < depth; j++) {
    unsigned int depthloop = num_instances >> (j + 1);
    for (unsigned int idx = 0; idx < depthloop; idx++) {
      xor_u8_array(V(j), R(j, 2 * idx + 1), V(j), outlen);
      xor_u8_array(R(j, 2 * idx), R(j, 2 * idx + 1), R(j + 1, idx), outlen);
    }
  }
  // Step: 10
  if (!sd0_bot && u != NULL) {
    memcpy(u, R(depth, 0), outlen);
  }
  free(r);
  return depth;
}

void vole_commit(const uint8_t* rootKey, const uint8_t* iv, const uint8_t* mu,
                 const uint8_t* tccr_s,
                 unsigned int ellhat,
                 const sig_paramset_t* params, bavc_t* bavc, uint8_t* c, uint8_t* u,
                 uint8_t** v) {
  const unsigned int lambda       = params->csp;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int k            = params->k;

  bavc_commit(bavc, rootKey, iv, mu, tccr_s, params);

  uint8_t* ui = malloc(tau * ellhat_bytes);
  assert(ui);

  unsigned int v_idx = 0;
  uint8_t* sd_i      = bavc->sd;
  for (unsigned int i = 0; i < tau; ++i) {
    // Step 6
    v_idx +=
        convert_to_vole(iv, sd_i, false, i, ellhat_bytes, ui + i * ellhat_bytes, v[v_idx], params);
    sd_i += lambda_bytes * bavc_max_node_index(i, tau_1, k);
  }

  // ensure 0-padding up to lambda
  for (; v_idx != lambda; ++v_idx) {
    memset(v[v_idx], 0, ellhat_bytes);
  }

  // Step 9
  memcpy(u, ui, ellhat_bytes);
  for (unsigned int i = 1; i < tau; i++) {
    // Step 11
    xor_u8_array(u, ui + i * ellhat_bytes, c + (i - 1) * ellhat_bytes, ellhat_bytes);
  }
  free(ui);
}

bool vole_reconstruct(uint8_t* com, uint8_t** q, const uint8_t* iv, const uint8_t* chall_3,
                      const uint8_t* decom_i, const uint8_t* c, const uint8_t* mu,
                      const uint8_t* tccr_s, unsigned int ellhat, const sig_paramset_t* params) {
  const unsigned int lambda       = params->csp;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ellhat_bytes = (ellhat + 7) / 8;
  const unsigned int tau          = params->tau;
  const unsigned int tau1         = params->tau1;
  const unsigned int L            = params->L;
  const unsigned int k            = params->k;

  uint16_t i_delta[MAX_TAU];
  if (!decode_all_chall_3(i_delta, chall_3, params)) {
    return false;
  }

  bavc_rec_t bavc_rec;
  bavc_rec.h = com;
  bavc_rec.s = malloc((L - tau) * lambda_bytes);
  assert(bavc_rec.s);

  if (!bavc_reconstruct(&bavc_rec, decom_i, i_delta, iv, mu, tccr_s, params)) {
    free(bavc_rec.s);
    return false;
  }

  uint8_t* sd   = malloc((1 << k) * lambda_bytes);
  uint8_t* qtmp = malloc(MAX_DEPTH * ellhat_bytes);
  assert(sd);
  assert(qtmp);

  // Step: 1
  unsigned int q_idx = 0;
  uint8_t* sd_i      = bavc_rec.s;
  for (unsigned int i = 0; i < tau; i++) {
    // Step: 2
    const unsigned int Ni = bavc_max_node_index(i, tau1, k);

    // Step: 6
    for (unsigned int j = 0; j < Ni; j++) {
      if (j < i_delta[i]) {
        memcpy(sd + (j ^ i_delta[i]) * lambda_bytes, sd_i + lambda_bytes * j, lambda_bytes);
      } else if (j > i_delta[i]) {
        memcpy(sd + (j ^ i_delta[i]) * lambda_bytes, sd_i + lambda_bytes * (j - 1), lambda_bytes);
      }
    }

    // Step: 7..8
    const unsigned int ki = convert_to_vole(iv, sd, true, i, ellhat_bytes, NULL, qtmp, params);

    // Step 11
    if (i == 0) {
      // Step 8
      memcpy(q[q_idx], qtmp, ellhat_bytes * ki);
      q_idx += ki;
    } else {
      // Step 14
      for (unsigned int d = 0; d < ki; ++d, ++q_idx) {
        masked_xor_u8_array(qtmp + d * ellhat_bytes, c + (i - 1) * ellhat_bytes, q[q_idx],
                            (i_delta[i] >> d) & 1, ellhat_bytes);
      }
    }
    sd_i += lambda_bytes * (Ni - 1);
  }

  // ensure 0-padding up to lambda
  for (; q_idx != lambda; ++q_idx) {
    memset(q[q_idx], 0, ellhat_bytes);
  }

  free(qtmp);
  free(sd);
  free(bavc_rec.s);
  return true;
}
