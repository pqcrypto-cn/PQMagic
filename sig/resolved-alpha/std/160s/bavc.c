/*
 *  SPDX-License-Identifier: MIT
 */

#include "bavc.h"
#include "endian_compat.h"
#include "instances.h"
#include "prg.h"
#include "tccr.h"
#include "xof.h"

#include <assert.h>
#include <string.h>

#define NODE(nodes, node, lambda_bytes) (&nodes[(node) * (lambda_bytes)])

static const uint8_t BAVC_HASH_DOMAIN = 2;

static void bavc_hash_init(hash_context* ctx, const uint8_t* mu, const uint8_t* tccr_s,
                           unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  hash_init(ctx, lambda);
  hash_update(ctx, &BAVC_HASH_DOMAIN, sizeof(BAVC_HASH_DOMAIN));
  hash_update(ctx, mu, 2 * lambda_bytes);
  hash_update(ctx, tccr_s, lambda_bytes);
}

static void bavc_hash_update_alpha(hash_context* ctx, hash_context* alpha_ctx,
                                   unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;
  uint8_t alpha_com[2 * MAX_CSP_BYTES];

  hash_final(alpha_ctx);
  hash_squeeze(alpha_ctx, alpha_com, 2 * lambda_bytes);
  hash_clear(alpha_ctx);
  hash_update(ctx, alpha_com, 2 * lambda_bytes);
}

static void bavc_hash_finalize(uint8_t* com, hash_context* ctx, const uint8_t* iv,
                               unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  hash_update(ctx, iv, IV_SIZE);
  hash_final(ctx);
  hash_squeeze(ctx, com, 2 * lambda_bytes);
  hash_clear(ctx);
}

static void expand_tccr_node(uint8_t* nodes, unsigned int id, const uint8_t* iv,
                             const uint8_t* tccr_s, const sig_paramset_t* params) {
  const unsigned int lambda_bytes = params->csp / 8;
  uint8_t* parent                 = NODE(nodes, id - 1, lambda_bytes);
  uint8_t* left                   = NODE(nodes, 2 * id - 1, lambda_bytes);
  uint8_t* right                  = NODE(nodes, 2 * id, lambda_bytes);

  if (id < params->L / 2) {
    tccr_hash(parent, tccr_s, iv, left, params->csp);
    xor_u8_array(left, parent, right, lambda_bytes);
    return;
  }

  tccr_hash_x0_x1(parent, tccr_s, iv, left, right, params->csp);
}

static void expand_tccr_tree(uint8_t* nodes, const uint8_t* iv, const uint8_t* tccr_s,
                             const sig_paramset_t* params) {
  for (unsigned int id = 1; id < params->L; ++id) {
    expand_tccr_node(nodes, id, iv, tccr_s, params);
  }
}

static uint8_t* generate_seeds(const uint8_t* root_seed, const uint8_t* iv, const uint8_t* tccr_s,
                               const sig_paramset_t* params) {
  unsigned int lambda_bytes = params->csp / 8;
  uint8_t* nodes            = calloc(2 * params->L - 1, lambda_bytes);
  assert(nodes);

  memcpy(NODE(nodes, 0, lambda_bytes), root_seed, lambda_bytes);
  expand_tccr_tree(nodes, iv, tccr_s, params);

  return nodes;
}

static void leaf_commit_2lambda(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv,
                                unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  memcpy(sd, key, lambda_bytes);
  prg_2_lambda(key, iv, 0, com, lambda);
}

#if defined(SIG_TESTS)
void leaf_commit(uint8_t* sd, uint8_t* com, const uint8_t* key, const uint8_t* iv, uint32_t tweak,
                 const sig_paramset_t* params) {
  (void)tweak;
  leaf_commit_2lambda(sd, com, key, iv, params->csp);
}
#endif

// BAVC.PosInTree
ATTR_PURE static inline unsigned int pos_in_tree(unsigned int i, unsigned int j,
                                                 const sig_paramset_t* params) {
  const unsigned int tmp = 1 << (params->k - 1);
  if (j < tmp) {
    return params->L - 1 + params->tau * j + i;
  }
  // mod 2^(k-1) is the same as & 2^(k-1)-1
  const unsigned int mask = tmp - 1;
  return params->L - 1 + params->tau * tmp + params->tau1 * (j & mask) + i;
}

void bavc_commit(bavc_t* bavc, const uint8_t* root_key, const uint8_t* iv, const uint8_t* mu,
                 const uint8_t* tccr_s, const sig_paramset_t* params) {
  const unsigned int lambda       = params->csp;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  hash_context com_ctx;
  bavc_hash_init(&com_ctx, mu, tccr_s, lambda);

  // Generating the tree
  uint8_t* nodes = generate_seeds(root_key, iv, tccr_s, params);

  // Initialzing stuff
  bavc->h   = malloc(lambda_bytes * 2);
  bavc->com = malloc(L * com_size);
  bavc->sd  = malloc(L * lambda_bytes);
  assert(bavc->h && bavc->com && bavc->sd);

  // Step: 1..3
  bavc->k = NODE(nodes, 0, lambda_bytes);

  assert(bavc->h);
  assert(bavc->com);
  assert(bavc->sd);
  assert(bavc->k);

  // Step: 4..5
  // compute commitments for remaining instances
  for (unsigned int i = 0, offset = 0; i < params->tau; ++i) {
    hash_context alpha_ctx;
    hash_init(&alpha_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, params->tau1, params->k);
    for (unsigned int j = 0; j < N_i; ++j, ++offset) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      leaf_commit_2lambda(bavc->sd + offset * lambda_bytes, bavc->com + offset * com_size,
                          NODE(nodes, alpha, lambda_bytes), iv, lambda);
      hash_update(&alpha_ctx, bavc->com + offset * com_size, com_size);
    }
    bavc_hash_update_alpha(&com_ctx, &alpha_ctx, lambda);
  }

  bavc_hash_finalize(bavc->h, &com_ctx, iv, lambda);
}

bool bavc_open(uint8_t* decom_i, const bavc_t* vc, const uint16_t* i_delta,
               const sig_paramset_t* params) {
  const unsigned int lambda       = params->csp;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = 2 * lambda_bytes;

  uint8_t* decom_i_end = decom_i + com_size * tau + params->T_open * lambda_bytes;

  // Step 5
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  assert(s);
  // Step 6
  unsigned int nh = 0;

  // Step 7..15
  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
    ++nh;

    while (alpha > 0 && ptr_get_bit(s, (alpha - 1) / 2) == 0) {
      alpha = (alpha - 1) / 2;
      ptr_set_bit(s, alpha, 1);
      ++nh;
    }
  }

  // Step 16..17
  if (nh - 2 * tau + 1 > params->T_open) {
    free(s);
    return false;
  }

  // Step 3
  const uint8_t* com = vc->com;
  for (unsigned int i = 0; i < tau; ++i) {
    memcpy(decom_i, com + i_delta[i] * com_size, com_size);
    decom_i += com_size;
    com += bavc_max_node_index(i, tau_1, k) * com_size;
  }

  // Step 19..25
  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      memcpy(decom_i, NODE(vc->k, alpha, lambda_bytes), lambda_bytes);
      decom_i += lambda_bytes;
    }
  }

  memset(decom_i, 0, decom_i_end - decom_i);

  free(s);
  return true;
}

static bool reconstruct_keys(uint8_t* s, uint8_t* keys, const uint8_t* decom_i,
                             const uint16_t* i_delta, const uint8_t* iv, const uint8_t* tccr_s,
                             const sig_paramset_t* params) {
  const unsigned int lambda       = params->csp;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int tau          = params->tau;

  const uint8_t* nodes = decom_i + 2 * tau * lambda_bytes;
  const uint8_t* end   = nodes + params->T_open * lambda_bytes;

  // Step 7..10
  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = pos_in_tree(i, i_delta[i], params);
    ptr_set_bit(s, alpha, 1);
  }

  // Step 12.12
  for (int i = L - 2; i >= 0; --i) {
    ptr_set_bit(s, i, ptr_get_bit(s, 2 * i + 1) | ptr_get_bit(s, 2 * i + 2));
    if ((ptr_get_bit(s, 2 * i + 1) ^ ptr_get_bit(s, 2 * i + 2)) == 1) {
      if (nodes == end) {
        return false;
      }

      const unsigned int alpha = 2 * i + 1 + ptr_get_bit(s, 2 * i + 1);
      memcpy(keys + alpha * lambda_bytes, nodes, lambda_bytes);
      nodes += lambda_bytes;
    }
  }

  for (; nodes != end; ++nodes) {
    if (*nodes) {
      return false;
    }
  }

  for (unsigned int i = 0; i != L - 1; ++i) {
    if (!ptr_get_bit(s, i)) {
      expand_tccr_node(keys, i + 1, iv, tccr_s, params);
    }
  }

  return true;
}

bool bavc_reconstruct(bavc_rec_t* bavc_rec, const uint8_t* decom_i, const uint16_t* i_delta,
                      const uint8_t* iv, const uint8_t* mu, const uint8_t* tccr_s,
                      const sig_paramset_t* params) {
  // Initializing
  const unsigned int lambda       = params->csp;
  const unsigned int L            = params->L;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int k            = params->k;
  const unsigned int tau          = params->tau;
  const unsigned int tau_1        = params->tau1;
  const unsigned int com_size     = lambda_bytes * 2; // size of com_ij

  // Step 6
  uint8_t* s = calloc((2 * L - 1 + 7) / 8, 1);
  assert(s);
  uint8_t* keys = calloc(2 * params->L - 1, lambda_bytes);
  assert(keys);

  // Step 7..10
  if (!reconstruct_keys(s, keys, decom_i, i_delta, iv, tccr_s, params)) {
    free(keys);
    free(s);
    return false;
  }

  hash_context com_ctx;
  bavc_hash_init(&com_ctx, mu, tccr_s, lambda);

  for (unsigned int i = 0, offset = 0; i != tau; ++i) {
    hash_context alpha_ctx;
    hash_init(&alpha_ctx, lambda);

    const unsigned int N_i = bavc_max_node_index(i, tau_1, k);
    for (unsigned int j = 0; j != N_i; ++j) {
      const unsigned int alpha = pos_in_tree(i, j, params);
      if (ptr_get_bit(s, alpha)) {
        hash_update(&alpha_ctx, decom_i + i * com_size, com_size);
      } else {
        uint8_t com[2 * MAX_CSP_BYTES];
        leaf_commit_2lambda(bavc_rec->s + offset * lambda_bytes, com, keys + alpha * lambda_bytes,
                            iv, lambda);
        ++offset;
        hash_update(&alpha_ctx, com, com_size);
      }
    }
    bavc_hash_update_alpha(&com_ctx, &alpha_ctx, lambda);
  }

  bavc_hash_finalize(bavc_rec->h, &com_ctx, iv, lambda);

  free(keys);
  free(s);
  return true;
}

void bavc_clear(bavc_t* com) {
  free(com->sd);
  free(com->com);
  free(com->h);
  free(com->k);
}
