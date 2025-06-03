#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "fors.h"
#include "utils.h"
#include "utilsx1.h"
#include "hash.h"
#include "thash.h"
#include "address.h"

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
                        uint32_t fors_leaf_addr[8])
{
    prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
                            const spx_ctx *ctx,
                            uint32_t fors_leaf_addr[8])
{
    thash(leaf, sk, 1, ctx, fors_leaf_addr);
}

struct fors_gen_leaf_info {
    uint32_t leaf_addrx[8];
};

static void fors_gen_leafx1(unsigned char *leaf,
                            const spx_ctx *ctx,
                            uint32_t addr_idx, void *info)
{
    struct fors_gen_leaf_info *fors_info = info;
    uint32_t *fors_leaf_addr = fors_info->leaf_addrx;

    /* Only set the parts that the caller doesn't set */
    set_tree_index(fors_leaf_addr, addr_idx);
    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSPRF);
    fors_gen_sk(leaf, ctx, fors_leaf_addr);

    set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE);
    fors_sk_to_leaf(leaf, leaf,
                    ctx, fors_leaf_addr);
}


/**
 * @brief Convert a byte string into a base 2^b representation
 * See FIPS 205 Algorithm 4
 *
 * @param out The array of returned base 2^b integers that represents the first
 *            |outlen|*|b| bits of |in|
 * @param in An input byte stream with a size >= |outlen * b / 8|
 *
 * 
 * @const SPX_FORS_HEIGHT: b, The bit size to divide |in| into
 *          This is one of 6, 8, 9, 12 or 14 for FORS.
 * @const SPX_FORS_TREES: out_len, The size of |out|
 */
static void message_to_indices(uint32_t *out, const uint8_t *in)
{
    size_t consumed = 0;
    uint32_t bits = 0;
    uint32_t total = 0;
    const uint32_t mask = (1 << SPX_FORS_HEIGHT) - 1;

    for (consumed = 0; consumed < SPX_FORS_TREES; consumed++) {
        while (bits < SPX_FORS_HEIGHT) {
            total <<= 8;
            total += *in++;
            bits += 8;
        }
        bits -= SPX_FORS_HEIGHT;
        *out++ = (total >> bits) & mask;
    }
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_sign(unsigned char *sig, unsigned char *pk,
               const unsigned char *m,
               const spx_ctx *ctx,
               const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    struct fors_gen_leaf_info fors_info = {0};
    uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_leaf_addr, fors_addr);

    copy_keypair_addr(fors_pk_addr, fors_addr);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSPRF);

        /* Include the secret key part that produces the selected leaf node. */
        fors_gen_sk(sig, ctx, fors_tree_addr);
        set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
        sig += SPX_N;

        /* Compute the authentication path for this leaf node. */
        treehashx1(roots + i*SPX_N, sig, ctx,
                 indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leafx1,
                 fors_tree_addr, &fors_info);

        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
 */
void fors_pk_from_sig(unsigned char *pk,
                      const unsigned char *sig, const unsigned char *m,
                      const spx_ctx* ctx,
                      const uint32_t fors_addr[8])
{
    uint32_t indices[SPX_FORS_TREES];
    unsigned char roots[SPX_FORS_TREES * SPX_N];
    unsigned char leaf[SPX_N];
    uint32_t fors_tree_addr[8] = {0};
    uint32_t fors_pk_addr[8] = {0};
    uint32_t idx_offset;
    unsigned int i;

    copy_keypair_addr(fors_tree_addr, fors_addr);
    copy_keypair_addr(fors_pk_addr, fors_addr);

    set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
    set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

    message_to_indices(indices, m);

    for (i = 0; i < SPX_FORS_TREES; i++) {
        idx_offset = i * (1 << SPX_FORS_HEIGHT);

        set_tree_height(fors_tree_addr, 0);
        set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
        sig += SPX_N;

        /* Derive the corresponding root node of this tree. */
        compute_root(roots + i*SPX_N, leaf, indices[i], idx_offset,
                     sig, SPX_FORS_HEIGHT, ctx, fors_tree_addr);
        sig += SPX_N * SPX_FORS_HEIGHT;
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    thash(pk, roots, SPX_FORS_TREES, ctx, fors_pk_addr);
}
