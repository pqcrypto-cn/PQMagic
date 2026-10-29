#ifndef SHA3_H__
#define SHA3_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

    /*
     * Context for a SHAKE computation. Contents are opaque.
     * Contents are pure data with no pointer; they need not be released
     * explicitly and don't reference any other allocated resource. The
     * caller is responsible for allocating the context structure itself,
     * typically on the stack.
     * A running state can be cloned by copying the structure; this is
     * useful if "partial hashes" (hash of data processed so far) are
     * needed, without preventing injecting extra bytes later on.
     */
    typedef struct
    {
        uint64_t A[25];
        unsigned dptr, rate;
    } shake_context;

    /*
     * Initialize a SHAKE context to its initial state. The state is
     * then ready to receive data (with shake_inject()).
     *
     * The "size" parameter should be 128 for SHAKE128, 256 for SHAKE256.
     * This is half of the internal parameter known as "capacity" (SHAKE128
     * works on an internal 256-bit capacity, SHAKE256 uses a 512-bit
     * capacity).
     */
    void shake_init(shake_context *sc, unsigned size);

    /*
     * Inject some data bytes into the SHAKE context ("absorb" operation).
     * This function can be called several times, to inject several chunks
     * of data of arbitrary length.
     */
    void shake_inject(shake_context *sc, const void *data, size_t len);

    /*
     * Flip the SHAKE state to output mode. After this call, shake_inject()
     * can no longer be called on the context, but shake_extract() can be
     * called.
     *
     * Flipping is one-way; a given context can be converted back to input
     * mode only by initializing it again, which forgets all previously
     * injected data.
     */
    void shake_flip(shake_context *sc);

    /*
     * Extract bytes from the SHAKE context ("squeeze" operation). The
     * context must have been flipped to output mode (with shake_flip()).
     * Arbitrary amounts of data can be extracted, in one or several calls
     * to this function.
     */
    void shake_extract(shake_context *sc, void *out, size_t len);

    /*
     * Context for SHA3 computations. Contents are opaque.
     * A running state can be cloned by copying the structure; this is
     * useful if "partial hashes" (hash of data processed so far) are
     * needed, without preventing injecting extra bytes later on.
     */
    typedef shake_context sha3_context;

    /*
     * Initialize a SHA3 context, for a given output size (in bits), e.g.
     * set size to 256 for SHA3-256.
     */
    void sha3_init(sha3_context *sc, unsigned size);

    /*
     * Update a SHA3 context with some bytes.
     */
    void sha3_update(sha3_context *sc, const void *in, size_t len);

    /*
     * Finalize a SHA3 computation. The hash output is written in dst[],
     * with a size that depends on the one provided when the context was
     * last initialized.
     *
     * The context is modified. If a new hash must be computed, the context
     * must first be reinitialized explicitly.
     */
    void sha3_close(sha3_context *sc, void *out);

#ifdef __cplusplus
}
#endif

#endif
