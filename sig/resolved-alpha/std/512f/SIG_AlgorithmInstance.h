/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef SIG_RESOLVED_ALPHA_512F_H
#define SIG_RESOLVED_ALPHA_512F_H

#define OUTPUT_BLANK_TEST_VECTORS 0
#define ALGORITHM_INSTANCE "ReSolveD-alpha-512f"

#define SIG_PK_BYTES  385
#define SIG_SK_BYTES  128
#define SIG_SN_BYTES  72611
#define SIG_CSP_BYTES (512 / 8)

#ifdef __cplusplus
extern "C" {
#endif

unsigned long long sig_get_pk_len_bytes(void);
unsigned long long sig_get_sk_len_bytes(void);
unsigned long long sig_get_sn_len_bytes(void);

int sig_keygen(
    unsigned char *pk, unsigned long long *pk_len_bytes,
    unsigned char *sk, unsigned long long *sk_len_bytes);

int sig_sign(
    unsigned char *sk, unsigned long long sk_len_bytes,
    unsigned char *m, unsigned long long m_len_bytes,
    unsigned char *sn, unsigned long long *sn_len_bytes);

int sig_verify(
    unsigned char *pk, unsigned long long pk_len_bytes,
    unsigned char *sn, unsigned long long sn_len_bytes,
    unsigned char *m, unsigned long long m_len_bytes);

#ifdef __cplusplus
}
#endif

#endif
