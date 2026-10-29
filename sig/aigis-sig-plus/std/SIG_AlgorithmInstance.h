/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#ifndef SIG_ALGORITHM_INSTANCE_H
#define SIG_ALGORITHM_INSTANCE_H

// Set "OUTPUT_BLANK_TEST_VECTORS" as 0 to generate test vector files
// Set "OUTPUT_BLANK_TEST_VECTORS" as 1 to generate blank template (default)
#define OUTPUT_BLANK_TEST_VECTORS 0

// Set "ALGORITHM_INSTANCE" as your algorithm instance name (no more than 64 bytes)
// Only letters, numbers, '-' or '_' are permitted
#define TO_STR(x) #x
#define STR(x) TO_STR(x)
#define SIG_ALGNAME "Aigis-sig"
#define ALGORITHM_INSTANCE SIG_ALGNAME STR(PARAMS)

#ifdef __cplusplus
extern "C"
{
#endif

	/// @brief Obtain the claimed byte length of the public key
	/// @return Claimed byte length of the public key
	unsigned long long sig_get_pk_len_bytes();

	/// @brief Obtain the claimed byte length of the private key
	/// @return Claimed byte length of the private key
	unsigned long long sig_get_sk_len_bytes();

	/// @brief Obtain the claimed byte length of the signature
	/// @return Claimed byte length of the signature
	unsigned long long sig_get_sn_len_bytes();

	/// @brief Key generate
	/// @param[out] pk Public key
	/// @param[out] pk_len_bytes Byte length of the public key
	/// @param[out] sk Private key
	/// @param[out] sk_len_bytes Byte length of the private key
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int sig_keygen(
		unsigned char *pk, unsigned long long *pk_len_bytes,
		unsigned char *sk, unsigned long long *sk_len_bytes);

	/// @brief Sign
	/// @param[in] sk Private key
	/// @param[in] sk_len_bytes Byte length of the private key
	/// @param[in] m Message
	/// @param[in] m_len_bytes Byte length of the message
	/// @param[out] sn Signature
	/// @param[out] sn_len_bytes Byte length of the signature
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int sig_sign(
		unsigned char *sk, unsigned long long sk_len_bytes,
		unsigned char *m, unsigned long long m_len_bytes,
		unsigned char *sn, unsigned long long *sn_len_bytes);

	/// @brief Verify
	/// @param[in] pk Public key
	/// @param[in] pk_len_bytes Byte length of the public key
	/// @param[in] sn Signature
	/// @param[in] sn_len_bytes Byte length of the signature
	/// @param[in] m Message
	/// @param[in] m_len_bytes Byte length of the message
	/// @return If the signature is valid, return 0; if the signature is invalid, return -1; otherwise, return a self-defined negative (-2 to -99) error code
	int sig_verify(
		unsigned char *pk, unsigned long long pk_len_bytes,
		unsigned char *sn, unsigned long long sn_len_bytes,
		unsigned char *m, unsigned long long m_len_bytes);

#ifdef __cplusplus
}
#endif
#endif