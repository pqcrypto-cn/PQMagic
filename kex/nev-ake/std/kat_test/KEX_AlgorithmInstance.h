/*
The software is provided by the Institute of Commercial Cryptography Standards
(ICCS), and is used for algorithm submissions in the Next-generation Commercial
Cryptographic Algorithms Program (NGCC).

ICCS doesn't represent or warrant that the operation of the software will be
uninterrupted or error-free in all cases. ICCS will take no responsibility for
the use of the software or the results thereof, if the software is used for any
other purposes.
*/

#ifndef KEX_ALGORITHM_INSTANCE_H
#define KEX_ALGORITHM_INSTANCE_H

#include "../params.h"

// Set "OUTPUT_BLANK_TEST_VECTORS" as 0 to generate test vector files
// Set "OUTPUT_BLANK_TEST_VECTORS" as 1 to generate blank template (default)
#define OUTPUT_BLANK_TEST_VECTORS 0

// Set "ALGORITHM_INSTANCE" as your algorithm instance name (no more than 64 bytes)
// Only letters, numbers, '-' or '_' are permitted

#define TO_STR_INNER(x) #x
#define TO_STR(x) TO_STR_INNER(x)

#if defined(USE_SHA3) && defined(USE_ICCS)
#error "USE_SHA3 and USE_ICCS cannot be enabled at the same time"
#elif defined(USE_SHA3)
#define HASH_BACKEND_SUFFIX "_SHA3"
#elif defined(USE_ICCS)
#define HASH_BACKEND_SUFFIX "_ICCS"
#else
#error "Either USE_SHA3 or USE_ICCS must be defined"
#endif

#if COMPRESS == 1
#define COMPRESS_SUFFIX "_C"
#else
#define COMPRESS_SUFFIX ""
#endif

#define ALGORITHM_INSTANCE \
"NEV_AKE_" TO_STR(PARAM_N) "_" TO_STR(PARAM_Q) COMPRESS_SUFFIX HASH_BACKEND_SUFFIX

#ifdef __cplusplus
extern "C"
{
#endif

	/// @brief Obtain the claimed number of passes
	/// @return Claimed pass
	unsigned long long kex_get_passes_num();

	/// @brief Obtain the claimed byte length of the long-term public key
	/// @return If the authentication function is available, return the claimed byte length of the long-term public key; if not, return 0
	unsigned long long kex_get_pk_len_bytes();

	/// @brief Obtain the claimed byte length of the long-term private key
	/// @return If the authentication function is available, return the claimed byte length of the long-term private key; if not, return 0
	unsigned long long kex_get_sk_len_bytes();

	/// @brief Obtain the maximum byte length of the initiator state information buffer
	/// @return The maximum byte length of the initiator state information buffer
	unsigned long long kex_get_sta_len_bytes();

	/// @brief Obtain the maximum byte length of the responder state information buffer
	/// @return The maximum byte length of the responder state information buffer
	unsigned long long kex_get_stb_len_bytes();

	/// @brief Obtain the claimed byte length of the shared secret key
	/// @return Claimed byte length of the shared secret key
	unsigned long long kex_get_ss_len_bytes();

	/// @brief Obtain the claimed byte length of all messages
	/// @return Claimed byte length of all messages
	unsigned long long kex_get_total_msg_len_bytes();

	/// @brief initialize by the initiator
	/// @param[out] pka Initiator long-term public key
	/// @param[out] pka_len_bytes Byte length of the initiator long-term public key (0 if no long-term public key)
	/// @param[out] ska Initiator long-term private key
	/// @param[out] ska_len_bytes Byte length of the initiator long-term private key (0 if no long-term private key)
	/// @param[out] sta Initiator state information
	/// @param[out] sta_len_bytes Byte length of the initiator state information (0 if no state information output)
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_init_a(
		unsigned char *pka, unsigned long long *pka_len_bytes,
		unsigned char *ska, unsigned long long *ska_len_bytes,
		unsigned char *sta, unsigned long long *sta_len_bytes);

	/// @brief initialize by the responder
	/// @param[out] pkb Responder long-term public key
	/// @param[out] pkb_len_bytes Byte length of the responder long-term public key (0 if no long-term public key)
	/// @param[out] skb Responder long-term private key
	/// @param[out] skb_len_bytes Byte length of the responder long-term private key (0 if no long-term private key)
	/// @param[out] stb Responder state information
	/// @param[out] stb_len_bytes Byte length of the responder state information (0 if no state information output)
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_init_b(
		unsigned char *pkb, unsigned long long *pkb_len_bytes,
		unsigned char *skb, unsigned long long *skb_len_bytes,
		unsigned char *stb, unsigned long long *stb_len_bytes);

	/// @brief generate the first-pass message sent by the initiator
	/// @param[in] ska Initiator long-term private key
	/// @param[in] ska_len_bytes Byte length of the initiator long-term private key
	/// @param[in] pkb Responder long-term public key
	/// @param[in] pkb_len_bytes Byte length of the responder long-term public key
	/// @param[in,out] sta Initiator state information (might be updated after execution)
	/// @param[in,out] sta_len_bytes Byte length of the initiator state information
	/// @param[out] m1 Message sent by the initiator in this pass
	/// @param[out] m1_len_bytes Byte length of the message sent by the initiator in this pass
	/// @return If key exchange is finished, return 1; if key exchange is not finished, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_generate_pass1_msg_a(
		unsigned char *ska, unsigned long long ska_len_bytes,
		unsigned char *pkb, unsigned long long pkb_len_bytes,
		unsigned char *sta, unsigned long long *sta_len_bytes,
		unsigned char *m1, unsigned long long *m1_len_bytes);

	/// @brief generate the second-pass message sent by the responder (implement this function if and only if kex_generate_pass1_msg_a returns 0)
	/// @param[in] skb Responder long-term private key
	/// @param[in] skb_len_bytes Byte length of the responder long-term private key
	/// @param[in] pka Initiator long-term public key
	/// @param[in] pka_len_bytes Byte length of the initiator long-term public key
	/// @param[in] m1 First-pass message sent by the initiator
	/// @param[in] m1_len_bytes Byte length of the first-pass message sent by the initiator
	/// @param[in,out] stb Responder state information (might be updated after execution)
	/// @param[in,out] stb_len_bytes Byte length of the responder state information
	/// @param[out] m2 Message sent by the the responder in this pass
	/// @param[out] m2_len_bytes Byte length of the message sent by the responder in this pass
	/// @return If key exchange is finished, return 1; if key exchange is not finished, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_generate_pass2_msg_b(
		unsigned char *skb, unsigned long long skb_len_bytes,
		unsigned char *pka, unsigned long long pka_len_bytes,
		unsigned char *m1, unsigned long long m1_len_bytes,
		unsigned char *stb, unsigned long long *stb_len_bytes,
		unsigned char *m2, unsigned long long *m2_len_bytes);

	/// @brief generate the third-pass message sent by the initiator (implement this function if and only if kex_generate_pass2_msg_b returns 0)
	/// @param[in] ska Initiator long-term private key
	/// @param[in] ska_len_bytes Byte length of the initiator long-term private key
	/// @param[in] pkb Responder long-term public key
	/// @param[in] pkb_len_bytes Byte length of the responder long-term public key
	/// @param[in] m2 Message sent by the responder
	/// @param[in] m2_len_bytes Byte length of the message sent by the responder
	/// @param[in,out] sta Initiator state information (might be updated after execution)
	/// @param[in,out] sta_len_bytes Byte length of the initiator state information
	/// @param[out] m3 Message sent by the initiator in this pass
	/// @param[out] m3_len_bytes Byte length of the message sent by the initiator in this pass
	/// @return If key exchange is finished, return 1; if key exchange is not finished, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_generate_pass3_msg_a(
		unsigned char *ska, unsigned long long ska_len_bytes,
		unsigned char *pkb, unsigned long long pkb_len_bytes,
		unsigned char *m2, unsigned long long m2_len_bytes,
		unsigned char *sta, unsigned long long *sta_len_bytes,
		unsigned char *m3, unsigned long long *m3_len_bytes);

	/*
	For key exchange protocols with more passes, the corresponding message
	generation functions shall be implemented likewise:
		int kex_generate_pass4_msg_b(
			unsigned char *skb, unsigned long long skb_len_bytes,
			unsigned char *pka, unsigned long long pka_len_bytes,
			unsigned char *m3, unsigned long long m3_len_bytes,
			unsigned char *stb, unsigned long long *stb_len_bytes,
			unsigned char *m4, unsigned long long *m4_len_bytes);
		int kex_generate_pass5_msg_a(
			unsigned char *ska, unsigned long long ska_len_bytes,
			unsigned char *pkb, unsigned long long pkb_len_bytes,
			unsigned char *m4, unsigned long long m4_len_bytes,
			unsigned char *sta, unsigned long long *sta_len_bytes,
			unsigned char *m5, unsigned long long *m5_len_bytes);
		...
	*/

	/// @brief derive the shared secret key by the initiator
	/// @param[in] ska Initiator long-term private key
	/// @param[in] ska_len_bytes Byte length of the initiator long-term private key
	/// @param[in] pkb Responder long-term public key
	/// @param[in] pkb_len_bytes Byte length of the responder long-term public key
	/// @param[in] mb The last message sent by the responder
	/// @param[in] mb_len_bytes Byte length of the last message sent by the responder
	/// @param[in] sta Initiator state information
	/// @param[in] sta_len_bytes Byte length of the initiator state information
	/// @param[out] ssa Shared secret key of the initiator
	/// @param[out] ssa_len_bytes Byte length of the shared secret key of the initiator
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_derive_ss_a(
		unsigned char *ska, unsigned long long ska_len_bytes,
		unsigned char *pkb, unsigned long long pkb_len_bytes,
		unsigned char *mb, unsigned long long mb_len_bytes,
		unsigned char *sta, unsigned long long sta_len_bytes,
		unsigned char *ssa, unsigned long long *ssa_len_bytes);

	/// @brief derive the shared secret key by the responder
	/// @param[in] skb Responder long-term private key
	/// @param[in] skb_len_bytes Byte length of the responder long-term private key
	/// @param[in] pka Initiator long-term public key
	/// @param[in] pka_len_bytes Byte length of the initiator long-term public key
	/// @param[in] ma The last message sent by the initiator
	/// @param[in] ma_len_bytes Byte length of the last message sent by the initiator
	/// @param[in] stb Responder state information
	/// @param[in] stb_len_bytes Byte length of the responder state information
	/// @param[out] ssb Shared secret key of the responder
	/// @param[out] ssb_len_bytes Byte length of the shared secret key of the responder
	/// @return If run successfully, return 0; otherwise, return a self-defined negative (-1 to -99) error code
	int kex_derive_ss_b(
		unsigned char *skb, unsigned long long skb_len_bytes,
		unsigned char *pka, unsigned long long pka_len_bytes,
		unsigned char *ma, unsigned long long ma_len_bytes,
		unsigned char *stb, unsigned long long stb_len_bytes,
		unsigned char *ssb, unsigned long long *ssb_len_bytes);

#ifdef __cplusplus
}
#endif
#endif
