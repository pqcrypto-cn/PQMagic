#ifndef PQMAGIC_REFERENCE_API_H
#define PQMAGIC_REFERENCE_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PQMAGIC_AIGIS_ENC_PLUS_1_PUBLICKEYBYTES 656
#define PQMAGIC_AIGIS_ENC_PLUS_1_SECRETKEYBYTES 1456
#define PQMAGIC_AIGIS_ENC_PLUS_1_CIPHERTEXTBYTES 896
#define PQMAGIC_AIGIS_ENC_PLUS_1_BYTES 16
int pqmagic_aigis_enc_plus_1_std_mkem_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_plus_1_std_mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_1_std_mdkem_enc(uint8_t *pk, uint8_t *rnd, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_1_std_mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss);

#define PQMAGIC_AIGIS_ENC_PLUS_2_PUBLICKEYBYTES 1312
#define PQMAGIC_AIGIS_ENC_PLUS_2_SECRETKEYBYTES 2912
#define PQMAGIC_AIGIS_ENC_PLUS_2_CIPHERTEXTBYTES 1664
#define PQMAGIC_AIGIS_ENC_PLUS_2_BYTES 32
int pqmagic_aigis_enc_plus_2_std_mkem_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_plus_2_std_mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_2_std_mdkem_enc(uint8_t *pk, uint8_t *rnd, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_2_std_mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss);

#define PQMAGIC_AIGIS_ENC_PLUS_3_PUBLICKEYBYTES 2624
#define PQMAGIC_AIGIS_ENC_PLUS_3_SECRETKEYBYTES 5824
#define PQMAGIC_AIGIS_ENC_PLUS_3_CIPHERTEXTBYTES 3584
#define PQMAGIC_AIGIS_ENC_PLUS_3_BYTES 64
int pqmagic_aigis_enc_plus_3_std_mkem_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_aigis_enc_plus_3_std_mkem_enc(uint8_t *pk, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_3_std_mdkem_enc(uint8_t *pk, uint8_t *rnd, uint8_t *ss, uint8_t *ct);
int pqmagic_aigis_enc_plus_3_std_mkem_dec(uint8_t *sk, uint8_t *ct, uint8_t *ss);

#define PQMAGIC_NEV_512_769_C_PUBLICKEYBYTES 615
#define PQMAGIC_NEV_512_769_C_SECRETKEYBYTES 1246
#define PQMAGIC_NEV_512_769_C_CIPHERTEXTBYTES 512
#define PQMAGIC_NEV_512_769_C_BYTES 16
int pqmagic_nev_512_769_c_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_512_769_c_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_512_769_c_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_1024_769_C_PUBLICKEYBYTES 1229
#define PQMAGIC_NEV_1024_769_C_SECRETKEYBYTES 2490
#define PQMAGIC_NEV_1024_769_C_CIPHERTEXTBYTES 1024
#define PQMAGIC_NEV_1024_769_C_BYTES 32
int pqmagic_nev_1024_769_c_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_1024_769_c_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_1024_769_c_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_2048_769_C_PUBLICKEYBYTES 2458
#define PQMAGIC_NEV_2048_769_C_SECRETKEYBYTES 4980
#define PQMAGIC_NEV_2048_769_C_CIPHERTEXTBYTES 2048
#define PQMAGIC_NEV_2048_769_C_BYTES 64
int pqmagic_nev_2048_769_c_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_2048_769_c_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_2048_769_c_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_512_1409_PUBLICKEYBYTES 672
#define PQMAGIC_NEV_512_1409_SECRETKEYBYTES 1360
#define PQMAGIC_NEV_512_1409_CIPHERTEXTBYTES 672
#define PQMAGIC_NEV_512_1409_BYTES 16
int pqmagic_nev_512_1409_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_512_1409_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_512_1409_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_1024_1409_PUBLICKEYBYTES 1344
#define PQMAGIC_NEV_1024_1409_SECRETKEYBYTES 2720
#define PQMAGIC_NEV_1024_1409_CIPHERTEXTBYTES 1344
#define PQMAGIC_NEV_1024_1409_BYTES 32
int pqmagic_nev_1024_1409_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_1024_1409_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_1024_1409_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_2048_1409_PUBLICKEYBYTES 2688
#define PQMAGIC_NEV_2048_1409_SECRETKEYBYTES 5440
#define PQMAGIC_NEV_2048_1409_CIPHERTEXTBYTES 2688
#define PQMAGIC_NEV_2048_1409_BYTES 64
int pqmagic_nev_2048_1409_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_2048_1409_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_2048_1409_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_512_3329_PUBLICKEYBYTES 768
#define PQMAGIC_NEV_512_3329_SECRETKEYBYTES 1552
#define PQMAGIC_NEV_512_3329_CIPHERTEXTBYTES 768
#define PQMAGIC_NEV_512_3329_BYTES 16
int pqmagic_nev_512_3329_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_512_3329_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_512_3329_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_1024_3329_PUBLICKEYBYTES 1536
#define PQMAGIC_NEV_1024_3329_SECRETKEYBYTES 3104
#define PQMAGIC_NEV_1024_3329_CIPHERTEXTBYTES 1536
#define PQMAGIC_NEV_1024_3329_BYTES 32
int pqmagic_nev_1024_3329_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_1024_3329_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_1024_3329_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_2048_3329_PUBLICKEYBYTES 3072
#define PQMAGIC_NEV_2048_3329_SECRETKEYBYTES 6208
#define PQMAGIC_NEV_2048_3329_CIPHERTEXTBYTES 3072
#define PQMAGIC_NEV_2048_3329_BYTES 64
int pqmagic_nev_2048_3329_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_2048_3329_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_2048_3329_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_512_769_PUBLICKEYBYTES 615
#define PQMAGIC_NEV_512_769_SECRETKEYBYTES 1246
#define PQMAGIC_NEV_512_769_CIPHERTEXTBYTES 615
#define PQMAGIC_NEV_512_769_BYTES 16
int pqmagic_nev_512_769_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_512_769_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_512_769_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_1024_769_PUBLICKEYBYTES 1229
#define PQMAGIC_NEV_1024_769_SECRETKEYBYTES 2490
#define PQMAGIC_NEV_1024_769_CIPHERTEXTBYTES 1229
#define PQMAGIC_NEV_1024_769_BYTES 32
int pqmagic_nev_1024_769_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_1024_769_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_1024_769_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_2048_769_PUBLICKEYBYTES 2458
#define PQMAGIC_NEV_2048_769_SECRETKEYBYTES 4980
#define PQMAGIC_NEV_2048_769_CIPHERTEXTBYTES 2458
#define PQMAGIC_NEV_2048_769_BYTES 64
int pqmagic_nev_2048_769_std_kem_cca_keygen(uint8_t *pk, uint8_t *sk);
int pqmagic_nev_2048_769_std_kem_cca_enc(uint8_t *ss, uint8_t *ct, const uint8_t *pk);
int pqmagic_nev_2048_769_std_kem_cca_dec(uint8_t *ss, uint8_t *ct, uint8_t *sk);

#define PQMAGIC_NEV_AKE_512_769_C_PUBLICKEYBYTES 615
#define PQMAGIC_NEV_AKE_512_769_C_SECRETKEYBYTES 1246
#define PQMAGIC_NEV_AKE_512_769_C_M1_BYTES 1127
#define PQMAGIC_NEV_AKE_512_769_C_M2_BYTES 1127
#define PQMAGIC_NEV_AKE_512_769_C_STATE_BYTES 1758
#define PQMAGIC_NEV_AKE_512_769_C_BYTES 16
int pqmagic_nev_ake_512_769_c_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_512_769_c_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_512_769_c_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_512_769_c_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_512_769_c_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_1024_769_C_PUBLICKEYBYTES 1229
#define PQMAGIC_NEV_AKE_1024_769_C_SECRETKEYBYTES 2490
#define PQMAGIC_NEV_AKE_1024_769_C_M1_BYTES 2253
#define PQMAGIC_NEV_AKE_1024_769_C_M2_BYTES 2253
#define PQMAGIC_NEV_AKE_1024_769_C_STATE_BYTES 3514
#define PQMAGIC_NEV_AKE_1024_769_C_BYTES 32
int pqmagic_nev_ake_1024_769_c_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_1024_769_c_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_1024_769_c_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_1024_769_c_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_1024_769_c_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_2048_769_C_PUBLICKEYBYTES 2458
#define PQMAGIC_NEV_AKE_2048_769_C_SECRETKEYBYTES 4980
#define PQMAGIC_NEV_AKE_2048_769_C_M1_BYTES 4506
#define PQMAGIC_NEV_AKE_2048_769_C_M2_BYTES 4506
#define PQMAGIC_NEV_AKE_2048_769_C_STATE_BYTES 7028
#define PQMAGIC_NEV_AKE_2048_769_C_BYTES 64
int pqmagic_nev_ake_2048_769_c_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_2048_769_c_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_2048_769_c_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_2048_769_c_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_2048_769_c_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_512_1409_PUBLICKEYBYTES 672
#define PQMAGIC_NEV_AKE_512_1409_SECRETKEYBYTES 1360
#define PQMAGIC_NEV_AKE_512_1409_M1_BYTES 1344
#define PQMAGIC_NEV_AKE_512_1409_M2_BYTES 1344
#define PQMAGIC_NEV_AKE_512_1409_STATE_BYTES 2032
#define PQMAGIC_NEV_AKE_512_1409_BYTES 16
int pqmagic_nev_ake_512_1409_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_512_1409_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_512_1409_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_512_1409_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_512_1409_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_1024_1409_PUBLICKEYBYTES 1344
#define PQMAGIC_NEV_AKE_1024_1409_SECRETKEYBYTES 2720
#define PQMAGIC_NEV_AKE_1024_1409_M1_BYTES 2688
#define PQMAGIC_NEV_AKE_1024_1409_M2_BYTES 2688
#define PQMAGIC_NEV_AKE_1024_1409_STATE_BYTES 4064
#define PQMAGIC_NEV_AKE_1024_1409_BYTES 32
int pqmagic_nev_ake_1024_1409_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_1024_1409_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_1024_1409_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_1024_1409_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_1024_1409_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_2048_1409_PUBLICKEYBYTES 2688
#define PQMAGIC_NEV_AKE_2048_1409_SECRETKEYBYTES 5440
#define PQMAGIC_NEV_AKE_2048_1409_M1_BYTES 5376
#define PQMAGIC_NEV_AKE_2048_1409_M2_BYTES 5376
#define PQMAGIC_NEV_AKE_2048_1409_STATE_BYTES 8128
#define PQMAGIC_NEV_AKE_2048_1409_BYTES 64
int pqmagic_nev_ake_2048_1409_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_2048_1409_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_2048_1409_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_2048_1409_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_2048_1409_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_512_769_PUBLICKEYBYTES 615
#define PQMAGIC_NEV_AKE_512_769_SECRETKEYBYTES 1246
#define PQMAGIC_NEV_AKE_512_769_M1_BYTES 1230
#define PQMAGIC_NEV_AKE_512_769_M2_BYTES 1230
#define PQMAGIC_NEV_AKE_512_769_STATE_BYTES 1861
#define PQMAGIC_NEV_AKE_512_769_BYTES 16
int pqmagic_nev_ake_512_769_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_512_769_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_512_769_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_512_769_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_512_769_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_1024_769_PUBLICKEYBYTES 1229
#define PQMAGIC_NEV_AKE_1024_769_SECRETKEYBYTES 2490
#define PQMAGIC_NEV_AKE_1024_769_M1_BYTES 2458
#define PQMAGIC_NEV_AKE_1024_769_M2_BYTES 2458
#define PQMAGIC_NEV_AKE_1024_769_STATE_BYTES 3719
#define PQMAGIC_NEV_AKE_1024_769_BYTES 32
int pqmagic_nev_ake_1024_769_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_1024_769_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_1024_769_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_1024_769_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_1024_769_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_NEV_AKE_2048_769_PUBLICKEYBYTES 2458
#define PQMAGIC_NEV_AKE_2048_769_SECRETKEYBYTES 4980
#define PQMAGIC_NEV_AKE_2048_769_M1_BYTES 4916
#define PQMAGIC_NEV_AKE_2048_769_M2_BYTES 4916
#define PQMAGIC_NEV_AKE_2048_769_STATE_BYTES 7438
#define PQMAGIC_NEV_AKE_2048_769_BYTES 64
int pqmagic_nev_ake_2048_769_std_ake_party_keygen(uint8_t *pk, uint8_t *sk);
void pqmagic_nev_ake_2048_769_std_ake_keygen(uint8_t *pki, uint8_t *ski, uint8_t *pkj, uint8_t *skj);
void pqmagic_nev_ake_2048_769_std_ake_init(uint8_t *message, uint8_t *state, const uint8_t *ski, const uint8_t *pkj);
void pqmagic_nev_ake_2048_769_std_ake_der_response(uint8_t *response, uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *skj, const uint8_t *pki, const uint8_t *message);
void pqmagic_nev_ake_2048_769_std_ake_der_init(uint8_t *key, const uint8_t *idi, const uint8_t *idj, const uint8_t *ski, const uint8_t *pkj, const uint8_t *state, const uint8_t *response);

#define PQMAGIC_AIGIS_SIG_PLUS_1_PUBLICKEYBYTES 928
#define PQMAGIC_AIGIS_SIG_PLUS_1_SECRETKEYBYTES 2800
#define PQMAGIC_AIGIS_SIG_PLUS_1_SIGBYTES 2015
int pqmagic_aigis_sig_plus_1_std_msig_keygen(unsigned char *pk, unsigned char *sk);
int pqmagic_aigis_sig_plus_1_std_msig_sign(unsigned char *sk, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_aigis_sig_plus_1_std_msig_verf(unsigned char *pk, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

#define PQMAGIC_AIGIS_SIG_PLUS_2_PUBLICKEYBYTES 1824
#define PQMAGIC_AIGIS_SIG_PLUS_2_SECRETKEYBYTES 4976
#define PQMAGIC_AIGIS_SIG_PLUS_2_SIGBYTES 4533
int pqmagic_aigis_sig_plus_2_std_msig_keygen(unsigned char *pk, unsigned char *sk);
int pqmagic_aigis_sig_plus_2_std_msig_sign(unsigned char *sk, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_aigis_sig_plus_2_std_msig_verf(unsigned char *pk, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

#define PQMAGIC_AIGIS_SIG_PLUS_3_PUBLICKEYBYTES 4672
#define PQMAGIC_AIGIS_SIG_PLUS_3_SECRETKEYBYTES 8800
#define PQMAGIC_AIGIS_SIG_PLUS_3_SIGBYTES 9134
int pqmagic_aigis_sig_plus_3_std_msig_keygen(unsigned char *pk, unsigned char *sk);
int pqmagic_aigis_sig_plus_3_std_msig_sign(unsigned char *sk, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_aigis_sig_plus_3_std_msig_verf(unsigned char *pk, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

#define PQMAGIC_QIMEN_PIKE_NGCC_1_PUBLICKEYBYTES 389
#define PQMAGIC_QIMEN_PIKE_NGCC_1_SECRETKEYBYTES 472
#define PQMAGIC_QIMEN_PIKE_NGCC_1_CIPHERTEXTBYTES 602
#define PQMAGIC_QIMEN_PIKE_NGCC_1_BYTES 32
#define PQMAGIC_QIMEN_PIKE_NGCC_2_PUBLICKEYBYTES 592
#define PQMAGIC_QIMEN_PIKE_NGCC_2_SECRETKEYBYTES 734
#define PQMAGIC_QIMEN_PIKE_NGCC_2_CIPHERTEXTBYTES 882
#define PQMAGIC_QIMEN_PIKE_NGCC_2_BYTES 32
#define PQMAGIC_QIMEN_PIKE_NGCC_3_PUBLICKEYBYTES 1198
#define PQMAGIC_QIMEN_PIKE_NGCC_3_SECRETKEYBYTES 1497
#define PQMAGIC_QIMEN_PIKE_NGCC_3_CIPHERTEXTBYTES 1746
#define PQMAGIC_QIMEN_PIKE_NGCC_3_BYTES 64

unsigned long long pqmagic_qimen_pike_ngcc_1_std_kem_get_pk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_1_std_kem_get_sk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_1_std_kem_get_ss_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_1_std_kem_get_ct_len_bytes(void);
int pqmagic_qimen_pike_ngcc_1_std_kem_keygen(unsigned char *pk, unsigned long long *pk_len_bytes, unsigned char *sk, unsigned long long *sk_len_bytes);
int pqmagic_qimen_pike_ngcc_1_std_kem_enc(unsigned char *pk, unsigned long long pk_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes, unsigned char *ct, unsigned long long *ct_len_bytes);
int pqmagic_qimen_pike_ngcc_1_std_kem_dec(unsigned char *sk, unsigned long long sk_len_bytes, unsigned char *ct, unsigned long long ct_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes);

unsigned long long pqmagic_qimen_pike_ngcc_2_std_kem_get_pk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_2_std_kem_get_sk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_2_std_kem_get_ss_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_2_std_kem_get_ct_len_bytes(void);
int pqmagic_qimen_pike_ngcc_2_std_kem_keygen(unsigned char *pk, unsigned long long *pk_len_bytes, unsigned char *sk, unsigned long long *sk_len_bytes);
int pqmagic_qimen_pike_ngcc_2_std_kem_enc(unsigned char *pk, unsigned long long pk_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes, unsigned char *ct, unsigned long long *ct_len_bytes);
int pqmagic_qimen_pike_ngcc_2_std_kem_dec(unsigned char *sk, unsigned long long sk_len_bytes, unsigned char *ct, unsigned long long ct_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes);

unsigned long long pqmagic_qimen_pike_ngcc_3_std_kem_get_pk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_3_std_kem_get_sk_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_3_std_kem_get_ss_len_bytes(void);
unsigned long long pqmagic_qimen_pike_ngcc_3_std_kem_get_ct_len_bytes(void);
int pqmagic_qimen_pike_ngcc_3_std_kem_keygen(unsigned char *pk, unsigned long long *pk_len_bytes, unsigned char *sk, unsigned long long *sk_len_bytes);
int pqmagic_qimen_pike_ngcc_3_std_kem_enc(unsigned char *pk, unsigned long long pk_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes, unsigned char *ct, unsigned long long *ct_len_bytes);
int pqmagic_qimen_pike_ngcc_3_std_kem_dec(unsigned char *sk, unsigned long long sk_len_bytes, unsigned char *ct, unsigned long long ct_len_bytes, unsigned char *ss, unsigned long long *ss_len_bytes);

unsigned long long pqmagic_resolved_alpha_160f_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_160f_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_160f_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_160f_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_160f_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_160f_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_160s_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_160s_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_160s_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_160s_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_160s_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_160s_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_256f_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_256f_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_256f_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_256f_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_256f_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_256f_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_256s_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_256s_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_256s_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_256s_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_256s_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_256s_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_384f_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_384f_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_384f_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_384f_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_384f_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_384f_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_384s_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_384s_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_384s_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_384s_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_384s_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_384s_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_512f_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_512f_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_512f_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_512f_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_512f_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_512f_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

unsigned long long pqmagic_resolved_alpha_512s_std_sig_get_pk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_512s_std_sig_get_sk_len_bytes(void);
unsigned long long pqmagic_resolved_alpha_512s_std_sig_get_sn_len_bytes(void);
int pqmagic_resolved_alpha_512s_std_sig_keygen(unsigned char *pk, unsigned long long *pk_length, unsigned char *sk, unsigned long long *sk_length);
int pqmagic_resolved_alpha_512s_std_sig_sign(unsigned char *sk, unsigned long long sk_length, unsigned char *message, unsigned long long message_length, unsigned char *signature, unsigned long long *signature_length);
int pqmagic_resolved_alpha_512s_std_sig_verify(unsigned char *pk, unsigned long long pk_length, unsigned char *signature, unsigned long long signature_length, unsigned char *message, unsigned long long message_length);

#ifdef __cplusplus
}
#endif

#endif
