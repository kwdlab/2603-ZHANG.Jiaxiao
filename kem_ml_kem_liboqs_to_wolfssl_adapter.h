// kem_ml_kem_liboqs_to_wolfssl_adapter.h
#ifndef KEM_ML_KEM_LIBOQS_TO_WOLFSSL_ADAPTER_H
#define KEM_ML_KEM_LIBOQS_TO_WOLFSSL_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int kem_level_params(int    kem_level,
                     int   *type,
                     word32 *pk_len,
                     word32 *sk_len,
                     word32 *ct_len);

int oqs_wolf_mlkem_keypair(int kem_level,
                           uint8_t *public_key,
                           uint8_t *secret_key);

int oqs_wolf_mlkem_encaps(int kem_level,
                          uint8_t *ciphertext,
                          uint8_t *shared_secret,
                          const uint8_t *public_key);

int oqs_wolf_mlkem_decaps(int kem_level,
                          uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const uint8_t *secret_key);

#ifdef __cplusplus
}
#endif

#endif /* KEM_ML_KEM_LIBOQS_TO_WOLFSSL_ADAPTER_H */
