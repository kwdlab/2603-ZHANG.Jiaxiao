// kem_ml_kem_liboqs_to_wolfssl_adapter.c

#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/mlkem.h>
    #ifdef WOLFSSL_WC_MLKEM
        #include <wolfssl/wolfcrypt/wc_mlkem.h>
    #endif
    #if defined(HAVE_LIBOQS)
        #include <wolfssl/wolfcrypt/ext_mlkem.h>
    #endif
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    static WOLFSSL_HEAP_HINT* HEAP_HINT;
#else
    #define HEAP_HINT NULL
#endif /* WOLFSSL_STATIC_MEMORY */

#ifndef INVALID_DEVID
#define INVALID_DEVID -2
#endif

static WC_RNG gRng;
static int gRng_Initialized = 0;


/* RNG を初期化する */
static int ensure_global_rng(void)
{
    int ret;

    if (!gRng_Initialized) {
        ret = wc_InitRng(&gRng);
        if (ret != 0) {
            return ret;
        }
        gRng_Initialized = 1;
    }
    return 0;
}

/* KEM レベル → wolfSSL 内部 type ＋サイズ変換 */
int kem_level_params(int kem_level,
                     int    *type,
                     word32 *pk_len,
                     word32 *sk_len,
                     word32 *ct_len)
{
    if (type)    *type    = -1;
    if (pk_len)  *pk_len  = 0;
    if (sk_len)  *sk_len  = 0;
    if (ct_len)  *ct_len  = 0;

    switch (kem_level) {
        case 512:
            if (type)   *type   = WC_ML_KEM_512;
            if (pk_len) *pk_len = 800;
            if (sk_len) *sk_len = 1632;
            if (ct_len) *ct_len = 768;
            break;
        case 768:
            if (type)   *type   = WC_ML_KEM_768;
            if (pk_len) *pk_len = 1184;
            if (sk_len) *sk_len = 2400;
            if (ct_len) *ct_len = 1088;
            break;
        case 1024:
            if (type)   *type   = WC_ML_KEM_1024;
            if (pk_len) *pk_len = 1568;
            if (sk_len) *sk_len = 3168;
            if (ct_len) *ct_len = 1568;
            break;
        default:
            return -1;
    }
    return 0;
}

/* KyberKey */
int oqs_wolf_mlkem_keypair(int kem_level,
                           uint8_t *public_key,
                           uint8_t *secret_key)
{
    int       ret;
    int       type;
    word32    pk_len, sk_len;
    KyberKey  key;

    ret = kem_level_params(kem_level, &type, &pk_len, &sk_len, NULL);
    if (ret != 0 || type < 0)
        return -1;

    ret = wc_KyberKey_Init(type, &key, HEAP_HINT, INVALID_DEVID);
    if (ret < 0)
        return ret;

    ret = ensure_global_rng();
    if (ret < 0) {
        wc_KyberKey_Free(&key);
        return ret;
    }

    /* wolfSSL 内部形式で鍵ペア生成 */
    ret = wc_KyberKey_MakeKey(&key, &gRng);
    if (ret < 0)
        goto cleanup;

    /* 内部形式 → バイト列へ変換 */
    ret = wc_KyberKey_EncodePublicKey(&key, (byte *)public_key, pk_len);
    if (ret < 0)
        goto cleanup;

    ret = wc_KyberKey_EncodePrivateKey(&key, (byte *)secret_key, sk_len);
    if (ret < 0)
        goto cleanup;

    ret = 0;

cleanup:
    wc_KyberKey_Free(&key);
    return ret;
}

/* Encaps */
int oqs_wolf_mlkem_encaps(int kem_level,
                          uint8_t *ciphertext,
                          uint8_t *shared_secret,
                          const uint8_t *public_key)
{
    int       ret;
    int       type;
    word32    pk_len, ct_len;
    KyberKey  key;

    ret = kem_level_params(kem_level, &type, &pk_len, NULL, &ct_len);
    if (ret != 0 || type < 0)
        return -1;

    ret = wc_KyberKey_Init(type, &key, HEAP_HINT, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_KyberKey_DecodePublicKey(&key, (const byte *)public_key, pk_len);
    if (ret != 0)
        goto cleanup;

    ret = ensure_global_rng();
    if (ret != 0)
        goto cleanup;

    ret = wc_KyberKey_Encapsulate(&key,
                                  (byte *)ciphertext,
                                  (byte *)shared_secret,
                                  &gRng);
    if (ret != 0)
        goto cleanup;

cleanup:
    wc_KyberKey_Free(&key);
    return ret;
}

/* Decaps */
int oqs_wolf_mlkem_decaps(int kem_level,
                          uint8_t *shared_secret,
                          const uint8_t *ciphertext,
                          const uint8_t *secret_key)
{
    int       ret;
    int       type;
    word32    sk_len, ct_len;
    KyberKey  key;

    ret = kem_level_params(kem_level, &type, NULL, &sk_len, &ct_len);
    if (ret != 0 || type < 0)
        return -1;

    ret = wc_KyberKey_Init(type, &key, HEAP_HINT, INVALID_DEVID);
    if (ret != 0)
        return ret;

    ret = wc_KyberKey_DecodePrivateKey(&key, (const byte *)secret_key, sk_len);
    if (ret != 0)
        goto cleanup;

    ret = wc_KyberKey_Decapsulate(&key,
                                  (unsigned char *)shared_secret,
                                  (const unsigned char *)ciphertext,
                                  ct_len);

cleanup:
    wc_KyberKey_Free(&key);
    return ret;
}
