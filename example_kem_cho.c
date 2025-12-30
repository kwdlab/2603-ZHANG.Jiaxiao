/*
 * example_kem_cho.c
 *
 * liboqsが変換アダプタを経由しwolfSSLを使用できるようにした拡張したコード。
 *
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <math.h>

//wolfsslのための宣言

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include "kem_ml_kem_liboqs_to_wolfssl_adapter.h"

#ifdef __APPLE__
#include <mach/mach_time.h>
#endif

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

#include <oqs/oqs.h>

#ifndef INVALID_DEVID
#define INVALID_DEVID -2
#endif

/* ============================================================================
 *  高精度な時間計測（単調増加タイマ）
 *  - ベンチマークでは「時間が戻らない」「できるだけ高精度」が重要
 *  - macOS: mach_absolute_time（ナノ秒換算）
 *  - Linux等: clock_gettime(CLOCK_MONOTONIC)
 * ============================================================================ */

#ifdef __APPLE__
// macOS: mach_absolute_time を ns に変換するための timebase を一度だけ初期化
static mach_timebase_info_data_t timebase_info;
static int timebase_initialized = 0;

static inline void init_timebase(void) {
    if (!timebase_initialized) {
        mach_timebase_info(&timebase_info);
        timebase_initialized = 1;
    }
}

// 単調増加時計の現在時刻（ns）を返す
static inline uint64_t mono_ns(void) {
    init_timebase();
    uint64_t mach_time = mach_absolute_time();
    /* mach tick -> ns 変換 */
    return (mach_time * timebase_info.numer) / timebase_info.denom;
}

#else
/* Linux/others: POSIX の単調増加タイマ（ns） */
static inline uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
#endif

//統計計算（中央値のためにソートを行う）

static int compare_uint64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t*)a;
    uint64_t ub = *(const uint64_t*)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static int compare_double(const void *a, const void *b) {
    double da = *(const double*)a;
    double db = *(const double*)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

/**
 * compute_statistics - 時間データ（ns）の統計値を計算
 *
 * @times: 各試行の処理時間（ナノ秒）配列
 * @count: 測定回数（配列要素数）
 *
 * 出力：
 *  - mean_ns:   平均（ns）
 *  - median_ns: 中央値（ns）
 *  - variance_ns2: 分散（ns^2）
 *  - stddev_ns: 標準偏差（ns）
 *  - min_ns / max_ns: 最小・最大（ns）
 */
static void compute_statistics(uint64_t *times, uint64_t count,
                               double *mean_ns, double *median_ns,
                               double *variance_ns2, double *stddev_ns,
                               double *min_ns, double *max_ns) {
    if (count == 0) {
        *mean_ns = 0.0;
        *median_ns = 0.0;
        *variance_ns2 = 0.0;
        *stddev_ns = 0.0;
        *min_ns = 0.0;
        *max_ns = 0.0;
        return;
    }

    /* 中央値/min/max のためソート */
    qsort(times, count, sizeof(uint64_t), compare_uint64);

    *min_ns = (double)times[0];
    *max_ns = (double)times[count - 1];

    /* 平均（ns） */
    uint64_t sum = 0;
    for (uint64_t i = 0; i < count; i++) {
        sum += times[i];
    }
    *mean_ns = (double)sum / (double)count;

    /* 中央値（ns） */
    if (count % 2 == 0) {
        *median_ns = (times[count/2 - 1] + times[count/2]) / 2.0;
    } else {
        *median_ns = (double)times[count/2];
    }

    /* 分散・標準偏差 */
    double sum_sq_diff = 0.0;
    for (uint64_t i = 0; i < count; i++) {
        double diff = (double)times[i] - *mean_ns;
        sum_sq_diff += diff * diff;
    }
    *variance_ns2 = sum_sq_diff / (double)count;
    *stddev_ns = sqrt(*variance_ns2);
}

/**
 * compute_ops_statistics - ops/sec の統計値を計算
 *
 * 各試行時間 times[i]（ns）から
 *   ops/sec = 1 / (time[s]) = 1e9 / time[ns]
 * を計算して、その配列の統計（平均/中央値/分散/標準偏差/min/max）を出す。
 *
 * 注意：
 *  - times は ns のまま渡し、内部で ops/sec に変換します。
 *  - min/max は「ops/sec の最小/最大」（＝遅い/速い）です。
 */
static void compute_ops_statistics(uint64_t *times, uint64_t count,
                                   double *mean_ops, double *median_ops,
                                   double *variance_ops2, double *stddev_ops,
                                   double *min_ops, double *max_ops) {
    if (count == 0) {
        *mean_ops = 0.0;
        *median_ops = 0.0;
        *variance_ops2 = 0.0;
        *stddev_ops = 0.0;
        *min_ops = 0.0;
        *max_ops = 0.0;
        return;
    }

    /* ops/sec の配列を作る（時間計測1回ごとの換算） */
    double *ops_array = (double*)malloc(count * sizeof(double));
    if (!ops_array) {
        fprintf(stderr, "Failed to allocate ops_array\n");
        *mean_ops = 0.0;
        *median_ops = 0.0;
        *variance_ops2 = 0.0;
        *stddev_ops = 0.0;
        *min_ops = 0.0;
        *max_ops = 0.0;
        return;
    }

    for (uint64_t i = 0; i < count; i++) {
        if (times[i] > 0) {
            ops_array[i] = 1e9 / (double)times[i];
        } else {
            ops_array[i] = 0.0;
        }
    }

    /* 中央値/min/max のためソート */
    qsort(ops_array, count, sizeof(double), compare_double);

    *min_ops = ops_array[0];
    *max_ops = ops_array[count - 1];

    /* 平均 */
    double sum = 0.0;
    for (uint64_t i = 0; i < count; i++) {
        sum += ops_array[i];
    }
    *mean_ops = sum / (double)count;

    /* 中央値 */
    if (count % 2 == 0) {
        *median_ops = (ops_array[count/2 - 1] + ops_array[count/2]) / 2.0;
    } else {
        *median_ops = ops_array[count/2];
    }

    /* 分散・標準偏差 */
    double sum_sq_diff = 0.0;
    for (uint64_t i = 0; i < count; i++) {
        double diff = ops_array[i] - *mean_ops;
        sum_sq_diff += diff * diff;
    }
    *variance_ops2 = sum_sq_diff / (double)count;
    *stddev_ops = sqrt(*variance_ops2);

    free(ops_array);
}

//RUN_FOR_SECONDS マクロ


#define RUN_FOR_SECONDS(kem_name, keySize, op_name, seconds, batch, op_stmt) do {     \
    uint64_t iters = 0;                                                                \
    const uint64_t t0 = mono_ns();                                                     \
    const uint64_t limit_ns = (uint64_t)((seconds) * 1e9);                             \
                                                                                        \
    /* timing 配列 */                                 \
    uint64_t capacity = 1000000;                                                       \
    uint64_t *op_times = (uint64_t*)malloc(capacity * sizeof(uint64_t));              \
    if (!op_times) {                                                                   \
        fprintf(stderr, "Failed to allocate timing array\n");                          \
        ret = -1;                                                                      \
        goto end;                                                                      \
    }                                                                                  \
    uint64_t time_count = 0;                                                           \
                                                                                        \
    /* 指定秒数に達するまで batch 回ずつ繰り返す */                                    \
    while (1) {                                                                        \
        for (int _i = 0; _i < (batch); _i++) {                                         \
            uint64_t op_start = mono_ns();                                             \
            op_stmt;                                                                   \
            uint64_t op_end = mono_ns();                                               \
            if (ret != 0) {                                                            \
                free(op_times);                                                        \
                goto end;                                                              \
            }                                                                          \
            /* 配列が足りなければ拡張 */                                               \
            if (time_count < capacity) {                                               \
                op_times[time_count++] = op_end - op_start;                            \
            } else {                                                                   \
                capacity *= 2;                                                         \
                uint64_t *new_times = (uint64_t*)realloc(op_times, capacity * sizeof(uint64_t)); \
                if (!new_times) {                                                      \
                    free(op_times);                                                    \
                    fprintf(stderr, "Failed to reallocate timing array\n");            \
                    ret = -1;                                                          \
                    goto end;                                                          \
                }                                                                      \
                op_times = new_times;                                                  \
                op_times[time_count++] = op_end - op_start;                            \
            }                                                                          \
            iters++;                                                                   \
        }                                                                              \
        if (mono_ns() - t0 >= limit_ns) break;                                         \
    }                                                                                  \
                                                                                        \
    /* 全体経過時間 dt（秒） */                                                        \
    const uint64_t dt_ns = mono_ns() - t0;                                             \
    const double dt = (double)dt_ns * 1e-9;                                            \
                                                                                        \
    /* 平均指標 */                                                       \
    const double ms_per_op = (iters == 0) ? 0.0 : (dt * 1e3) / (double)iters;          \
    const double ops_per_s = (dt == 0.0) ? 0.0 : (double)iters / dt;                   \
                                                                                        \
    /* 時間統計（ns -> ms 変換して出力） */                                            \
    double mean_ns, median_ns, variance_ns2, stddev_ns, min_ns, max_ns;                \
    compute_statistics(op_times, time_count, &mean_ns, &median_ns, &variance_ns2, &stddev_ns, &min_ns, &max_ns); \
                                                                                        \
    double mean_ms = mean_ns * 1e-6;                                                   \
    double median_ms = median_ns * 1e-6;                                               \
    double variance_ms2 = variance_ns2 * 1e-12;                                        \
    double stddev_ms = stddev_ns * 1e-6;                                               \
    double min_ms = min_ns * 1e-6;                                                     \
    double max_ms = max_ns * 1e-6;                                                     \
                                                                                        \
    /* ops/sec 統計 */                                  \
    double mean_ops, median_ops, variance_ops2, stddev_ops, min_ops, max_ops;          \
    compute_ops_statistics(op_times, time_count, &mean_ops, &median_ops, &variance_ops2, &stddev_ops, &min_ops, &max_ops); \
                                                                                        \
    printf("%-10s %4d  %-7s %10llu ops took %6.3f sec, avg %0.006f ms, %12.3f ops/sec\n", \
           (kem_name), (keySize), (op_name),                                           \
           (unsigned long long)iters, dt, ms_per_op, ops_per_s);                       \
                                                                                        \
    /* 時間統計 */                                                               \
    printf("  Time Statistics:\n");                                                    \
    printf("    mean=%0.006f ms, median=%0.006f ms, min=%0.006f ms, max=%0.006f ms\n", \
           mean_ms, median_ms, min_ms, max_ms);                                        \
    printf("    variance=%0.009f ms², stddev=%0.006f ms\n",                            \
           variance_ms2, stddev_ms);                                                   \
                                                                                        \
    /* ops/sec 統計 */                                                           \
    printf("  Ops/sec Statistics:\n");                                                 \
    printf("    mean=%0.3f ops/sec, median=%0.3f ops/sec, min=%0.3f ops/sec, max=%0.3f ops/sec\n", \
           mean_ops, median_ops, min_ops, max_ops);                                    \
    printf("    variance=%0.3f (ops/sec)², stddev=%0.3f ops/sec\n",                    \
           variance_ops2, stddev_ops);                                                 \
                                                                                        \
    free(op_times);                                                                    \
} while(0)


//メモリ消去・解放（秘密情報を残さない）
void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len);

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem);

/* ============================================================================
 *  liboqs のサンプル（stack版 / heap版）
 * ============================================================================ */

static OQS_STATUS example_stack(void) {
#ifndef OQS_ENABLE_KEM_ml_kem_768
    printf("[example_stack] OQS_KEM_ml_kem_768 was not enabled at compile-time.\n");
    return OQS_SUCCESS;
#else
    uint8_t public_key[OQS_KEM_ml_kem_768_length_public_key];
    uint8_t secret_key[OQS_KEM_ml_kem_768_length_secret_key];
    uint8_t ciphertext[OQS_KEM_ml_kem_768_length_ciphertext];
    uint8_t shared_secret_e[OQS_KEM_ml_kem_768_length_shared_secret];
    uint8_t shared_secret_d[OQS_KEM_ml_kem_768_length_shared_secret];

    OQS_STATUS rc = OQS_KEM_ml_kem_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_ml_kem_768_keypair failed!\n");
        cleanup_stack(secret_key, OQS_KEM_ml_kem_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_ml_kem_768_length_shared_secret);
        return OQS_ERROR;
    }
    rc = OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_ml_kem_768_encaps failed!\n");
        cleanup_stack(secret_key, OQS_KEM_ml_kem_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_ml_kem_768_length_shared_secret);
        return OQS_ERROR;
    }
    rc = OQS_KEM_ml_kem_768_decaps(shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_ml_kem_768_decaps failedS failed!\n");
        cleanup_stack(secret_key, OQS_KEM_ml_kem_768_length_secret_key,
                      shared_secret_e, shared_secret_d,
                      OQS_KEM_ml_kem_768_length_shared_secret);
        return OQS_ERROR;
    }
    printf("[example_stack] OQS_KEM_ml_kem_768 operations completed.\n");
    return OQS_SUCCESS;
#endif
}

static OQS_STATUS example_heap(void) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        printf("[example_heap]  OQS_KEM_ml_kem_768 was not enabled at compile-time.\n");
        return OQS_SUCCESS;
    }

    public_key = OQS_MEM_malloc(kem->length_public_key);
    secret_key = OQS_MEM_malloc(kem->length_secret_key);
    ciphertext = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);
    if (!public_key || !secret_key || !ciphertext || !shared_secret_e || !shared_secret_d) {
        fprintf(stderr, "ERROR: OQS_MEM_malloc failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_keypair failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }
    rc = OQS_KEM_encaps(kem, ciphertext, shared_secret_e, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    printf("[example_heap]  OQS_KEM_ml_kem_768 operations completed.\n");
    cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
    return OQS_SUCCESS;
}

/* ============================================================================
 *  wolfSSL native benchmark
 *  wolfSSLを実行できるかをテストする
 *  速度をテスト
 * ============================================================================ */

void mlkem_liboqs_wolfssl(int kem_level)
{
    int type;
    const char* name;
    int keySize;

    /* kem_level（512/768/1024）に応じて wolfSSL のタイプを選択 */
    switch (kem_level) {
#ifdef WOLFSSL_WC_ML_KEM_512
    case 512:
        type    = WC_ML_KEM_512;
        keySize = 128;
        name    = "ML-KEM 512";
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_768
    case 768:
        type    = WC_ML_KEM_768;
        keySize = 192;
        name    = "ML-KEM 768";
        break;
#endif
#ifdef WOLFSSL_WC_ML_KEM_1024
    case 1024:
        type    = WC_ML_KEM_1024;
        keySize = 256;
        name    = "ML-KEM 1024";
        break;
#endif
    default:
        fprintf(stderr,
            "[mlkem_liboqs_wolfssl] unsupported kem_level=%d (use 512/768/1024)\n",
            kem_level);
        return;
    }

    const double seconds = 10.0;
    const int batch = 64;

    printf("------------------------------------------------------------------------------\n");
    printf(" example_kem (wolfSSL-like output)\n");
    printf("------------------------------------------------------------------------------\n");
    printf("wolfCrypt Benchmark (min %.1f sec each)\n", seconds);

    KyberKey key1;
    KyberKey key2;
    WC_RNG   rng;
    int      ret = 0;

    /* 共有鍵や暗号文、公開鍵バッファ（最大サイズ） */
    byte   ct[WC_ML_KEM_MAX_CIPHER_TEXT_SIZE];
    byte   ss[WC_ML_KEM_SS_SZ];
    byte   pub[WC_ML_KEM_MAX_PUBLIC_KEY_SIZE];
    word32 pubLen = 0;
    word32 ctSz   = 0;

    memset(&key1, 0, sizeof(key1));
    memset(&key2, 0, sizeof(key2));

    /* RNG 初期化（wolfSSL の暗号処理に必要） */
    ret = wc_InitRng(&rng);
    if (ret != 0) {
        fprintf(stderr, "[mlkem_liboqs_wolfssl] wc_InitRng failed (ret=%d)\n", ret);
        return;
    }

    /* 1) KeyGen：毎回 Free->Init->MakeKey を行う（初期化含む） */
    RUN_FOR_SECONDS(name, keySize, "key gen", seconds, batch, ({
        wc_KyberKey_Free(&key1);
        ret = wc_KyberKey_Init(type, &key1, HEAP_HINT, INVALID_DEVID);
        if (ret == 0) ret = wc_KyberKey_MakeKey(&key1, &rng);
    }));

    /* 2) Encaps のために公開鍵を encode/decode（ここは計測外：準備処理） */
    ret = wc_KyberKey_PublicKeySize(&key1, &pubLen);
    if (ret != 0) goto end;

    ret = wc_KyberKey_EncodePublicKey(&key1, pub, pubLen);
    if (ret != 0) goto end;

    wc_KyberKey_Free(&key2);
    ret = wc_KyberKey_Init(type, &key2, HEAP_HINT, INVALID_DEVID);
    if (ret != 0) goto end;

    ret = wc_KyberKey_DecodePublicKey(&key2, pub, pubLen);
    if (ret != 0) goto end;

    ret = wc_KyberKey_CipherTextSize(&key2, &ctSz);
    if (ret != 0) goto end;

    /* 3) Encaps */
    RUN_FOR_SECONDS(name, keySize, "encap", seconds, batch, ({
        ret = wc_KyberKey_Encapsulate(&key2, ct, ss, &rng);
    }));

    /* 4) Decaps：先に1回 Encaps して ct を準備してから測る */
    ret = wc_KyberKey_Encapsulate(&key2, ct, ss, &rng);
    if (ret != 0) goto end;

    RUN_FOR_SECONDS(name, keySize, "decap", seconds, batch, ({
        ret = wc_KyberKey_Decapsulate(&key1, ss, ct, ctSz);
    }));

end:
    if (ret != 0) {
        fprintf(stderr, "[mlkem_liboqs_wolfssl] error ret=%d\n", ret);
    }
    wc_KyberKey_Free(&key1);
    wc_KyberKey_Free(&key2);
    wc_FreeRng(&rng);

    printf("Benchmark complete\n");
}

/* ============================================================================
 *  相互運用テスト（interop）
 *  - liboqs で作った鍵を wolfSSL 側アダプタで Enc/Dec できるか
 *  - wolfSSL で作った鍵を liboqs で Decaps できるか
 *
 * ※ここでは “秘密鍵/公開鍵/暗号文” のバイト列互換が正しいかの確認が主目的。
 * ============================================================================ */

static OQS_STATUS test_liboqs_key_with_wolfssl(int kem_level) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    const char *alg_name = NULL;
    OQS_STATUS rc = OQS_ERROR;
    int wret;

    switch (kem_level) {
    case 512:  alg_name = OQS_KEM_alg_ml_kem_512; break;
    case 768:  alg_name = OQS_KEM_alg_ml_kem_768; break;
    case 1024: alg_name = OQS_KEM_alg_ml_kem_1024; break;
    default:
        fprintf(stderr, "[interop] unsupported kem_level=%d (expected 512/768/1024)\n", kem_level);
        return OQS_ERROR;
    }

    kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        printf("[interop] %s was not enabled at compile-time. skip.\n", alg_name);
        return OQS_SUCCESS;
    }

    /* サイズは kem->length_* を使用 */
    public_key      = OQS_MEM_malloc(kem->length_public_key);
    secret_key      = OQS_MEM_malloc(kem->length_secret_key);
    ciphertext      = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret_e || !shared_secret_d) {
        fprintf(stderr, "[interop] malloc failed in test_liboqs_key_with_wolfssl\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    /* liboqs で鍵生成 */
    rc = OQS_KEM_keypair(kem, public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "[interop] OQS_KEM_keypair failed\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return rc;
    }

    /* wolfSSL アダプタで encaps/decaps */
    wret = oqs_wolf_mlkem_encaps(kem_level, ciphertext, shared_secret_e, public_key);
    if (wret != 0) {
        fprintf(stderr, "[interop] oqs_wolf_mlkem_encaps failed (ret=%d)\n", wret);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    wret = oqs_wolf_mlkem_decaps(kem_level, shared_secret_d, ciphertext, secret_key);
    if (wret != 0) {
        fprintf(stderr, "[interop] oqs_wolf_mlkem_decaps failed (ret=%d)\n", wret);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    /* 共有鍵が一致すれば OK */
    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) != 0) {
        fprintf(stderr, "[interop] mismatch: liboqs-key + wolfSSL Encaps/Decaps (ML-KEM-%d)\n", kem_level);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    printf("[interop] liboqs keypair + wolfSSL Encaps/Decaps (ML-KEM-%d) : OK\n", kem_level);

    cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
    return OQS_SUCCESS;
}

static OQS_STATUS test_wolfssl_key_with_liboqs(int kem_level) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    const char *alg_name = NULL;
    OQS_STATUS rc = OQS_ERROR;
    int wret;

    switch (kem_level) {
    case 512:  alg_name = OQS_KEM_alg_ml_kem_512; break;
    case 768:  alg_name = OQS_KEM_alg_ml_kem_768; break;
    case 1024: alg_name = OQS_KEM_alg_ml_kem_1024; break;
    default:
        fprintf(stderr, "[interop] unsupported kem_level=%d (expected 512/768/1024)\n", kem_level);
        return OQS_ERROR;
    }

    kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        printf("[interop] %s was not enabled at compile-time. skip.\n", alg_name);
        return OQS_SUCCESS;
    }

    public_key      = OQS_MEM_malloc(kem->length_public_key);
    secret_key      = OQS_MEM_malloc(kem->length_secret_key);
    ciphertext      = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret_e || !shared_secret_d) {
        fprintf(stderr, "[interop] malloc failed in test_wolfssl_key_with_liboqs\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    /* wolfSSL アダプタで鍵生成 */
    wret = oqs_wolf_mlkem_keypair(kem_level, public_key, secret_key);
    if (wret != 0) {
        fprintf(stderr, "[interop] oqs_wolf_mlkem_keypair failed (ret=%d)\n", wret);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    /* wolfSSL アダプタで encaps */
    wret = oqs_wolf_mlkem_encaps(kem_level, ciphertext, shared_secret_e, public_key);
    if (wret != 0) {
        fprintf(stderr, "[interop] oqs_wolf_mlkem_encaps failed (ret=%d)\n", wret);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    /* liboqs 側で decaps */
    rc = OQS_KEM_decaps(kem, shared_secret_d, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "[interop] OQS_KEM_decaps failed with wolfSSL ct/sk\n");
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return rc;
    }

    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) != 0) {
        fprintf(stderr, "[interop] mismatch: wolfSSL-key + wolfSSL Encaps / liboqs Decaps (ML-KEM-%d)\n", kem_level);
        cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
        return OQS_ERROR;
    }

    printf("[interop] wolfSSL keypair + wolfSSL Encaps / liboqs Decaps (ML-KEM-%d) : OK\n", kem_level);

    cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
    return OQS_SUCCESS;
}

/* ============================================================================
 *  adapter bench（あなたの主目的：アダプタ経由の性能測定）
 *  - oqs_wolf_mlkem_*（アダプタ関数）を使って
 *    keygen / encaps / decaps を wolfCrypt 風の形式で計測
 * ============================================================================ */

static OQS_STATUS liboqs_wolfssl_adapter(int kem_level) {
    OQS_KEM *kem = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret_e = NULL;
    uint8_t *shared_secret_d = NULL;

    const char *alg_name = NULL;
    const char *name = NULL;
    int keySize = 0;

    OQS_STATUS rc = OQS_ERROR;
    int ret = 0;

    /* 512/768/1024 を選択 */
    switch (kem_level) {
    case 512:
        alg_name = OQS_KEM_alg_ml_kem_512;
        name     = "ML-KEM 512";
        keySize  = 128;
        break;
    case 768:
        alg_name = OQS_KEM_alg_ml_kem_768;
        name     = "ML-KEM 768";
        keySize  = 192;
        break;
    case 1024:
        alg_name = OQS_KEM_alg_ml_kem_1024;
        name     = "ML-KEM 1024";
        keySize  = 256;
        break;
    default:
        fprintf(stderr, "[adapter_bench] unsupported kem_level=%d (expected 512/768/1024)\n", kem_level);
        return OQS_ERROR;
    }

    const double seconds = 10.0;
    const int batch = 64;

    printf("------------------------------------------------------------------------------\n");
    printf(" adapter_bench (wolfSSL-like output)\n");
    printf("------------------------------------------------------------------------------\n");
    printf("Benchmark (min %.1f sec each)\n", seconds);

    kem = OQS_KEM_new(alg_name);
    if (kem == NULL) {
        printf("[adapter_bench] %s was not enabled at compile-time. skip.\n", alg_name);
        return OQS_SUCCESS;
    }

    /* liboqs のサイズに合わせて確保 */
    public_key      = OQS_MEM_malloc(kem->length_public_key);
    secret_key      = OQS_MEM_malloc(kem->length_secret_key);
    ciphertext      = OQS_MEM_malloc(kem->length_ciphertext);
    shared_secret_e = OQS_MEM_malloc(kem->length_shared_secret);
    shared_secret_d = OQS_MEM_malloc(kem->length_shared_secret);

    if (!public_key || !secret_key || !ciphertext || !shared_secret_e || !shared_secret_d) {
        fprintf(stderr, "[adapter_bench] malloc failed\n");
        rc = OQS_ERROR;
        goto cleanup;
    }

    /* KeyGen（アダプタ経由：wolfSSLで生成し、liboqs形式のバイト列で返す想定） */
    RUN_FOR_SECONDS(name, keySize, "key gen", seconds, batch, ({
        ret = oqs_wolf_mlkem_keypair(kem_level, public_key, secret_key);
    }));

    /* Encaps（アダプタ経由） */
    RUN_FOR_SECONDS(name, keySize, "encap", seconds, batch, ({
        ret = oqs_wolf_mlkem_encaps(kem_level, ciphertext, shared_secret_e, public_key);
    }));

    /* Decaps（アダプタ経由） */
    RUN_FOR_SECONDS(name, keySize, "decap", seconds, batch, ({
        ret = oqs_wolf_mlkem_decaps(kem_level, shared_secret_d, ciphertext, secret_key);
    }));

    /* 共有鍵を確認 */
    if (memcmp(shared_secret_e, shared_secret_d, kem->length_shared_secret) != 0) {
        fprintf(stderr, "[adapter_bench] mismatch\n");
        rc = OQS_ERROR;
        goto cleanup;
    }

    printf("[adapter_bench] wolfSSL adapter self-test OK (ML-KEM-%d)\n", kem_level);
    rc = OQS_SUCCESS;
    goto cleanup;

end:
    fprintf(stderr, "[adapter_bench] error ret=%d\n", ret);
    rc = OQS_ERROR;

cleanup:
    cleanup_heap(secret_key, shared_secret_e, shared_secret_d, public_key, ciphertext, kem);
    return rc;
}

/* ============================================================================
 *  main
 * ============================================================================ */

int main(void) {
    OQS_init();

//    OQS_init();
//        if (example_stack() == OQS_SUCCESS && example_heap() == OQS_SUCCESS) {
//            OQS_destroy();
//            return EXIT_SUCCESS;
//        } else {
//            OQS_destroy();
//            return EXIT_FAILURE;
//        }
    
    // mlkem_liboqs_wolfssl(768);

//     アダプタ経由ベンチ
    (void)liboqs_wolfssl_adapter(512);
    (void)liboqs_wolfssl_adapter(768);
    (void)liboqs_wolfssl_adapter(1024);

    OQS_destroy();
    return 0;
}

/* ============================================================================
 *  - 秘密鍵や共有鍵はゼロ化してから解放（情報漏えいを防ぐ）
 * ============================================================================ */

void cleanup_stack(uint8_t *secret_key, size_t secret_key_len,
                   uint8_t *shared_secret_e, uint8_t *shared_secret_d,
                   size_t shared_secret_len) {
    OQS_MEM_cleanse(secret_key, secret_key_len);
    OQS_MEM_cleanse(shared_secret_e, shared_secret_len);
    OQS_MEM_cleanse(shared_secret_d, shared_secret_len);
}

void cleanup_heap(uint8_t *secret_key, uint8_t *shared_secret_e,
                  uint8_t *shared_secret_d, uint8_t *public_key,
                  uint8_t *ciphertext, OQS_KEM *kem) {
    if (kem != NULL) {
        OQS_MEM_secure_free(secret_key, kem->length_secret_key);
        OQS_MEM_secure_free(shared_secret_e, kem->length_shared_secret);
        OQS_MEM_secure_free(shared_secret_d, kem->length_shared_secret);
    }
    OQS_MEM_insecure_free(public_key);
    OQS_MEM_insecure_free(ciphertext);
    OQS_KEM_free(kem);
}
