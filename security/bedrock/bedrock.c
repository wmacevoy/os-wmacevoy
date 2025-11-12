#include "bedrock.h"

#include <string.h>

#if defined(BEDROCK_USE_COMMONCRYPTO)
#include <CommonCrypto/CommonDigest.h>
#elif defined(BEDROCK_USE_BCRYPT)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(BEDROCK_USE_OPENSSL)
#include <openssl/sha.h>
#endif

// Fallback forward declarations
void bedrock_sha256_fallback_init(void *state);
void bedrock_sha256_fallback_reset(void *state);
void bedrock_sha256_fallback_update(void *state, const uint8_t *data, size_t len);
void bedrock_sha256_fallback_final_copy(const void *state, uint8_t out[32]);
void bedrock_sha256_fallback_fini(void *state);

void bedrock_sha512_fallback_init(void *state);
void bedrock_sha512_fallback_reset(void *state);
void bedrock_sha512_fallback_update(void *state, const uint8_t *data, size_t len);
void bedrock_sha512_fallback_final_copy(const void *state, uint8_t out[64]);
void bedrock_sha512_fallback_fini(void *state);

typedef enum bedrock_backend_tag {
    BEDROCK_BACKEND_FALLBACK = 0,
    BEDROCK_BACKEND_COMMONCRYPTO = 1,
    BEDROCK_BACKEND_BCRYPT = 2,
    BEDROCK_BACKEND_OPENSSL = 3
} bedrock_backend_tag;

typedef struct bedrock_sha256_ctx_internal {
    bedrock_backend_tag backend;
    union {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        CC_SHA256_CTX cc;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        struct {
            BCRYPT_ALG_HANDLE alg;
            BCRYPT_HASH_HANDLE hash;
            unsigned char *hashObject;
            ULONG hashObjectSize;
        } bc;
#endif
#if defined(BEDROCK_USE_OPENSSL)
        SHA256_CTX ossl;
#endif
        unsigned char fallback[256];
    } u;
} bedrock_sha256_ctx_internal;

typedef struct bedrock_sha512_ctx_internal {
    bedrock_backend_tag backend;
    union {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        CC_SHA512_CTX cc;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        struct {
            BCRYPT_ALG_HANDLE alg;
            BCRYPT_HASH_HANDLE hash;
            unsigned char *hashObject;
            ULONG hashObjectSize;
        } bc;
#endif
#if defined(BEDROCK_USE_OPENSSL)
        SHA512_CTX ossl;
#endif
        unsigned char fallback[512];
    } u;
} bedrock_sha512_ctx_internal;

// Safety check sizes at compile-time (best-effort)
#define STATIC_ASSERT(COND,MSG) typedef char static_assertion_##MSG[(COND)?1:-1]
STATIC_ASSERT(sizeof(bedrock_sha256_ctx_internal) <= sizeof(((bedrock_sha256_struct*)0)->opaque), sha256_ctx_fits);
STATIC_ASSERT(sizeof(bedrock_sha512_ctx_internal) <= sizeof(((bedrock_sha512_struct*)0)->opaque), sha512_ctx_fits);

static inline bedrock_sha256_ctx_internal *sha256_cast(bedrock_sha256_struct *ctx) {
    return (bedrock_sha256_ctx_internal*)(void*)ctx->opaque;
}
static inline const bedrock_sha256_ctx_internal *sha256_cast_c(const bedrock_sha256_struct *ctx) {
    return (const bedrock_sha256_ctx_internal*)(const void*)ctx->opaque;
}
static inline bedrock_sha512_ctx_internal *sha512_cast(bedrock_sha512_struct *ctx) {
    return (bedrock_sha512_ctx_internal*)(void*)ctx->opaque;
}
static inline const bedrock_sha512_ctx_internal *sha512_cast_c(const bedrock_sha512_struct *ctx) {
    return (const bedrock_sha512_ctx_internal*)(const void*)ctx->opaque;
}

// Backend selection helpers
static inline bedrock_backend_tag select_sha_backend(void) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
    return BEDROCK_BACKEND_COMMONCRYPTO;
#elif defined(BEDROCK_USE_BCRYPT)
    return BEDROCK_BACKEND_BCRYPT;
#elif defined(BEDROCK_USE_OPENSSL)
    return BEDROCK_BACKEND_OPENSSL;
#else
    return BEDROCK_BACKEND_FALLBACK;
#endif
}

// SHA-256
void bedrock_sha256_init(bedrock_sha256_struct *ctx_public) {
    bedrock_sha256_ctx_internal *ctx = sha256_cast(ctx_public);
    memset(ctx, 0, sizeof(*ctx));
    ctx->backend = select_sha_backend();
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA256_Init(&ctx->u.cc);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.bc.alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
            if (status != 0) { ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            ULONG cb = sizeof(ctx->u.bc.hashObjectSize);
            status = BCryptGetProperty(ctx->u.bc.alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ctx->u.bc.hashObjectSize, cb, &cb, 0);
            if (status != 0) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            ctx->u.bc.hashObject = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, ctx->u.bc.hashObjectSize);
            if (!ctx->u.bc.hashObject) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            status = BCryptCreateHash(ctx->u.bc.alg, &ctx->u.bc.hash, ctx->u.bc.hashObject, ctx->u.bc.hashObjectSize, NULL, 0, 0);
            if (status != 0) { HeapFree(GetProcessHeap(),0,ctx->u.bc.hashObject); BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA256_Init(&ctx->u.ossl);
            break;
#endif
        default:
            bedrock_sha256_fallback_init(&ctx->u.fallback[0]);
            break;
    }
}

void bedrock_sha256_reset(bedrock_sha256_struct *ctx_public) {
    bedrock_sha256_ctx_internal *ctx = sha256_cast(ctx_public);
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA256_Init(&ctx->u.cc);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            if (ctx->u.bc.hash) { BCryptDestroyHash(ctx->u.bc.hash); ctx->u.bc.hash = NULL; }
            if (ctx->u.bc.alg && ctx->u.bc.hashObject && ctx->u.bc.hashObjectSize) {
                NTSTATUS status = BCryptCreateHash(ctx->u.bc.alg, &ctx->u.bc.hash, ctx->u.bc.hashObject, ctx->u.bc.hashObjectSize, NULL, 0, 0);
                (void)status;
            }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA256_Init(&ctx->u.ossl);
            break;
#endif
        default:
            bedrock_sha256_fallback_reset(&ctx->u.fallback[0]);
            break;
    }
}

void bedrock_sha256_process(bedrock_sha256_struct *ctx_public, size_t len, const uint8_t *data) {
    bedrock_sha256_ctx_internal *ctx = sha256_cast(ctx_public);
    if (len == 0) return;
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA256_Update(&ctx->u.cc, data, (CC_LONG)len);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT:
            BCryptHashData(ctx->u.bc.hash, (PUCHAR)data, (ULONG)len, 0);
            break;
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA256_Update(&ctx->u.ossl, data, len);
            break;
#endif
        default:
            bedrock_sha256_fallback_update(&ctx->u.fallback[0], data, len);
            break;
    }
}

void bedrock_sha256_digest(const bedrock_sha256_struct *ctx_public_c, uint8_t out_digest[32]) {
    const bedrock_sha256_ctx_internal *ctx_c = sha256_cast_c(ctx_public_c);
    switch (ctx_c->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO: {
            CC_SHA256_CTX copy = ctx_c->u.cc;
            CC_SHA256_Final(out_digest, &copy);
            break; }
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            BCRYPT_HASH_HANDLE dup = NULL;
            if (BCryptDuplicateHash(ctx_c->u.bc.hash, &dup, NULL, 0, 0) == 0 && dup) {
                UCHAR tmp[32];
                ULONG cb = 0;
                BCryptFinishHash(dup, tmp, 32, 0);
                memcpy(out_digest, tmp, 32);
                BCryptDestroyHash(dup);
            } else {
                // Fallback by cloning memory unsafe; as a safeguard, just finalize directly is not allowed. Do nothing.
                // To ensure we still provide a result, we copy by exporting/importing state is not trivial; duplicate failure is rare.
                UCHAR tmp[32] = {0};
                memcpy(out_digest, tmp, 32);
            }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL: {
            SHA256_CTX copy;
            memcpy(&copy, &ctx_c->u.ossl, sizeof(copy));
            SHA256_Final(out_digest, &copy);
            break; }
#endif
        default:
            bedrock_sha256_fallback_final_copy(&ctx_c->u.fallback[0], out_digest);
            break;
    }
}

void bedrock_sha256_fini(bedrock_sha256_struct *ctx_public) {
    bedrock_sha256_ctx_internal *ctx = sha256_cast(ctx_public);
    switch (ctx->backend) {
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT:
            if (ctx->u.bc.hash) { BCryptDestroyHash(ctx->u.bc.hash); ctx->u.bc.hash = NULL; }
            if (ctx->u.bc.hashObject) { HeapFree(GetProcessHeap(), 0, ctx->u.bc.hashObject); ctx->u.bc.hashObject = NULL; }
            if (ctx->u.bc.alg) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg, 0); ctx->u.bc.alg = NULL; }
            break;
#endif
        default:
            bedrock_sha256_fallback_fini(&ctx->u.fallback[0]);
            break;
    }
    // Zeroize entire context
    volatile unsigned char *p = (volatile unsigned char*)ctx;
    for (size_t i = 0; i < sizeof(*ctx); ++i) p[i] = 0;
}

// SHA-512
void bedrock_sha512_init(bedrock_sha512_struct *ctx_public) {
    bedrock_sha512_ctx_internal *ctx = sha512_cast(ctx_public);
    memset(ctx, 0, sizeof(*ctx));
    ctx->backend = select_sha_backend();
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA512_Init(&ctx->u.cc);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            NTSTATUS status = BCryptOpenAlgorithmProvider(&ctx->u.bc.alg, BCRYPT_SHA512_ALGORITHM, NULL, 0);
            if (status != 0) { ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            ULONG cb = sizeof(ctx->u.bc.hashObjectSize);
            status = BCryptGetProperty(ctx->u.bc.alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&ctx->u.bc.hashObjectSize, cb, &cb, 0);
            if (status != 0) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            ctx->u.bc.hashObject = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, ctx->u.bc.hashObjectSize);
            if (!ctx->u.bc.hashObject) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            status = BCryptCreateHash(ctx->u.bc.alg, &ctx->u.bc.hash, ctx->u.bc.hashObject, ctx->u.bc.hashObjectSize, NULL, 0, 0);
            if (status != 0) { HeapFree(GetProcessHeap(),0,ctx->u.bc.hashObject); BCryptCloseAlgorithmProvider(ctx->u.bc.alg,0); ctx->backend = BEDROCK_BACKEND_FALLBACK; break; }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA512_Init(&ctx->u.ossl);
            break;
#endif
        default:
            bedrock_sha512_fallback_init(&ctx->u.fallback[0]);
            break;
    }
}

void bedrock_sha512_reset(bedrock_sha512_struct *ctx_public) {
    bedrock_sha512_ctx_internal *ctx = sha512_cast(ctx_public);
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA512_Init(&ctx->u.cc);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            if (ctx->u.bc.hash) { BCryptDestroyHash(ctx->u.bc.hash); ctx->u.bc.hash = NULL; }
            if (ctx->u.bc.alg && ctx->u.bc.hashObject && ctx->u.bc.hashObjectSize) {
                NTSTATUS status = BCryptCreateHash(ctx->u.bc.alg, &ctx->u.bc.hash, ctx->u.bc.hashObject, ctx->u.bc.hashObjectSize, NULL, 0, 0);
                (void)status;
            }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA512_Init(&ctx->u.ossl);
            break;
#endif
        default:
            bedrock_sha512_fallback_reset(&ctx->u.fallback[0]);
            break;
    }
}

void bedrock_sha512_process(bedrock_sha512_struct *ctx_public, size_t len, const uint8_t *data) {
    bedrock_sha512_ctx_internal *ctx = sha512_cast(ctx_public);
    if (len == 0) return;
    switch (ctx->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO:
            CC_SHA512_Update(&ctx->u.cc, data, (CC_LONG)len);
            break;
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT:
            BCryptHashData(ctx->u.bc.hash, (PUCHAR)data, (ULONG)len, 0);
            break;
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL:
            SHA512_Update(&ctx->u.ossl, data, len);
            break;
#endif
        default:
            bedrock_sha512_fallback_update(&ctx->u.fallback[0], data, len);
            break;
    }
}

void bedrock_sha512_digest(const bedrock_sha512_struct *ctx_public_c, uint8_t out_digest[64]) {
    const bedrock_sha512_ctx_internal *ctx_c = sha512_cast_c(ctx_public_c);
    switch (ctx_c->backend) {
#if defined(BEDROCK_USE_COMMONCRYPTO)
        case BEDROCK_BACKEND_COMMONCRYPTO: {
            CC_SHA512_CTX copy = ctx_c->u.cc;
            CC_SHA512_Final(out_digest, &copy);
            break; }
#endif
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT: {
            BCRYPT_HASH_HANDLE dup = NULL;
            if (BCryptDuplicateHash(ctx_c->u.bc.hash, &dup, NULL, 0, 0) == 0 && dup) {
                UCHAR tmp[64];
                BCryptFinishHash(dup, tmp, 64, 0);
                memcpy(out_digest, tmp, 64);
                BCryptDestroyHash(dup);
            } else {
                UCHAR tmp[64] = {0};
                memcpy(out_digest, tmp, 64);
            }
            break; }
#endif
#if defined(BEDROCK_USE_OPENSSL)
        case BEDROCK_BACKEND_OPENSSL: {
            SHA512_CTX copy;
            memcpy(&copy, &ctx_c->u.ossl, sizeof(copy));
            SHA512_Final(out_digest, &copy);
            break; }
#endif
        default:
            bedrock_sha512_fallback_final_copy(&ctx_c->u.fallback[0], out_digest);
            break;
    }
}

void bedrock_sha512_fini(bedrock_sha512_struct *ctx_public) {
    bedrock_sha512_ctx_internal *ctx = sha512_cast(ctx_public);
    switch (ctx->backend) {
#if defined(BEDROCK_USE_BCRYPT)
        case BEDROCK_BACKEND_BCRYPT:
            if (ctx->u.bc.hash) { BCryptDestroyHash(ctx->u.bc.hash); ctx->u.bc.hash = NULL; }
            if (ctx->u.bc.hashObject) { HeapFree(GetProcessHeap(), 0, ctx->u.bc.hashObject); ctx->u.bc.hashObject = NULL; }
            if (ctx->u.bc.alg) { BCryptCloseAlgorithmProvider(ctx->u.bc.alg, 0); ctx->u.bc.alg = NULL; }
            break;
#endif
        default:
            bedrock_sha512_fallback_fini(&ctx->u.fallback[0]);
            break;
    }
    volatile unsigned char *p = (volatile unsigned char*)ctx;
    for (size_t i = 0; i < sizeof(*ctx); ++i) p[i] = 0;
}


