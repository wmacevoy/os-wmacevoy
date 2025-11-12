#include "bedrock.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#if defined(_WIN32) || defined(WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
#include <stdlib.h>
#elif defined(BEDROCK_USE_OPENSSL)
#include <openssl/rand.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#endif

static void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) { *p++ = 0; }
}

static int get_crypto_random(uint8_t *out, size_t len) {
#if defined(_WIN32) || defined(WIN32)
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return st == 0 ? 0 : -1;
#elif defined(__APPLE__)
    arc4random_buf(out, len);
    return 0;
#elif defined(BEDROCK_USE_OPENSSL)
    return RAND_bytes(out, (int)len) == 1 ? 0 : -1;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

typedef struct prng256_internal {
    bedrock_sha256_struct base_ctx;  // base context after seeding
    uint64_t counter;                // block counter
    uint8_t buffer[32];              // digest buffer
    uint32_t buf_index;              // next unread byte index in buffer (32 == empty)
} prng256_internal;

typedef struct prng512_internal {
    bedrock_sha512_struct base_ctx;  // base context after seeding
    uint64_t counter;                // block counter
    uint8_t buffer[64];              // digest buffer
    uint32_t buf_index;              // next unread byte index in buffer (64 == empty)
} prng512_internal;

#define STATIC_ASSERT(COND,MSG) typedef char static_assertion_##MSG[(COND)?1:-1]
STATIC_ASSERT(sizeof(prng256_internal) <= sizeof(((bedrock_prng256_struct*)0)->opaque), prng256_fits);
STATIC_ASSERT(sizeof(prng512_internal) <= sizeof(((bedrock_prng512_struct*)0)->opaque), prng512_fits);

static inline prng256_internal *prng256_cast(bedrock_prng256_struct *p) {
    return (prng256_internal*)(void*)p->opaque;
}
static inline prng512_internal *prng512_cast(bedrock_prng512_struct *p) {
    return (prng512_internal*)(void*)p->opaque;
}

static void encode_counter_le_8bytes(uint8_t out8[8], uint64_t counter) {
    // 8-byte little-endian representation of the integer
    for (int i = 0; i < 8; ++i) {
        out8[i] = (uint8_t)(counter >> (8 * i));
    }
}

void bedrock_prng256_init(bedrock_prng256_struct *prng, const uint8_t *seed, size_t seed_len) {
    prng256_internal *s = prng256_cast(prng);
    memset(s, 0, sizeof(*s));
    bedrock_sha256_init(&s->base_ctx);
    uint8_t seedbuf[32];
    const uint8_t *use_seed = seed;
    size_t use_len = seed_len;
    if (use_seed == NULL) {
        if (get_crypto_random(seedbuf, sizeof(seedbuf)) != 0) {
            // As a last resort (should not happen), fallback to a counter-based seed
            for (size_t i = 0; i < sizeof(seedbuf); ++i) seedbuf[i] = (uint8_t)i;
        }
        use_seed = seedbuf; use_len = sizeof(seedbuf);
    }
    // Hash the seed into the base context; subsequent blocks append counter block and digest
    bedrock_sha256_process(&s->base_ctx, use_len, use_seed);
    secure_bzero(seedbuf, sizeof(seedbuf));
    s->counter = 0;
    s->buf_index = 32; // buffer empty
}

void bedrock_prng256_bytes(bedrock_prng256_struct *prng, uint8_t *data, size_t data_len) {
    if (data_len == 0) return;
    prng256_internal *s = prng256_cast(prng);
    uint8_t ctr8[8];
    while (data_len) {
        if (s->buf_index >= 32) {
            bedrock_sha256_struct tmp;
            memcpy(&tmp, &s->base_ctx, sizeof(tmp));
            encode_counter_le_8bytes(ctr8, s->counter);
            s->counter += 1;
            bedrock_sha256_process(&tmp, sizeof(ctr8), ctr8);
            bedrock_sha256_digest(&tmp, s->buffer);
            secure_bzero(&tmp, sizeof(tmp));
            s->buf_index = 0;
        }
        size_t avail = 32u - s->buf_index;
        size_t take = data_len < avail ? data_len : avail;
        memcpy(data, s->buffer + s->buf_index, take);
        s->buf_index += (uint32_t)take;
        data += take;
        data_len -= take;
    }
    secure_bzero(ctr8, sizeof(ctr8));
}

void bedrock_prng256_fini(bedrock_prng256_struct *prng) {
    prng256_internal *s = prng256_cast(prng);
    bedrock_sha256_fini(&s->base_ctx);
    secure_bzero(s->buffer, sizeof(s->buffer));
    secure_bzero(s, sizeof(*s));
}

void bedrock_prng512_init(bedrock_prng512_struct *prng, const uint8_t *seed, size_t seed_len) {
    prng512_internal *s = prng512_cast(prng);
    memset(s, 0, sizeof(*s));
    bedrock_sha512_init(&s->base_ctx);
    uint8_t seedbuf[64];
    const uint8_t *use_seed = seed;
    size_t use_len = seed_len;
    if (use_seed == NULL) {
        if (get_crypto_random(seedbuf, sizeof(seedbuf)) != 0) {
            for (size_t i = 0; i < sizeof(seedbuf); ++i) seedbuf[i] = (uint8_t)i;
        }
        use_seed = seedbuf; use_len = sizeof(seedbuf);
    }
    bedrock_sha512_process(&s->base_ctx, use_len, use_seed);
    secure_bzero(seedbuf, sizeof(seedbuf));
    s->counter = 0;
    s->buf_index = 64; // buffer empty
}

void bedrock_prng512_bytes(bedrock_prng512_struct *prng, uint8_t *data, size_t data_len) {
    if (data_len == 0) return;
    prng512_internal *s = prng512_cast(prng);
    uint8_t ctr8[8];
    while (data_len) {
        if (s->buf_index >= 64) {
            bedrock_sha512_struct tmp;
            memcpy(&tmp, &s->base_ctx, sizeof(tmp));
            encode_counter_le_8bytes(ctr8, s->counter);
            s->counter += 1;
            bedrock_sha512_process(&tmp, sizeof(ctr8), ctr8);
            bedrock_sha512_digest(&tmp, s->buffer);
            secure_bzero(&tmp, sizeof(tmp));
            s->buf_index = 0;
        }
        size_t avail = 64u - s->buf_index;
        size_t take = data_len < avail ? data_len : avail;
        memcpy(data, s->buffer + s->buf_index, take);
        s->buf_index += (uint32_t)take;
        data += take;
        data_len -= take;
    }
    secure_bzero(ctr8, sizeof(ctr8));
}

void bedrock_prng512_fini(bedrock_prng512_struct *prng) {
    prng512_internal *s = prng512_cast(prng);
    bedrock_sha512_fini(&s->base_ctx);
    secure_bzero(s->buffer, sizeof(s->buffer));
    secure_bzero(s, sizeof(*s));
}


