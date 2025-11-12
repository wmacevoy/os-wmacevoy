#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

static void gen_pattern256(const uint8_t *seed, size_t seed_len, const size_t *chunks, size_t num_chunks, uint8_t *out, size_t out_len) {
    bedrock_prng256_struct p;
    bedrock_prng256_init(&p, seed, seed_len);
    uint8_t *dst = out;
    size_t remaining = out_len;
    for (size_t i = 0; i < num_chunks && remaining > 0; ++i) {
        size_t take = chunks[i] < remaining ? chunks[i] : remaining;
        bedrock_prng256_bytes(&p, dst, take);
        dst += take;
        remaining -= take;
    }
    if (remaining) {
        bedrock_prng256_bytes(&p, dst, remaining);
    }
    bedrock_prng256_fini(&p);
}

static void gen_pattern512(const uint8_t *seed, size_t seed_len, const size_t *chunks, size_t num_chunks, uint8_t *out, size_t out_len) {
    bedrock_prng512_struct p;
    bedrock_prng512_init(&p, seed, seed_len);
    uint8_t *dst = out;
    size_t remaining = out_len;
    for (size_t i = 0; i < num_chunks && remaining > 0; ++i) {
        size_t take = chunks[i] < remaining ? chunks[i] : remaining;
        bedrock_prng512_bytes(&p, dst, take);
        dst += take;
        remaining -= take;
    }
    if (remaining) {
        bedrock_prng512_bytes(&p, dst, remaining);
    }
    bedrock_prng512_fini(&p);
}

int main(void) {
    const uint8_t seed[] = { 's','e','e','d' };
    uint8_t a[64], b[64];
    size_t c1[] = {1,10,8,3,9,7,26};
    size_t c2[] = {3,9,7,1,10,8,26};

    memset(a, 0, sizeof(a));
    memset(b, 0, sizeof(b));
    gen_pattern256(seed, sizeof(seed), c1, sizeof(c1)/sizeof(c1[0]), a, sizeof(a));
    gen_pattern256(seed, sizeof(seed), c2, sizeof(c2)/sizeof(c2[0]), b, sizeof(b));
    if (memcmp(a, b, sizeof(a)) != 0) {
        fprintf(stderr, "PRNG256 chunking invariance FAILED\n");
        return 1;
    }

    gen_pattern512(seed, sizeof(seed), c1, sizeof(c1)/sizeof(c1[0]), a, sizeof(a));
    gen_pattern512(seed, sizeof(seed), c2, sizeof(c2)/sizeof(c2[0]), b, sizeof(b));
    if (memcmp(a, b, sizeof(a)) != 0) {
        fprintf(stderr, "PRNG512 chunking invariance FAILED\n");
        return 1;
    }

    printf("PRNG tests passed\n");
    return 0;
}


