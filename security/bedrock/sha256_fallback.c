#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct sha256_fb_state {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t buffer[64];
    uint32_t buffer_len;
} sha256_fb_state;

static void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) { *p++ = 0; }
}

#define ROR32(x,n) ((uint32_t)((x >> n) | (x << (32 - n))))
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)   (ROR32(x,2) ^ ROR32(x,13) ^ ROR32(x,22))
#define BSIG1(x)   (ROR32(x,6) ^ ROR32(x,11) ^ ROR32(x,25))
#define SSIG0(x)   (ROR32(x,7) ^ ROR32(x,18) ^ (x >> 3))
#define SSIG1(x)   (ROR32(x,17) ^ ROR32(x,19) ^ (x >> 10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_fb_transform(sha256_fb_state *s, const uint8_t block[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }

    uint32_t a = s->state[0];
    uint32_t b = s->state[1];
    uint32_t c = s->state[2];
    uint32_t d = s->state[3];
    uint32_t e = s->state[4];
    uint32_t f = s->state[5];
    uint32_t g = s->state[6];
    uint32_t h = s->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h + BSIG1(e) + CH(e,f,g) + K[i] + w[i];
        uint32_t t2 = BSIG0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s->state[0] += a;
    s->state[1] += b;
    s->state[2] += c;
    s->state[3] += d;
    s->state[4] += e;
    s->state[5] += f;
    s->state[6] += g;
    s->state[7] += h;

    // Clear sensitive temporaries
    secure_bzero(w, sizeof(w));
    {
        volatile uint32_t *z;
        z = &a; *z = 0;
        z = &b; *z = 0;
        z = &c; *z = 0;
        z = &d; *z = 0;
        z = &e; *z = 0;
        z = &f; *z = 0;
        z = &g; *z = 0;
        z = &h; *z = 0;
    }
}

static void sha256_fb_init_state(sha256_fb_state *s) {
    s->state[0] = 0x6a09e667;
    s->state[1] = 0xbb67ae85;
    s->state[2] = 0x3c6ef372;
    s->state[3] = 0xa54ff53a;
    s->state[4] = 0x510e527f;
    s->state[5] = 0x9b05688c;
    s->state[6] = 0x1f83d9ab;
    s->state[7] = 0x5be0cd19;
    s->bitlen = 0;
    s->buffer_len = 0;
}

void bedrock_sha256_fallback_init(void *state) {
    sha256_fb_state *s = (sha256_fb_state*)state;
    sha256_fb_init_state(s);
}

void bedrock_sha256_fallback_reset(void *state) {
    sha256_fb_state *s = (sha256_fb_state*)state;
    sha256_fb_init_state(s);
}

void bedrock_sha256_fallback_update(void *state, const uint8_t *data, size_t len) {
    sha256_fb_state *s = (sha256_fb_state*)state;
    if (len == 0) return;
    s->bitlen += (uint64_t)len * 8u;
    size_t off = 0;
    if (s->buffer_len) {
        size_t need = 64 - s->buffer_len;
        if (need > len) need = len;
        memcpy(&s->buffer[s->buffer_len], &data[off], need);
        s->buffer_len += (uint32_t)need;
        off += need;
        if (s->buffer_len == 64) {
            sha256_fb_transform(s, s->buffer);
            s->buffer_len = 0;
        }
    }
    while (off + 64 <= len) {
        sha256_fb_transform(s, &data[off]);
        off += 64;
    }
    if (off < len) {
        size_t rem = len - off;
        memcpy(s->buffer, &data[off], rem);
        s->buffer_len = (uint32_t)rem;
    }
}

static void sha256_fb_final(sha256_fb_state *s, uint8_t out[32]) {
    uint8_t block[64];
    uint8_t block2[64];
    size_t used = s->buffer_len;
    uint64_t bitlen = s->bitlen; // preserve original bit length

    // Copy current buffer
    memcpy(block, s->buffer, used);
    // Append 0x80
    block[used++] = 0x80;

    if (used > 56) {
        // Fill the rest with zeros and transform
        memset(block + used, 0, 64 - used);
        sha256_fb_transform(s, block);
        // Next block: all zeros except length at end
        memset(block2, 0, 64);
        for (int i = 0; i < 8; ++i) block2[56 + 7 - i] = (uint8_t)(bitlen >> (i*8));
        sha256_fb_transform(s, block2);
    } else {
        // Fill zeros up to 56
        memset(block + used, 0, 56 - used);
        // Append length big-endian
        for (int i = 0; i < 8; ++i) block[56 + 7 - i] = (uint8_t)(bitlen >> (i*8));
        sha256_fb_transform(s, block);
    }

    for (int i = 0; i < 8; ++i) {
        out[i*4+0] = (uint8_t)(s->state[i] >> 24);
        out[i*4+1] = (uint8_t)(s->state[i] >> 16);
        out[i*4+2] = (uint8_t)(s->state[i] >> 8);
        out[i*4+3] = (uint8_t)(s->state[i]);
    }

    // Clear local buffers
    secure_bzero(block, sizeof(block));
    secure_bzero(block2, sizeof(block2));
}

void bedrock_sha256_fallback_final_copy(const void *state, uint8_t out[32]) {
    sha256_fb_state tmp;
    memcpy(&tmp, state, sizeof(tmp));
    sha256_fb_final(&tmp, out);
    secure_bzero(&tmp, sizeof(tmp));
}

void bedrock_sha256_fallback_fini(void *state) {
    volatile uint8_t *p = (volatile uint8_t*)state;
    for (size_t i = 0; i < sizeof(sha256_fb_state); ++i) p[i] = 0;
}


