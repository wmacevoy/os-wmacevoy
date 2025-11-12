#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct sha512_fb_state {
    uint64_t state[8];
    uint64_t bitlen_low;   // low 64 bits of bit length
    uint64_t bitlen_high;  // high 64 bits of bit length
    uint8_t buffer[128];
    uint32_t buffer_len;
} sha512_fb_state;

static void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) { *p++ = 0; }
}

#define ROR64(x,n) ((uint64_t)((x >> n) | (x << (64 - n))))
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define BSIG0(x)   (ROR64(x,28) ^ ROR64(x,34) ^ ROR64(x,39))
#define BSIG1(x)   (ROR64(x,14) ^ ROR64(x,18) ^ ROR64(x,41))
#define SSIG0(x)   (ROR64(x,1) ^ ROR64(x,8) ^ (x >> 7))
#define SSIG1(x)   (ROR64(x,19) ^ ROR64(x,61) ^ (x >> 6))

static const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static void sha512_fb_transform(sha512_fb_state *s, const uint8_t block[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint64_t)block[i*8+0] << 56) | ((uint64_t)block[i*8+1] << 48) |
               ((uint64_t)block[i*8+2] << 40) | ((uint64_t)block[i*8+3] << 32) |
               ((uint64_t)block[i*8+4] << 24) | ((uint64_t)block[i*8+5] << 16) |
               ((uint64_t)block[i*8+6] << 8) | (uint64_t)block[i*8+7];
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = SSIG1(w[i-2]) + w[i-7] + SSIG0(w[i-15]) + w[i-16];
    }

    uint64_t a = s->state[0];
    uint64_t b = s->state[1];
    uint64_t c = s->state[2];
    uint64_t d = s->state[3];
    uint64_t e = s->state[4];
    uint64_t f = s->state[5];
    uint64_t g = s->state[6];
    uint64_t h = s->state[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = h + BSIG1(e) + CH(e,f,g) + K512[i] + w[i];
        uint64_t t2 = BSIG0(a) + MAJ(a,b,c);
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
        volatile uint64_t *z;
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

static void sha512_fb_init_state(sha512_fb_state *s) {
    s->state[0] = 0x6a09e667f3bcc908ULL;
    s->state[1] = 0xbb67ae8584caa73bULL;
    s->state[2] = 0x3c6ef372fe94f82bULL;
    s->state[3] = 0xa54ff53a5f1d36f1ULL;
    s->state[4] = 0x510e527fade682d1ULL;
    s->state[5] = 0x9b05688c2b3e6c1fULL;
    s->state[6] = 0x1f83d9abfb41bd6bULL;
    s->state[7] = 0x5be0cd19137e2179ULL;
    s->bitlen_low = 0;
    s->bitlen_high = 0;
    s->buffer_len = 0;
}

void bedrock_sha512_fallback_init(void *state) {
    sha512_fb_state *s = (sha512_fb_state*)state;
    sha512_fb_init_state(s);
}

void bedrock_sha512_fallback_reset(void *state) {
    sha512_fb_state *s = (sha512_fb_state*)state;
    sha512_fb_init_state(s);
}

static void add_bits(sha512_fb_state *s, uint64_t bits) {
    uint64_t old = s->bitlen_low;
    s->bitlen_low += bits;
    if (s->bitlen_low < old) { // overflow
        s->bitlen_high += 1;
    }
}

void bedrock_sha512_fallback_update(void *state, const uint8_t *data, size_t len) {
    sha512_fb_state *s = (sha512_fb_state*)state;
    if (len == 0) return;
    add_bits(s, (uint64_t)len * 8u);
    size_t off = 0;
    if (s->buffer_len) {
        size_t need = 128 - s->buffer_len;
        if (need > len) need = len;
        memcpy(&s->buffer[s->buffer_len], &data[off], need);
        s->buffer_len += (uint32_t)need;
        off += need;
        if (s->buffer_len == 128) {
            sha512_fb_transform(s, s->buffer);
            s->buffer_len = 0;
        }
    }
    while (off + 128 <= len) {
        sha512_fb_transform(s, &data[off]);
        off += 128;
    }
    if (off < len) {
        size_t rem = len - off;
        memcpy(s->buffer, &data[off], rem);
        s->buffer_len = (uint32_t)rem;
    }
}

static void sha512_fb_final(sha512_fb_state *s, uint8_t out[64]) {
    uint8_t block[128];
    uint8_t block2[128];
    size_t used = s->buffer_len;
    uint64_t lo = s->bitlen_low;
    uint64_t hi = s->bitlen_high;

    memcpy(block, s->buffer, used);
    block[used++] = 0x80;

    if (used > 112) {
        memset(block + used, 0, 128 - used);
        sha512_fb_transform(s, block);
        memset(block2, 0, 128);
        // append 128-bit big-endian length (hi then lo)
        for (int i = 0; i < 8; ++i) block2[112 + 7 - i] = (uint8_t)(hi >> (i*8));
        for (int i = 0; i < 8; ++i) block2[120 + 7 - i] = (uint8_t)(lo >> (i*8));
        sha512_fb_transform(s, block2);
    } else {
        memset(block + used, 0, 112 - used);
        for (int i = 0; i < 8; ++i) block[112 + 7 - i] = (uint8_t)(hi >> (i*8));
        for (int i = 0; i < 8; ++i) block[120 + 7 - i] = (uint8_t)(lo >> (i*8));
        sha512_fb_transform(s, block);
    }

    for (int i = 0; i < 8; ++i) {
        out[i*8+0] = (uint8_t)(s->state[i] >> 56);
        out[i*8+1] = (uint8_t)(s->state[i] >> 48);
        out[i*8+2] = (uint8_t)(s->state[i] >> 40);
        out[i*8+3] = (uint8_t)(s->state[i] >> 32);
        out[i*8+4] = (uint8_t)(s->state[i] >> 24);
        out[i*8+5] = (uint8_t)(s->state[i] >> 16);
        out[i*8+6] = (uint8_t)(s->state[i] >> 8);
        out[i*8+7] = (uint8_t)(s->state[i]);
    }

    // Clear local buffers
    secure_bzero(block, sizeof(block));
    secure_bzero(block2, sizeof(block2));
}

void bedrock_sha512_fallback_final_copy(const void *state, uint8_t out[64]) {
    sha512_fb_state tmp;
    memcpy(&tmp, state, sizeof(tmp));
    sha512_fb_final(&tmp, out);
    secure_bzero(&tmp, sizeof(tmp));
}

void bedrock_sha512_fallback_fini(void *state) {
    volatile uint8_t *p = (volatile uint8_t*)state;
    for (size_t i = 0; i < sizeof(sha512_fb_state); ++i) p[i] = 0;
}


