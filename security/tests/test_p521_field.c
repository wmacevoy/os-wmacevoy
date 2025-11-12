#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "../bedrock/p521_field.h"
#include "../bedrock/bedrock.h"

static void hexdump(const char *label, const uint8_t *b, size_t n) {
    (void)label; (void)b; (void)n;
}

static void test_zero_one(void) {
    bedrock_p521_fe z, o, t;
    bedrock_p521_fe_zero(&z);
    bedrock_p521_fe_one(&o);
    bedrock_p521_fe_add(&t, &z, &o);
    // t should equal 1
    uint8_t tb[66], ob[66];
    bedrock_p521_fe_to_bytes(tb, &t);
    bedrock_p521_fe_to_bytes(ob, &o);
    assert(memcmp(tb, ob, 66) == 0);
}

static void test_p_is_zero(void) {
    // p = 2^521 - 1 encodes as 0x01 followed by 65 bytes 0xFF
    uint8_t pbe[66]; memset(pbe, 0xFF, sizeof(pbe)); pbe[0] = 0x01;
    bedrock_p521_fe x;
    bedrock_p521_fe_from_bytes(&x, pbe);
    uint8_t xb[66]; bedrock_p521_fe_to_bytes(xb, &x);
    uint8_t zero[66]; memset(zero, 0, sizeof(zero));
    assert(memcmp(xb, zero, 66) == 0);
}

static void test_add_sub_inverse(void) {
    // Construct random-ish values using bedrock PRNG seeded deterministically
    uint8_t seed[32]; for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;
    bedrock_prng256_struct pr;
    bedrock_prng256_init(&pr, seed, sizeof(seed));
    for (int it = 0; it < 64; it++) {
        uint8_t ab[66], bb[66];
        bedrock_prng256_bytes(&pr, ab, sizeof(ab));
        bedrock_prng256_bytes(&pr, bb, sizeof(bb));
        // mask top byte to avoid degenerate extremely large numbers too often
        ab[0] &= 0x01; bb[0] &= 0x01;
        bedrock_p521_fe a, b, s, d, back;
        bedrock_p521_fe_from_bytes(&a, ab);
        bedrock_p521_fe_from_bytes(&b, bb);
        bedrock_p521_fe_add(&s, &a, &b);
        bedrock_p521_fe_sub(&d, &s, &b);
        // (a + b) - b == a
        uint8_t db[66], ab2[66];
        bedrock_p521_fe_to_bytes(db, &d);
        bedrock_p521_fe_to_bytes(ab2, &a);
        assert(memcmp(db, ab2, 66) == 0);
        // (a - a) == 0
        bedrock_p521_fe_sub(&back, &a, &a);
        uint8_t bb2[66]; bedrock_p521_fe_to_bytes(bb2, &back);
        uint8_t zero[66]; memset(zero, 0, sizeof(zero));
        assert(memcmp(bb2, zero, 66) == 0);
    }
    bedrock_prng256_fini(&pr);
}

static void test_mul_small_limbs(void) {
    // Pick small values in low limb and verify product using 128-bit math
    for (uint64_t x = 0; x < 1000; x += 127) {
        for (uint64_t y = 0; y < 1000; y += 131) {
            bedrock_p521_fe a, b, p;
            bedrock_p521_fe_zero(&a);
            bedrock_p521_fe_zero(&b);
            a.limb[0] = x;
            b.limb[0] = y;
            bedrock_p521_fe_mul(&p, &a, &b);
            // Expected is x*y (no reduction needed as it's << p)
            __uint128_t xy = (__uint128_t)x * y;
            uint8_t eb[66]; memset(eb, 0, sizeof(eb));
            // encode xy into eb big-endian
            for (int i = 0; i < 16; i++) {
                int idx = 65 - i;
                if (idx >= 0) eb[idx] = (uint8_t)(xy & 0xFF), xy >>= 8;
            }
            uint8_t pb[66]; bedrock_p521_fe_to_bytes(pb, &p);
            assert(memcmp(pb, eb, 66) == 0);
        }
    }
}

static void test_sqr_small_limbs(void) {
    for (uint64_t x = 0; x < 1000; x += 113) {
        bedrock_p521_fe a, s, p;
        bedrock_p521_fe_zero(&a);
        a.limb[0] = x;
        bedrock_p521_fe_sqr(&s, &a);
        bedrock_p521_fe_mul(&p, &a, &a);
        uint8_t sb[66], pb[66];
        bedrock_p521_fe_to_bytes(sb, &s);
        bedrock_p521_fe_to_bytes(pb, &p);
        assert(memcmp(sb, pb, 66) == 0);
    }
}

int main(void) {
    test_zero_one();
    test_p_is_zero();
    test_add_sub_inverse();
    test_mul_small_limbs();
    test_sqr_small_limbs();
    printf("p521_field tests passed\n");
    return 0;
}


