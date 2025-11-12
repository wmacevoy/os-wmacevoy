#include "p521_field.h"

#include <string.h>

// p = 2^521 - 1
static const uint64_t P521_TOP_MASK = ((uint64_t)1 << 9) - 1; // low 9 bits set

static void fe_set_p(bedrock_p521_fe *r) {
    for (int i = 0; i < 8; i++) r->limb[i] = UINT64_MAX;
    r->limb[8] = P521_TOP_MASK;
}

static int fe_is_zero(const bedrock_p521_fe *a) {
    uint64_t acc = 0;
    for (int i = 0; i < 9; i++) acc |= a->limb[i];
    return acc == 0;
}

static int fe_is_p(const bedrock_p521_fe *a) {
    for (int i = 0; i < 8; i++) {
        if (a->limb[i] != UINT64_MAX) return 0;
    }
    return a->limb[8] == P521_TOP_MASK;
}

static uint64_t add_carry_u64(uint64_t a, uint64_t b, uint64_t *out) {
    __uint128_t s = (__uint128_t)a + b;
    *out = (uint64_t)s;
    return (uint64_t)(s >> 64);
}

static uint64_t add_carry3_u64(uint64_t a, uint64_t b, uint64_t c, uint64_t *out) {
    __uint128_t s = (__uint128_t)a + b + c;
    *out = (uint64_t)s;
    return (uint64_t)(s >> 64);
}

static uint64_t sub_borrow_u64(uint64_t a, uint64_t b, uint64_t *out) {
    __uint128_t d = (__uint128_t)a - b;
    *out = (uint64_t)d;
    return (uint64_t)((d >> 64) & 1); // 1 if borrow
}

// Add a 64-bit value to limbs[0..8] (little-endian) and return carry out of limb[8].
static uint64_t fe_add_scalar_u64(bedrock_p521_fe *r, uint64_t v) {
    uint64_t carry = v;
    for (int i = 0; i < 9; i++) {
        uint64_t out;
        carry = add_carry3_u64(r->limb[i], (uint64_t)0, carry, &out);
        r->limb[i] = out;
    }
    return carry;
}

// Add val << (64*w + b) into r, where 0 <= w, 0 <= b < 64.
// Only r->limb[0..8] exist; carry beyond limb 8 is returned.
static uint64_t fe_add_shifted64(bedrock_p521_fe *r, int w, int b, uint64_t val) {
    if (val == 0) return 0;
    uint64_t carry = 0;
    // low part
    if (w <= 8) {
        __uint128_t add = ((__uint128_t)val) << b;
        for (int i = w; i <= 8 && add; i++) {
            uint64_t cur = r->limb[i];
            __uint128_t sum = (__uint128_t)cur + (uint64_t)add;
            r->limb[i] = (uint64_t)sum;
            add = (add >> 64) + (sum >> 64);
        }
        carry = (uint64_t)add;
    } else {
        // starts beyond our array; treat as carry (will fold below)
        carry = 1; // indicate something to fold
    }
    // high spill from bit shift (val >> (64-b)) goes to w+1
    if (b != 0) {
        uint64_t high = val >> (64 - b);
        if (high) {
            if (w + 1 <= 8) {
                uint64_t c = high;
                for (int i = w + 1; i <= 8 && c; i++) {
                    uint64_t out;
                    uint64_t co = add_carry_u64(r->limb[i], c, &out);
                    r->limb[i] = out;
                    c = co;
                }
                carry += c;
            } else {
                carry += 1;
            }
        }
    }
    return carry;
}

// Normalize to canonical: fold bits above 521 back and ensure 0 <= r < p.
static void fe_normalize(bedrock_p521_fe *r) {
    for (;;) {
        // Extract bits above 521 from limb[8]
        uint64_t high = r->limb[8] >> 9;
        r->limb[8] &= P521_TOP_MASK;
        // Add 'high' to limb[0] with carry across
        uint64_t carry = 0;
        if (high) {
            carry = fe_add_scalar_u64(r, high);
        }
        // Any carry beyond limb[8] corresponds to +carry * 2^576 ≡ +carry * 2^55
        while (carry) {
            // add carry << 55 at bit position 55 (within limb 0..1)
            uint64_t co = fe_add_shifted64(r, 0, 55, carry);
            // After this, we may still have carry beyond limb8
            carry = co;
        }
        // If still have bits above 521 due to wrap additions, loop again
        if ((r->limb[8] >> 9) == 0) break;
    }
    // Reduce r if r == p => set to 0
    if (fe_is_p(r)) {
        bedrock_p521_fe_zero(r);
    }
}

void bedrock_p521_fe_zero(bedrock_p521_fe *r) {
    for (int i = 0; i < 9; i++) r->limb[i] = 0;
}

void bedrock_p521_fe_one(bedrock_p521_fe *r) {
    for (int i = 0; i < 9; i++) r->limb[i] = 0;
    r->limb[0] = 1;
}

void bedrock_p521_fe_copy(bedrock_p521_fe *r, const bedrock_p521_fe *a) {
    for (int i = 0; i < 9; i++) r->limb[i] = a->limb[i];
}

void bedrock_p521_fe_from_bytes(bedrock_p521_fe *r, const uint8_t be[66]) {
    // Convert big-endian 66-byte into little-endian byte array
    uint8_t le[66];
    for (int i = 0; i < 66; i++) le[i] = be[65 - i];
    // Pack into limbs
    for (int i = 0; i < 9; i++) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; b++) {
            int idx = i * 8 + b;
            if (idx < 66) {
                limb |= ((uint64_t)le[idx]) << (8 * b);
            }
        }
        r->limb[i] = limb;
    }
    fe_normalize(r);
}

void bedrock_p521_fe_to_bytes(uint8_t be[66], const bedrock_p521_fe *a) {
    bedrock_p521_fe t;
    bedrock_p521_fe_copy(&t, a);
    fe_normalize(&t);
    uint8_t le[66];
    for (int i = 0; i < 66; i++) le[i] = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t limb = t.limb[i];
        for (int b = 0; b < 8; b++) {
            int idx = i * 8 + b;
            if (idx < 66) {
                le[idx] = (uint8_t)(limb & 0xFF);
                limb >>= 8;
            }
        }
    }
    for (int i = 0; i < 66; i++) be[i] = le[65 - i];
}

void bedrock_p521_fe_add(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b) {
    uint64_t carry = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t out;
        carry = add_carry3_u64(a->limb[i], b->limb[i], carry, &out);
        r->limb[i] = out;
    }
    // Fold (at most small) overflow through normalization
    fe_normalize(r);
}

void bedrock_p521_fe_sub(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b) {
    uint64_t borrow = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t bi = b->limb[i] + borrow;
        uint64_t out;
        // borrow if a < bi
        borrow = (a->limb[i] < bi) ? 1 : 0;
        out = a->limb[i] - bi;
        r->limb[i] = out;
    }
    if (borrow) {
        // r += p
        uint64_t carry = 0;
        for (int i = 0; i < 8; i++) {
            uint64_t out;
            carry = add_carry3_u64(r->limb[i], UINT64_MAX, carry, &out);
            r->limb[i] = out;
        }
        uint64_t out9;
        carry = add_carry3_u64(r->limb[8], P521_TOP_MASK, carry, &out9);
        r->limb[8] = out9;
        // any remaining carry corresponds to +2^576, fold it
        while (carry) {
            uint64_t co = fe_add_shifted64(r, 0, 55, carry);
            carry = co;
        }
    }
    fe_normalize(r);
}

void bedrock_p521_fe_mul(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b) {
    __uint128_t acc[18] = {0};
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            acc[i + j] += (__uint128_t)a->limb[i] * b->limb[j];
        }
    }
    // Convert to 64-bit limbs with carry
    uint64_t U[19];
    uint64_t carry = 0;
    for (int k = 0; k < 18; k++) {
        acc[k] += carry;
        U[k] = (uint64_t)acc[k];
        carry = (uint64_t)(acc[k] >> 64);
    }
    U[18] = carry; // may be non-zero

    // Initialize R with low 9 limbs
    for (int i = 0; i < 9; i++) r->limb[i] = U[i];
    // Fold top bits from limb[8]
    r->limb[8] &= P521_TOP_MASK;
    uint64_t high0 = U[8] >> 9;
    if (high0) {
        uint64_t co = fe_add_scalar_u64(r, high0);
        while (co) {
            uint64_t c2 = fe_add_shifted64(r, 0, 55, co);
            co = c2;
        }
    }
    // Fold U[9..18]
    for (int k = 9; k <= 18; k++) {
        uint64_t hk = U[k];
        if (!hk) continue;
        int s = 64 * k - 521;
        if (s >= 521) s -= 521; // only k=18 hits this
        int w = s / 64;
        int b = s % 64;
        uint64_t co = fe_add_shifted64(r, w, b, hk);
        while (co) {
            uint64_t c2 = fe_add_shifted64(r, 0, 55, co);
            co = c2;
        }
    }
    fe_normalize(r);
}

void bedrock_p521_fe_sqr(bedrock_p521_fe *r, const bedrock_p521_fe *a) {
    bedrock_p521_fe_mul(r, a, a);
}

void bedrock_p521_fe_inv(bedrock_p521_fe *r, const bedrock_p521_fe *a) {
    // Exponentiation by e = p-2 where p = 2^521 - 1.
    // e (big-endian 66 bytes) = 0x01 || 64*0xFF || 0xFD
    uint8_t e[66];
    e[0] = 0x01;
    for (int i = 1; i < 65; i++) e[i] = 0xFF;
    e[65] = 0xFD;
    bedrock_p521_fe base, result;
    bedrock_p521_fe_copy(&base, a);
    bedrock_p521_fe_one(&result);
    int started = 0;
    for (int i = 0; i < 66; i++) {
        uint8_t byte = e[i];
        for (int b = 7; b >= 0; b--) {
            if (started) {
                bedrock_p521_fe_sqr(&result, &result);
            }
            if ((byte >> b) & 1) {
                bedrock_p521_fe_mul(&result, &result, &base);
                started = 1;
            }
        }
    }
    *r = result;
}

