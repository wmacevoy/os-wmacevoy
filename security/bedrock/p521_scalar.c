#include "p521_scalar.h"

#include <string.h>

// secp521r1 group order n (big-endian):
// n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
static const uint8_t N_BE[66] = {
    0x01,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFA,0x51,0x86,0x87,0x83,0xBF,0x2F,0x96,0x6B,0x7F,0xCC,0x01,0x48,0xF7,0x09,0xA5,
    0xD0,0x3B,0xB5,0xC9,0xB8,0x89,0x9C,0x47,0xAE,0xBB,0x6F,0xB7,0x1E,0x91,0x38,0x64,0x09
};

static void n_to_le(uint64_t n_le[9]) {
    for (int i = 0; i < 9; i++) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; b++) {
            int idx = 65 - (i*8 + b);
            if (idx >= 0) limb = (limb << 8) | N_BE[idx];
        }
        n_le[i] = limb;
    }
    // n_le is little-endian limbs:
    // recompute properly
    uint64_t tmp[9];
    for (int i = 0; i < 9; i++) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; b++) {
            int be_idx = 65 - (i*8 + b);
            if (be_idx >= 0) {
                limb |= ((uint64_t)N_BE[be_idx]) << (8*b);
            }
        }
        tmp[i] = limb;
    }
    for (int i = 0; i < 9; i++) n_le[i] = tmp[i];
}

static const uint64_t* N_le(void) {
    static uint64_t NLE[9];
    static int init = 0;
    if (!init) {
        n_to_le(NLE);
        init = 1;
    }
    return NLE;
}

void bedrock_p521_scalar_zero(bedrock_p521_scalar *r) {
    for (int i = 0; i < 9; i++) r->limb[i] = 0;
}

void bedrock_p521_scalar_one(bedrock_p521_scalar *r) {
    for (int i = 0; i < 9; i++) r->limb[i] = 0;
    r->limb[0] = 1;
}

int bedrock_p521_scalar_is_zero(const bedrock_p521_scalar *a) {
    uint64_t acc = 0;
    for (int i = 0; i < 9; i++) acc |= a->limb[i];
    return acc == 0;
}

static int cmp_limbs(const uint64_t *a, const uint64_t *b, size_t n) {
    for (size_t i = n; i-- > 0;) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

int bedrock_p521_scalar_cmp(const bedrock_p521_scalar *a, const bedrock_p521_scalar *b) {
    return cmp_limbs(a->limb, b->limb, 9);
}

void bedrock_p521_scalar_from_bytes(bedrock_p521_scalar *r, const uint8_t be[66]) {
    // big-endian to little-endian limbs
    for (int i = 0; i < 9; i++) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; b++) {
            int idx = 66 - 1 - (i*8 + b);
            if (idx >= 0) limb = (limb << 8) | be[idx];
        }
        r->limb[i] = limb;
    }
    // reduce modulo n if necessary (value is at most 2^521-1)
    const uint64_t *n = N_le();
    if (cmp_limbs(r->limb, n, 9) >= 0) {
        // r = r - n
        uint64_t borrow = 0;
        for (int i = 0; i < 9; i++) {
            __uint128_t diff = (__uint128_t)r->limb[i] - n[i] - borrow;
            r->limb[i] = (uint64_t)diff;
            borrow = (diff >> 127) & 1; // 1 if negative
        }
    }
}

void bedrock_p521_scalar_to_bytes(uint8_t be[66], const bedrock_p521_scalar *a) {
    // canonical form: if a == n, map to 0 (but our representation ensures < n)
    for (int i = 0; i < 66; i++) be[i] = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t limb = a->limb[i];
        for (int b = 0; b < 8; b++) {
            int idx = 66 - 1 - (i*8 + b);
            if (idx >= 0) {
                be[idx] = (uint8_t)(limb & 0xFF);
                limb >>= 8;
            }
        }
    }
}

static int highest_bit_index(const uint64_t *a, size_t n) {
    for (int i = (int)n - 1; i >= 0; i--) {
        if (a[i]) {
            uint64_t v = a[i];
            int bit = 63;
            while (((v >> bit) & 1) == 0) bit--;
            return i * 64 + bit;
        }
    }
    return -1;
}

static void shift_left_bits(uint64_t *out, size_t out_len, const uint64_t *in, size_t in_len, int bits) {
    memset(out, 0, out_len * sizeof(uint64_t));
    int w = bits / 64;
    int b = bits % 64;
    uint64_t carry = 0;
    for (size_t i = 0; i < in_len; i++) {
        uint64_t v = in[i];
        size_t oi = i + w;
        if (oi < out_len) {
            out[oi] |= (v << b) | carry;
            carry = (b == 0) ? 0 : (v >> (64 - b));
        }
    }
    if (carry && (in_len + w) < out_len) {
        out[in_len + w] |= carry;
    }
}

static void sub_in_place(uint64_t *a, const uint64_t *b, size_t n) {
    __uint128_t borrow = 0;
    for (size_t i = 0; i < n; i++) {
        __uint128_t diff = (__uint128_t)a[i] - b[i] - (uint64_t)borrow;
        a[i] = (uint64_t)diff;
        borrow = (diff >> 127) & 1;
    }
}

void bedrock_p521_scalar_reduce_mod_n(bedrock_p521_scalar *r, const uint64_t *wide, size_t wide_limbs) {
    // wide up to 18 limbs
    uint64_t rem[19]; memset(rem, 0, sizeof(rem));
    size_t L = (wide_limbs > 19) ? 19 : wide_limbs;
    for (size_t i = 0; i < L; i++) rem[i] = wide[i];
    const uint64_t *n = N_le();
    int nbits = highest_bit_index(n, 9);
    int rbits = highest_bit_index(rem, 19);
    while (rbits >= nbits) {
        int shift = rbits - nbits;
        uint64_t dn[20]; memset(dn, 0, sizeof(dn));
        shift_left_bits(dn, 20, n, 9, shift);
        size_t dn_len = (9 + (shift/64) + 2);
        if (dn_len > 19) dn_len = 19;
        if (cmp_limbs(rem, dn, 19) >= 0) {
            sub_in_place(rem, dn, 19);
        } else {
            // Shouldn't happen due to bit alignment, but guard
        }
        rbits = highest_bit_index(rem, 19);
    }
    for (int i = 0; i < 9; i++) r->limb[i] = rem[i];
    // Ensure < n
    if (cmp_limbs(r->limb, n, 9) >= 0) {
        sub_in_place(r->limb, n, 9);
    }
}

void bedrock_p521_scalar_reduce_hash64(bedrock_p521_scalar *r, const uint8_t hash_be[64]) {
    // Load 64-byte big-endian into 9 little-endian limbs (fills upper with zeros)
    uint64_t wide[18]; memset(wide, 0, sizeof(wide));
    // Treat as 8 limbs (512 bits) into little-endian; place into wide
    for (int i = 0; i < 8; i++) {
        uint64_t limb = 0;
        for (int b = 0; b < 8; b++) {
            limb = (limb << 8) | hash_be[i*8 + b];
        }
        // store in little-endian index
        wide[i] = 0;
    }
    // Simpler: parse directly to limbs little-endian
    for (int i = 0; i < 9; i++) r->limb[i] = 0;
    // We'll reuse from_bytes for 66 bytes by prefixing 2 zero bytes
    uint8_t be66[66];
    be66[0] = 0x00; be66[1] = 0x00;
    memcpy(&be66[2], hash_be, 64);
    bedrock_p521_scalar_from_bytes(r, be66);
}

void bedrock_p521_scalar_add_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b) {
    __uint128_t carry = 0;
    for (int i = 0; i < 9; i++) {
        __uint128_t s = (__uint128_t)a->limb[i] + b->limb[i] + (uint64_t)carry;
        r->limb[i] = (uint64_t)s;
        carry = s >> 64;
    }
    const uint64_t *n = N_le();
    if (carry || cmp_limbs(r->limb, n, 9) >= 0) {
        // subtract n
        sub_in_place(r->limb, n, 9);
    }
}

void bedrock_p521_scalar_sub_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b) {
    __uint128_t borrow = 0;
    for (int i = 0; i < 9; i++) {
        __uint128_t d = (__uint128_t)a->limb[i] - b->limb[i] - (uint64_t)borrow;
        r->limb[i] = (uint64_t)d;
        borrow = (d >> 127) & 1;
    }
    if (borrow) {
        // add n
        const uint64_t *n = N_le();
        __uint128_t carry = 0;
        for (int i = 0; i < 9; i++) {
            __uint128_t s = (__uint128_t)r->limb[i] + n[i] + (uint64_t)carry;
            r->limb[i] = (uint64_t)s;
            carry = s >> 64;
        }
    }
}

void bedrock_p521_scalar_mul_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b) {
    __uint128_t acc[18]; for (int i = 0; i < 18; i++) acc[i] = 0;
    for (int i = 0; i < 9; i++) {
        for (int j = 0; j < 9; j++) {
            acc[i + j] += (__uint128_t)a->limb[i] * b->limb[j];
        }
    }
    uint64_t wide[18];
    uint64_t carry = 0;
    for (int k = 0; k < 18; k++) {
        acc[k] += carry;
        wide[k] = (uint64_t)acc[k];
        carry = (uint64_t)(acc[k] >> 64);
    }
    bedrock_p521_scalar_reduce_mod_n(r, wide, 18);
}

static int is_even(const bedrock_p521_scalar *a) {
    return (a->limb[0] & 1) == 0;
}

static void rshift1(bedrock_p521_scalar *a) {
    uint64_t carry = 0;
    for (int i = 8; i >= 0; i--) {
        uint64_t new_carry = a->limb[i] << 63;
        a->limb[i] = (a->limb[i] >> 1) | carry;
        carry = new_carry;
    }
}

void bedrock_p521_scalar_inv_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a) {
    // Binary extended GCD to compute inverse of a mod n
    const uint64_t *nle = N_le();
    bedrock_p521_scalar u, v, x1, x2, zero;
    memcpy(&u, &(bedrock_p521_scalar){ .limb = {0} }, sizeof(u));
    for (int i = 0; i < 9; i++) u.limb[i] = nle[i];
    v = *a;
    bedrock_p521_scalar_zero(&x1);
    bedrock_p521_scalar_one(&x2);
    bedrock_p521_scalar_zero(&zero);
    while (!bedrock_p521_scalar_is_zero(&v)) {
        while (is_even(&u)) {
            rshift1(&u);
            if (is_even(&x1)) {
                rshift1(&x1);
            } else {
                bedrock_p521_scalar_add_mod(&x1, &x1, (const bedrock_p521_scalar*)&(bedrock_p521_scalar){ .limb = {0} }); // no-op; will add n then shift
                // x1 += n, then >>1
                bedrock_p521_scalar t; for (int i = 0; i < 9; i++) t.limb[i] = nle[i];
                bedrock_p521_scalar_add_mod(&x1, &x1, &t);
                rshift1(&x1);
            }
        }
        while (is_even(&v)) {
            rshift1(&v);
            if (is_even(&x2)) {
                rshift1(&x2);
            } else {
                bedrock_p521_scalar t; for (int i = 0; i < 9; i++) t.limb[i] = nle[i];
                bedrock_p521_scalar_add_mod(&x2, &x2, &t);
                rshift1(&x2);
            }
        }
        if (bedrock_p521_scalar_cmp(&u, &v) >= 0) {
            bedrock_p521_scalar_sub_mod(&u, &u, &v);
            bedrock_p521_scalar_sub_mod(&x1, &x1, &x2);
        } else {
            bedrock_p521_scalar_sub_mod(&v, &v, &u);
            bedrock_p521_scalar_sub_mod(&x2, &x2, &x1);
        }
    }
    // x1 is inverse of a mod n
    *r = x2; // Due to the loop structure, inverse ends up in x2
    // Normalize: ensure 0..n-1
    const uint64_t *n = N_le();
    if (bedrock_p521_scalar_is_zero(r) || cmp_limbs(r->limb, n, 9) >= 0) {
        while (cmp_limbs(r->limb, n, 9) >= 0) {
            sub_in_place(r->limb, n, 9);
        }
        while ((int)(r->limb[8] >> 63) < 0) { // not meaningful; keep as-is
            bedrock_p521_scalar_add_mod(r, r, (const bedrock_p521_scalar*)&(bedrock_p521_scalar){ .limb = {0} });
        }
    }
}

void bedrock_p521_scalar_from_random_bytes(bedrock_p521_scalar *d, const uint8_t rnd[66]) {
    bedrock_p521_scalar_from_bytes(d, rnd);
    // Ensure 1..n-1: if zero, set to one; otherwise leave reduced.
    if (bedrock_p521_scalar_is_zero(d)) {
        bedrock_p521_scalar_one(d);
    }
}


