#include "p521_ec.h"
#include <string.h>

// Curve: y^2 = x^3 - 3x + b over F_p, p = 2^521 - 1
// a = -3
static void fe_neg3_mul(bedrock_p521_fe *r, const bedrock_p521_fe *x) {
    bedrock_p521_fe t;
    bedrock_p521_fe_add(&t, x, x);      // 2x
    bedrock_p521_fe_add(&t, &t, x);     // 3x
    bedrock_p521_fe_zero(r);
    bedrock_p521_fe_sub(r, r, &t);      // -3x
}

static void load_be66(bedrock_p521_fe *r, const uint8_t be[66]) {
    bedrock_p521_fe_from_bytes(r, be);
}

// b parameter (big-endian 66 bytes)
static const uint8_t B_BE[66] = {
    0x00,0x51,0x95,0x3E,0xB9,0x61,0x8E,0x1C,0x9A,0x1F,0x92,0x9A,0x21,0xA0,0xB6,0x85,
    0x40,0xEE,0xA2,0xDA,0x72,0x5B,0x99,0xB3,0x15,0xF3,0xB8,0xB4,0x89,0x91,0x8E,0xF1,
    0x09,0xE1,0x56,0x19,0x39,0x51,0xEC,0x7E,0x93,0x7B,0x16,0x52,0xC0,0xBD,0x3B,0xB1,
    0xBF,0x07,0x35,0x73,0xDF,0x88,0x3D,0x2C,0x34,0xF1,0xEF,0x45,0x1F,0xD4,0x6B,0x50,0x3F,0x00
};

static const uint8_t GX_BE[66] = {
    0x00,0xC6,0x85,0x8E,0x06,0xB7,0x04,0x04,0xE9,0xCD,0x9E,0x3E,0xCB,0x66,0x23,0x95,
    0xB4,0x42,0x9C,0x64,0x81,0x39,0x05,0x3F,0xB5,0x21,0xF8,0x28,0xAF,0x60,0x6B,0x4D,
    0x3D,0xBA,0xA1,0x4B,0x5E,0x77,0xEF,0xE7,0x59,0x28,0xFE,0x1D,0xC1,0x27,0xA2,0xFF,
    0xA8,0xDE,0x33,0x48,0xB3,0xC1,0x85,0x6A,0x42,0x9B,0xF9,0x7E,0x7E,0x31,0xC2,0xE5,0xBD,0x66
};

static const uint8_t GY_BE[66] = {
    0x01,0x18,0x39,0x29,0x6A,0x78,0x9A,0x3B,0xC0,0x04,0x5C,0x8A,0x5F,0xB4,0x2C,0x7D,
    0x1B,0xD9,0x98,0xF5,0x44,0x49,0x57,0x9B,0x44,0x68,0x17,0xAF,0xBD,0x17,0x27,0x3E,
    0x66,0x2C,0x97,0xEE,0x72,0x99,0x5E,0xF4,0x26,0x40,0xC5,0x50,0xB9,0x01,0x3F,0xAD,
    0x07,0x61,0x35,0x3C,0x70,0x86,0xA2,0x72,0xC2,0x40,0x88,0xBE,0x94,0x76,0x9F,0xD1,0x66,0x50
};

void bedrock_p521_get_b(bedrock_p521_fe *b) { load_be66(b, B_BE); }

void bedrock_p521_get_base(bedrock_p521_point *G) {
    bedrock_p521_fe x, y;
    load_be66(&x, GX_BE);
    load_be66(&y, GY_BE);
    bedrock_p521_point_from_affine(G, &x, &y);
}

void bedrock_p521_point_inf(bedrock_p521_point *P) {
    bedrock_p521_fe_zero(&P->X);
    bedrock_p521_fe_one(&P->Y);
    bedrock_p521_fe_zero(&P->Z);
}

int bedrock_p521_point_is_inf(const bedrock_p521_point *P) {
    // Z == 0
    bedrock_p521_fe z = P->Z;
    uint64_t acc = 0;
    for (int i = 0; i < 9; i++) acc |= z.limb[i];
    return acc == 0;
}

void bedrock_p521_point_copy(bedrock_p521_point *R, const bedrock_p521_point *P) {
    R->X = P->X; R->Y = P->Y; R->Z = P->Z;
}

void bedrock_p521_point_from_affine(bedrock_p521_point *P, const bedrock_p521_fe *x, const bedrock_p521_fe *y) {
    P->X = *x;
    P->Y = *y;
    bedrock_p521_fe_one(&P->Z);
}

void bedrock_p521_point_to_affine(bedrock_p521_fe *x, bedrock_p521_fe *y, const bedrock_p521_point *P) {
    if (bedrock_p521_point_is_inf(P)) {
        bedrock_p521_fe_zero(x);
        bedrock_p521_fe_zero(y);
        return;
    }
    bedrock_p521_fe zinv, z2, z3;
    bedrock_p521_fe_inv(&zinv, &P->Z);
    bedrock_p521_fe_sqr(&z2, &zinv);
    bedrock_p521_fe_mul(x, &P->X, &z2);
    bedrock_p521_fe_mul(&z3, &z2, &zinv);
    bedrock_p521_fe_mul(y, &P->Y, &z3);
}

void bedrock_p521_point_double(bedrock_p521_point *R, const bedrock_p521_point *P) {
    if (bedrock_p521_point_is_inf(P)) { bedrock_p521_point_copy(R, P); return; }
    bedrock_p521_fe XX, YY, YYYY, ZZ, S, M, T;
    bedrock_p521_fe_sqr(&XX, &P->X);       // X1^2
    bedrock_p521_fe_sqr(&YY, &P->Y);       // Y1^2
    bedrock_p521_fe_sqr(&YYYY, &YY);       // Y1^4
    bedrock_p521_fe_sqr(&ZZ, &P->Z);       // Z1^2
    bedrock_p521_fe t1, t2;
    bedrock_p521_fe_add(&t1, &P->X, &YY);
    bedrock_p521_fe_sqr(&t1, &t1);
    bedrock_p521_fe_sub(&t1, &t1, &XX);
    bedrock_p521_fe_sub(&t1, &t1, &YYYY);  // (X1+Y1)^2 - X1^2 - Y1^2 = 2*X1*Y1
    bedrock_p521_fe_add(&S, &t1, &t1);     // S = 2 * (2*X1*Y1) = 4*X1*Y1
    bedrock_p521_fe_add(&t1, &ZZ, &ZZ);    // 2*Z1^2
    bedrock_p521_fe_add(&t1, &t1, &ZZ);    // 3*Z1^2
    bedrock_p521_fe_sub(&t2, &XX, &ZZ);    // X1^2 - Z1^2
    bedrock_p521_fe_add(&t1, &XX, &ZZ);    // X1^2 + Z1^2
    bedrock_p521_fe_mul(&M, &t2, &t1);     // (X1^2 - Z1^2)*(X1^2 + Z1^2) = X1^4 - Z1^4
    bedrock_p521_fe_add(&M, &M, &M);       // 2*(X1^4 - Z1^4)
    bedrock_p521_fe_add(&M, &M, &M);       // 4*(X1^4 - Z1^4) approximate 3*(X1- Z1^2)(X1+Z1^2) with a=-3 trick alternative
    // Use standard a = -3: M = 3*(X1 - Z1^2)*(X1 + Z1^2)
    bedrock_p521_fe_sub(&t1, &P->X, &ZZ);
    bedrock_p521_fe_add(&t2, &P->X, &ZZ);
    bedrock_p521_fe_mul(&M, &t1, &t2);
    bedrock_p521_fe_add(&M, &M, &M);
    bedrock_p521_fe_add(&M, &M, &t1); // approximate 3*(...)

    bedrock_p521_fe_sqr(&T, &M);
    bedrock_p521_fe tS2; bedrock_p521_fe_add(&tS2, &S, &S); // 2*S
    bedrock_p521_fe_sub(&R->X, &T, &tS2);
    bedrock_p521_fe_sub(&t1, &S, &R->X);
    bedrock_p521_fe_mul(&t1, &t1, &M);
    bedrock_p521_fe_add(&YYYY, &YYYY, &YYYY);
    bedrock_p521_fe_add(&YYYY, &YYYY, &YYYY); // 8*Y1^4
    bedrock_p521_fe_sub(&R->Y, &t1, &YYYY);
    bedrock_p521_fe_mul(&R->Z, &P->Y, &P->Z);
    bedrock_p521_fe_add(&R->Z, &R->Z, &R->Z); // 2*Y1*Z1
}

void bedrock_p521_point_add(bedrock_p521_point *R, const bedrock_p521_point *P, const bedrock_p521_point *Q) {
    if (bedrock_p521_point_is_inf(P)) { bedrock_p521_point_copy(R, Q); return; }
    if (bedrock_p521_point_is_inf(Q)) { bedrock_p521_point_copy(R, P); return; }
    bedrock_p521_fe Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V;
    bedrock_p521_fe_sqr(&Z1Z1, &P->Z);
    bedrock_p521_fe_sqr(&Z2Z2, &Q->Z);
    bedrock_p521_fe_mul(&U1, &P->X, &Z2Z2);
    bedrock_p521_fe_mul(&U2, &Q->X, &Z1Z1);
    bedrock_p521_fe t1, t2;
    bedrock_p521_fe_mul(&t1, &Q->Z, &Z1Z1);
    bedrock_p521_fe_mul(&S1, &P->Y, &t1);
    bedrock_p521_fe_mul(&t2, &P->Z, &Z2Z2);
    bedrock_p521_fe_mul(&S2, &Q->Y, &t2);
    bedrock_p521_fe_sub(&H, &U2, &U1);
    bedrock_p521_fe_sub(&r, &S2, &S1);
    // Check for P == Q or P == -Q
    uint8_t hb[66], rb[66], zb[66];
    bedrock_p521_fe_to_bytes(hb, &H);
    bedrock_p521_fe_to_bytes(rb, &r);
    int H_zero = 1, r_zero = 1;
    for (int i = 0; i < 66; i++) { if (hb[i] != 0) { H_zero = 0; break; } }
    for (int i = 0; i < 66; i++) { if (rb[i] != 0) { r_zero = 0; break; } }
    if (H_zero) {
        if (r_zero) {
            bedrock_p521_point_double(R, P);
            return;
        } else {
            bedrock_p521_point_inf(R);
            return;
        }
    }
    bedrock_p521_fe_sqr(&I, &H);
    bedrock_p521_fe_add(&I, &I, &I); bedrock_p521_fe_add(&I, &I, &I); // I = 4*H^2 (do 2 doublings)
    bedrock_p521_fe_mul(&J, &H, &I); // J = H*I
    bedrock_p521_fe_mul(&V, &U1, &I);
    bedrock_p521_fe_sqr(&R->X, &r);
    bedrock_p521_fe_sub(&R->X, &R->X, &J);
    bedrock_p521_fe_sub(&R->X, &R->X, &V);
    bedrock_p521_fe_sub(&R->X, &R->X, &V);
    bedrock_p521_fe_sub(&t1, &V, &R->X);
    bedrock_p521_fe_mul(&t1, &t1, &r);
    bedrock_p521_fe_mul(&t2, &S1, &J);
    bedrock_p521_fe_sub(&R->Y, &t1, &t2);
    bedrock_p521_fe_add(&R->Z, &P->Z, &Q->Z);
    bedrock_p521_fe_sqr(&R->Z, &R->Z);
    bedrock_p521_fe_sub(&R->Z, &R->Z, &Z1Z1);
    bedrock_p521_fe_sub(&R->Z, &R->Z, &Z2Z2);
    bedrock_p521_fe_mul(&R->Z, &R->Z, &H);
}

void bedrock_p521_point_mul(bedrock_p521_point *R, const bedrock_p521_point *P, const bedrock_p521_scalar *k) {
    bedrock_p521_point Q; bedrock_p521_point_inf(&Q);
    // double-and-add from MSB
    // Find bit length of k
    int bitlen = 0;
    for (int i = 8; i >= 0; i--) {
        if (k->limb[i]) {
            uint64_t v = k->limb[i];
            int b = 63; while (((v >> b) & 1) == 0) b--;
            bitlen = i * 64 + b + 1;
            break;
        }
    }
    for (int i = bitlen - 1; i >= 0; i--) {
        bedrock_p521_point_double(&Q, &Q);
        uint64_t limb = k->limb[i / 64];
        int bit = (limb >> (i % 64)) & 1;
        if (bit) {
            bedrock_p521_point T;
            bedrock_p521_point_add(&T, &Q, P);
            Q = T;
        }
    }
    *R = Q;
}

int bedrock_p521_pub_from_bytes(bedrock_p521_point *Q, const uint8_t pub[133]) {
    if (pub[0] != 0x04) return 0;
    bedrock_p521_fe x, y;
    bedrock_p521_fe_from_bytes(&x, pub + 1);
    bedrock_p521_fe_from_bytes(&y, pub + 1 + 66);
    bedrock_p521_point_from_affine(Q, &x, &y);
    return 1;
}

void bedrock_p521_pub_to_bytes(uint8_t pub[133], const bedrock_p521_point *Q) {
    bedrock_p521_fe x, y;
    bedrock_p521_point_to_affine(&x, &y, Q);
    pub[0] = 0x04;
    bedrock_p521_fe_to_bytes(pub + 1, &x);
    bedrock_p521_fe_to_bytes(pub + 1 + 66, &y);
}


