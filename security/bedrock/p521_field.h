// Minimal P-521 prime field arithmetic (mod p = 2^521 - 1), pure C.
// Representation: little-endian array of 9 uint64_t limbs.
// Total 521-bit value: limbs[0..7] are full 64 bits, limbs[8] uses only low 9 bits.
// All APIs operate on canonical reduced elements.
#ifndef BEDROCK_P521_FIELD_H
#define BEDROCK_P521_FIELD_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bedrock_p521_fe {
    uint64_t limb[9];
} bedrock_p521_fe;

// Constructors and converters
void bedrock_p521_fe_zero(bedrock_p521_fe *r);
void bedrock_p521_fe_one(bedrock_p521_fe *r);
void bedrock_p521_fe_copy(bedrock_p521_fe *r, const bedrock_p521_fe *a);
// big-endian 66-byte encoding
void bedrock_p521_fe_from_bytes(bedrock_p521_fe *r, const uint8_t be[66]);
void bedrock_p521_fe_to_bytes(uint8_t be[66], const bedrock_p521_fe *a);

// Core ops (r = op(a,b) mod p). Inputs need not be reduced; outputs are reduced.
void bedrock_p521_fe_add(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b);
void bedrock_p521_fe_sub(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b);
void bedrock_p521_fe_mul(bedrock_p521_fe *r, const bedrock_p521_fe *a, const bedrock_p521_fe *b);
void bedrock_p521_fe_sqr(bedrock_p521_fe *r, const bedrock_p521_fe *a);
// Multiplicative inverse modulo p (a != 0). Uses exponentiation a^(p-2).
void bedrock_p521_fe_inv(bedrock_p521_fe *r, const bedrock_p521_fe *a);

#ifdef __cplusplus
}
#endif

#endif // BEDROCK_P521_FIELD_H


