// Minimal big-integer arithmetic modulo P-521 group order n (secp521r1)
#ifndef BEDROCK_P521_SCALAR_H
#define BEDROCK_P521_SCALAR_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bedrock_p521_scalar {
    uint64_t limb[9]; // little-endian limbs, 521-bit integer
} bedrock_p521_scalar;

// Load/store big-endian 66-byte
void bedrock_p521_scalar_from_bytes(bedrock_p521_scalar *r, const uint8_t be[66]);
void bedrock_p521_scalar_to_bytes(uint8_t be[66], const bedrock_p521_scalar *a);

// r in [0, n-1]
void bedrock_p521_scalar_reduce_mod_n(bedrock_p521_scalar *r, const uint64_t *wide, size_t wide_limbs);
void bedrock_p521_scalar_reduce_hash64(bedrock_p521_scalar *r, const uint8_t hash_be[64]);

// Basic ops modulo n
void bedrock_p521_scalar_zero(bedrock_p521_scalar *r);
void bedrock_p521_scalar_one(bedrock_p521_scalar *r);
int bedrock_p521_scalar_is_zero(const bedrock_p521_scalar *a);
int bedrock_p521_scalar_cmp(const bedrock_p521_scalar *a, const bedrock_p521_scalar *b);
void bedrock_p521_scalar_add_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b);
void bedrock_p521_scalar_sub_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b);
void bedrock_p521_scalar_mul_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a, const bedrock_p521_scalar *b);
void bedrock_p521_scalar_inv_mod(bedrock_p521_scalar *r, const bedrock_p521_scalar *a); // a != 0

// Generate a private scalar d in [1, n-1] from 66 random bytes
void bedrock_p521_scalar_from_random_bytes(bedrock_p521_scalar *d, const uint8_t rnd[66]);

#ifdef __cplusplus
}
#endif

#endif // BEDROCK_P521_SCALAR_H


