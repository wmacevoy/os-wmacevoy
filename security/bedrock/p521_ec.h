// Elliptic curve operations for NIST P-521 (secp521r1), pure C.
#ifndef BEDROCK_P521_EC_H
#define BEDROCK_P521_EC_H

#include <stdint.h>
#include "p521_field.h"
#include "p521_scalar.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bedrock_p521_point {
    bedrock_p521_fe X;
    bedrock_p521_fe Y;
    bedrock_p521_fe Z; // Jacobian; Z==0 => infinity
} bedrock_p521_point;

void bedrock_p521_point_inf(bedrock_p521_point *P);
int bedrock_p521_point_is_inf(const bedrock_p521_point *P);
void bedrock_p521_point_copy(bedrock_p521_point *R, const bedrock_p521_point *P);

// Get base point G and curve constant b
void bedrock_p521_get_base(bedrock_p521_point *G);
void bedrock_p521_get_b(bedrock_p521_fe *b);

// Point ops
void bedrock_p521_point_double(bedrock_p521_point *R, const bedrock_p521_point *P);
void bedrock_p521_point_add(bedrock_p521_point *R, const bedrock_p521_point *P, const bedrock_p521_point *Q);
void bedrock_p521_point_mul(bedrock_p521_point *R, const bedrock_p521_point *P, const bedrock_p521_scalar *k);

// Conversions
void bedrock_p521_point_to_affine(bedrock_p521_fe *x, bedrock_p521_fe *y, const bedrock_p521_point *P);
void bedrock_p521_point_from_affine(bedrock_p521_point *P, const bedrock_p521_fe *x, const bedrock_p521_fe *y);

// Encode/decode uncompressed public key 0x04 || X || Y (66-byte fields, big-endian)
int bedrock_p521_pub_from_bytes(bedrock_p521_point *Q, const uint8_t pub[133]);
void bedrock_p521_pub_to_bytes(uint8_t pub[133], const bedrock_p521_point *Q);

#ifdef __cplusplus
}
#endif

#endif // BEDROCK_P521_EC_H


