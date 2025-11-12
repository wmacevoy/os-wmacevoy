#ifndef BEDROCK_BEDROCK_H
#define BEDROCK_BEDROCK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Public opaque contexts. Large enough to hold any backend.
// We keep alignment by using uint64_t.
#define BEDROCK_SHA256_CONTEXT_OPAQUE_QWORDS 128
#define BEDROCK_SHA512_CONTEXT_OPAQUE_QWORDS 192

typedef struct bedrock_sha256_struct {
    uint64_t opaque[BEDROCK_SHA256_CONTEXT_OPAQUE_QWORDS];
} bedrock_sha256_struct;

typedef struct bedrock_sha512_struct {
    uint64_t opaque[BEDROCK_SHA512_CONTEXT_OPAQUE_QWORDS];
} bedrock_sha512_struct;

// SHA-256 API
void bedrock_sha256_init(bedrock_sha256_struct *ctx);
void bedrock_sha256_reset(bedrock_sha256_struct *ctx);
void bedrock_sha256_process(bedrock_sha256_struct *ctx, size_t len, const uint8_t *data);
void bedrock_sha256_digest(const bedrock_sha256_struct *ctx, uint8_t out_digest[32]);
void bedrock_sha256_fini(bedrock_sha256_struct *ctx);

// SHA-512 API
void bedrock_sha512_init(bedrock_sha512_struct *ctx);
void bedrock_sha512_reset(bedrock_sha512_struct *ctx);
void bedrock_sha512_process(bedrock_sha512_struct *ctx, size_t len, const uint8_t *data);
void bedrock_sha512_digest(const bedrock_sha512_struct *ctx, uint8_t out_digest[64]);
void bedrock_sha512_fini(bedrock_sha512_struct *ctx);

// PRNG based on SHA-256 and SHA-512
#define BEDROCK_PRNG256_OPAQUE_QWORDS 136
#define BEDROCK_PRNG512_OPAQUE_QWORDS 208

typedef struct bedrock_prng256_struct {
    uint64_t opaque[BEDROCK_PRNG256_OPAQUE_QWORDS];
} bedrock_prng256_struct;

typedef struct bedrock_prng512_struct {
    uint64_t opaque[BEDROCK_PRNG512_OPAQUE_QWORDS];
} bedrock_prng512_struct;

void bedrock_prng256_init(bedrock_prng256_struct *prng, const uint8_t *seed, size_t seed_len);
void bedrock_prng256_bytes(bedrock_prng256_struct *prng, uint8_t *data, size_t data_len);
void bedrock_prng256_fini(bedrock_prng256_struct *prng);

void bedrock_prng512_init(bedrock_prng512_struct *prng, const uint8_t *seed, size_t seed_len);
void bedrock_prng512_bytes(bedrock_prng512_struct *prng, uint8_t *data, size_t data_len);
void bedrock_prng512_fini(bedrock_prng512_struct *prng);

struct bedrock_aead256_struct {
    struct bedrock_sha256_struct hash;
    uint8_t data[32];
    uint8_t pad[32];
    size_t size;
};

void bedrock_aead256_init(struct bedrock_aead256_struct *ctx, size_t unique_key_len, const uint8_t *unique_key);
size_t bedrock_aead256_enclear(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer);
size_t bedrock_aead256_encipher(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer);
/* pad must be able to hold at least pad_block_len bytes */
size_t bedrock_aead256_enpad(struct bedrock_aead256_struct *ctx, uint8_t pad_block_size, uint8_t *pad);
size_t bedrock_aead256_entag(struct bedrock_aead256_struct *ctx, uint8_t tag[32]);
size_t bedrock_aead256_declear(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer);
size_t bedrock_aead256_decipher(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer);
size_t bedrock_aead256_depad(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer);
size_t bedrock_aead256_detag(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer);
void bedrock_aead256_fini(struct bedrock_aead256_struct *ctx);

struct bedrock_aead512_struct {
    struct bedrock_sha512_struct hash;
    uint8_t data[64];
    uint8_t pad[64];
    size_t size;
};

void bedrock_aead512_init(struct bedrock_aead512_struct *ctx, size_t unique_key_len, const uint8_t *unique_key);
size_t bedrock_aead512_enclear(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer);
size_t bedrock_aead512_encipher(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer);
/* pad must be able to hold at least pad_block_len bytes */
size_t bedrock_aead512_enpad(struct bedrock_aead512_struct *ctx, uint8_t pad_block_size, uint8_t *pad);
size_t bedrock_aead512_entag(struct bedrock_aead512_struct *ctx, uint8_t tag[64]);
size_t bedrock_aead512_declear(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer);
size_t bedrock_aead512_decipher(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer);
size_t bedrock_aead512_depad(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer);
size_t bedrock_aead512_detag(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer);
void bedrock_aead512_fini(struct bedrock_aead512_struct *ctx);

#ifdef __cplusplus
}
#endif
 
#endif // BEDROCK_BEDROCK_H

// ---- P-521 ECDSA API (OpenSSL-backed; raw fixed-size encodings) ----
// Public key: uncompressed point: 0x04 || X[66] || Y[66] (total 133 bytes, big-endian)
// Private key: scalar d[66] (big-endian, zero-padded to 66 bytes)
// Signature: r[66] || s[66] (big-endian, zero-padded; total 132 bytes)
#ifdef __cplusplus
extern "C" {
#endif

enum {
    BEDROCK_P521_PUBLIC_KEY_BYTES  = 133,
    BEDROCK_P521_PRIVATE_KEY_BYTES = 66,
    BEDROCK_P521_SIGNATURE_BYTES   = 132
};

// Generate a random P-521 keypair.
// Returns 1 on success, 0 on failure.
int bedrock_p521_keypair_random(uint8_t pub[133], uint8_t priv[66]);

// Create a detached ECDSA signature over msg using SHA-512 as the hash.
// Returns 1 on success, 0 on failure.
int bedrock_p521_sign_detached(uint8_t sig[132],
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t pub[133],
                               const uint8_t priv[66]);

// Verify a detached ECDSA signature (raw r||s) over msg (SHA-512).
// Returns 1 if valid, 0 if invalid.
int bedrock_p521_verify_detached(const uint8_t sig[132],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t pub[133]);

#ifdef __cplusplus
}
#endif

// ---- P-521 ECIES for short digests (no external deps) ----
// Encrypt/decrypt a 32-byte (SHA-256) or 64-byte (SHA-512) digest to a P-521 public key.
// Scheme: ECIES (P-521 ECDH) + bedrock AEAD{256,512} with KDF = SHA{256,512} over:
// "Bedrock-ECIES-P521-{256|512}" || ephemeral_pub(133) || x(ECDH)(66)
// Ciphertext format: eph_pub[133] || enc[digest][32|64] || tag[32|64]
#ifdef __cplusplus
extern "C" {
#endif

enum {
    BEDROCK_P521_ECIES256_CIPHERTEXT_BYTES = 133 + 32 + 32,
    BEDROCK_P521_ECIES512_CIPHERTEXT_BYTES = 133 + 64 + 64
};

int bedrock_p521_encrypt_digest256(uint8_t out_cipher[133 + 32 + 32],
                                   const uint8_t digest32[32],
                                   const uint8_t recipient_pub[133]);

int bedrock_p521_decrypt_digest256(uint8_t out_digest32[32],
                                   const uint8_t in_cipher[133 + 32 + 32],
                                   const uint8_t recipient_priv[66]);

int bedrock_p521_encrypt_digest512(uint8_t out_cipher[133 + 64 + 64],
                                   const uint8_t digest64[64],
                                   const uint8_t recipient_pub[133]);

int bedrock_p521_decrypt_digest512(uint8_t out_digest64[64],
                                   const uint8_t in_cipher[133 + 64 + 64],
                                   const uint8_t recipient_priv[66]);
#ifdef __cplusplus
}
#endif

// ---- SPHINCS+ SHA2-128s-simple (optional; guarded by BEDROCK_ENABLE_SPHINCS) ----
#ifdef __cplusplus
extern "C" {
#endif

enum {
    BEDROCK_SPHINCS_SHA2_128S_PUBLIC_KEY_BYTES = 32,
    BEDROCK_SPHINCS_SHA2_128S_SECRET_KEY_BYTES = 64,
    BEDROCK_SPHINCS_SHA2_128S_SIGNATURE_BYTES  = 7856
};

int bedrock_sphincs_sha2_128s_keypair_random(uint8_t pk[32], uint8_t sk[64]);
int bedrock_sphincs_sha2_128s_sign_detached(uint8_t sig[7856],
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t pk[32],
                                            const uint8_t sk[64]);
int bedrock_sphincs_sha2_128s_verify_detached(const uint8_t sig[7856],
                                              const uint8_t *msg, size_t msg_len,
                                              const uint8_t pk[32]);

#ifdef __cplusplus
}
#endif
