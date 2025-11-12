#include "bedrock.h"
#include "p521_ec.h"
#include "p521_scalar.h"
#include "p521_field.h"

#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

static void secure_bzero(void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (len--) { *p++ = 0; }
}

static int read_urandom(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, out + off, len - off);
        if (n <= 0) { close(fd); return 0; }
        off += (size_t)n;
    }
    close(fd);
    return 1;
}

// ECDH shared secret X coordinate into 66-byte big-endian
static int p521_ecdh_x_be66(uint8_t xbe[66], const uint8_t peer_pub[133], const bedrock_p521_scalar *my_scalar) {
    bedrock_p521_point P;
    if (!bedrock_p521_pub_from_bytes(&P, peer_pub)) return 0;
    bedrock_p521_point S;
    bedrock_p521_point_mul(&S, &P, my_scalar);
    if (bedrock_p521_point_is_inf(&S)) return 0;
    bedrock_p521_fe X, Y;
    bedrock_p521_point_to_affine(&X, &Y, &S);
    bedrock_p521_fe_to_bytes(xbe, &X);
    return 1;
}

int bedrock_p521_encrypt_digest256(uint8_t out_cipher[133 + 32 + 32],
                                   const uint8_t digest32[32],
                                   const uint8_t recipient_pub[133]) {
    // Generate ephemeral scalar
    uint8_t rnd[66];
    if (!read_urandom(rnd, sizeof(rnd))) return 0;
    bedrock_p521_scalar ke;
    bedrock_p521_scalar_from_random_bytes(&ke, rnd);
    secure_bzero(rnd, sizeof(rnd));
    // Compute ephemeral pub
    bedrock_p521_point G, Ke;
    bedrock_p521_get_base(&G);
    bedrock_p521_point_mul(&Ke, &G, &ke);
    uint8_t eph_pub[133];
    bedrock_p521_pub_to_bytes(eph_pub, &Ke);
    // Compute ECDH with recipient pub
    uint8_t xbe[66];
    if (!p521_ecdh_x_be66(xbe, recipient_pub, &ke)) return 0;
    // AEAD key derivation input
    uint8_t label[] = "Bedrock-ECIES-P521-256";
    struct bedrock_aead256_struct aead;
    bedrock_aead256_init(&aead, sizeof(label), label);
    bedrock_aead256_enclear(&aead, 133, eph_pub);
    bedrock_aead256_enclear(&aead, 66, xbe);
    // Build ciphertext: eph_pub || enc(digest) || tag
    memcpy(out_cipher, eph_pub, 133);
    uint8_t *enc = out_cipher + 133;
    memcpy(enc, digest32, 32);
    bedrock_aead256_encipher(&aead, 32, enc);
    uint8_t *tag = out_cipher + 133 + 32;
    bedrock_aead256_entag(&aead, tag);
    bedrock_aead256_fini(&aead);
    secure_bzero(xbe, sizeof(xbe));
    return 1;
}

int bedrock_p521_decrypt_digest256(uint8_t out_digest32[32],
                                   const uint8_t in_cipher[133 + 32 + 32],
                                   const uint8_t recipient_priv[66]) {
    const uint8_t *eph_pub = in_cipher;
    const uint8_t *enc = in_cipher + 133;
    const uint8_t *tag = in_cipher + 133 + 32;
    // Load priv
    bedrock_p521_scalar d;
    bedrock_p521_scalar_from_bytes(&d, recipient_priv);
    // ECDH with ephemeral pub
    uint8_t xbe[66];
    if (!p521_ecdh_x_be66(xbe, eph_pub, &d)) return 0;
    // AEAD derive same key
    uint8_t label[] = "Bedrock-ECIES-P521-256";
    struct bedrock_aead256_struct aead;
    bedrock_aead256_init(&aead, sizeof(label), label);
    bedrock_aead256_declear(&aead, 133, eph_pub);
    bedrock_aead256_declear(&aead, 66, xbe);
    // Verify tag
    if (bedrock_aead256_detag(&aead, 32, tag) != 32) { bedrock_aead256_fini(&aead); secure_bzero(xbe, sizeof(xbe)); return 0; }
    // Decrypt
    memcpy(out_digest32, enc, 32);
    bedrock_aead256_decipher(&aead, 32, out_digest32);
    bedrock_aead256_fini(&aead);
    secure_bzero(xbe, sizeof(xbe));
    return 1;
}

int bedrock_p521_encrypt_digest512(uint8_t out_cipher[133 + 64 + 64],
                                   const uint8_t digest64[64],
                                   const uint8_t recipient_pub[133]) {
    uint8_t rnd[66];
    if (!read_urandom(rnd, sizeof(rnd))) return 0;
    bedrock_p521_scalar ke;
    bedrock_p521_scalar_from_random_bytes(&ke, rnd);
    secure_bzero(rnd, sizeof(rnd));
    bedrock_p521_point G, Ke;
    bedrock_p521_get_base(&G);
    bedrock_p521_point_mul(&Ke, &G, &ke);
    uint8_t eph_pub[133];
    bedrock_p521_pub_to_bytes(eph_pub, &Ke);
    uint8_t xbe[66];
    if (!p521_ecdh_x_be66(xbe, recipient_pub, &ke)) return 0;
    uint8_t label[] = "Bedrock-ECIES-P521-512";
    struct bedrock_aead512_struct aead;
    bedrock_aead512_init(&aead, sizeof(label), label);
    bedrock_aead512_enclear(&aead, 133, eph_pub);
    bedrock_aead512_enclear(&aead, 66, xbe);
    memcpy(out_cipher, eph_pub, 133);
    uint8_t *enc = out_cipher + 133;
    memcpy(enc, digest64, 64);
    bedrock_aead512_encipher(&aead, 64, enc);
    uint8_t *tag = out_cipher + 133 + 64;
    bedrock_aead512_entag(&aead, tag);
    bedrock_aead512_fini(&aead);
    secure_bzero(xbe, sizeof(xbe));
    return 1;
}

int bedrock_p521_decrypt_digest512(uint8_t out_digest64[64],
                                   const uint8_t in_cipher[133 + 64 + 64],
                                   const uint8_t recipient_priv[66]) {
    const uint8_t *eph_pub = in_cipher;
    const uint8_t *enc = in_cipher + 133;
    const uint8_t *tag = in_cipher + 133 + 64;
    bedrock_p521_scalar d;
    bedrock_p521_scalar_from_bytes(&d, recipient_priv);
    uint8_t xbe[66];
    if (!p521_ecdh_x_be66(xbe, eph_pub, &d)) return 0;
    uint8_t label[] = "Bedrock-ECIES-P521-512";
    struct bedrock_aead512_struct aead;
    bedrock_aead512_init(&aead, sizeof(label), label);
    bedrock_aead512_declear(&aead, 133, eph_pub);
    bedrock_aead512_declear(&aead, 66, xbe);
    if (bedrock_aead512_detag(&aead, 64, tag) != 64) { bedrock_aead512_fini(&aead); secure_bzero(xbe, sizeof(xbe)); return 0; }
    memcpy(out_digest64, enc, 64);
    bedrock_aead512_decipher(&aead, 64, out_digest64);
    bedrock_aead512_fini(&aead);
    secure_bzero(xbe, sizeof(xbe));
    return 1;
}


