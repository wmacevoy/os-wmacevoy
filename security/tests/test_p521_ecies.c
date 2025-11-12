#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

static void make_digest256(uint8_t out[32], const char *msg) {
    bedrock_sha256_struct h;
    bedrock_sha256_init(&h);
    bedrock_sha256_process(&h, strlen(msg), (const uint8_t*)msg);
    bedrock_sha256_digest(&h, out);
    bedrock_sha256_fini(&h);
}

static void make_digest512(uint8_t out[64], const char *msg) {
    bedrock_sha512_struct h;
    bedrock_sha512_init(&h);
    bedrock_sha512_process(&h, strlen(msg), (const uint8_t*)msg);
    bedrock_sha512_digest(&h, out);
    bedrock_sha512_fini(&h);
}

int main(void) {
    uint8_t pub[133], priv[66];
    if (!bedrock_p521_keypair_random(pub, priv)) {
        fprintf(stderr, "p521 keypair failed\n");
        return 1;
    }
    // 256-bit digest
    uint8_t d256[32], c256[133+32+32], p256[32];
    make_digest256(d256, "ecies test message 256");
    if (!bedrock_p521_encrypt_digest256(c256, d256, pub)) {
        fprintf(stderr, "ecies256 encrypt failed\n");
        return 1;
    }
    if (!bedrock_p521_decrypt_digest256(p256, c256, priv)) {
        fprintf(stderr, "ecies256 decrypt failed\n");
        return 1;
    }
    if (memcmp(d256, p256, 32) != 0) {
        fprintf(stderr, "ecies256 mismatch\n");
        return 1;
    }
    // Corrupt tag and ensure failure
    c256[133 + 32] ^= 0x01;
    if (bedrock_p521_decrypt_digest256(p256, c256, priv)) {
        fprintf(stderr, "ecies256 should fail on bad tag\n");
        return 1;
    }
    // 512-bit digest
    uint8_t d512[64], c512[133+64+64], p512[64];
    make_digest512(d512, "ecies test message 512");
    if (!bedrock_p521_encrypt_digest512(c512, d512, pub)) {
        fprintf(stderr, "ecies512 encrypt failed\n");
        return 1;
    }
    if (!bedrock_p521_decrypt_digest512(p512, c512, priv)) {
        fprintf(stderr, "ecies512 decrypt failed\n");
        return 1;
    }
    if (memcmp(d512, p512, 64) != 0) {
        fprintf(stderr, "ecies512 mismatch\n");
        return 1;
    }
    printf("P-521 ECIES tests passed\n");
    return 0;
}


