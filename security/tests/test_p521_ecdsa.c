#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

int main(void) {
    uint8_t pub[133], priv[66], sig[132];
    const char *msg = "p521 ecdsa test message";
    if (!bedrock_p521_keypair_random(pub, priv)) {
        printf("P-521 ECDSA unsupported in this build (no OpenSSL); skipping\n");
        return 0;
    }
    if (!bedrock_p521_sign_detached(sig, (const uint8_t*)msg, strlen(msg), pub, priv)) {
        fprintf(stderr, "p521 sign failed\n");
        return 1;
    }
    if (!bedrock_p521_verify_detached(sig, (const uint8_t*)msg, strlen(msg), pub)) {
        fprintf(stderr, "p521 verify failed\n");
        return 1;
    }
    // Corrupt signature and ensure verification fails
    sig[0] ^= 0x01;
    if (bedrock_p521_verify_detached(sig, (const uint8_t*)msg, strlen(msg), pub)) {
        fprintf(stderr, "p521 verify should have failed on corrupted signature\n");
        return 1;
    }
    printf("P-521 ECDSA tests passed\n");
    return 0;
}


