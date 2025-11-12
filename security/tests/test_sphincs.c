#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

int main(void) {
    uint8_t pk[BEDROCK_SPHINCS_SHA2_128S_PUBLIC_KEY_BYTES];
    uint8_t sk[BEDROCK_SPHINCS_SHA2_128S_SECRET_KEY_BYTES];
    uint8_t sig[BEDROCK_SPHINCS_SHA2_128S_SIGNATURE_BYTES];
    const uint8_t msg[] = "bedrock-sphincs-selftest";
    int ok = bedrock_sphincs_sha2_128s_keypair_random(pk, sk);
    if (!ok) {
        printf("SPHINCS not enabled; skipping\n");
        return 0;
    }
    ok = bedrock_sphincs_sha2_128s_sign_detached(sig, msg, sizeof(msg)-1, pk, sk);
    if (!ok) { fprintf(stderr, "sign failed\n"); return 1; }
    ok = bedrock_sphincs_sha2_128s_verify_detached(sig, msg, sizeof(msg)-1, pk);
    if (!ok) { fprintf(stderr, "verify failed\n"); return 1; }
    printf("SPHINCS test passed\n");
    return 0;
}


