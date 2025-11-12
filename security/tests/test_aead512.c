#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

uint8_t buffer[2048];
const char *seed = "secret-512";
const char *hi = "Hello";
const char *who = "World";

size_t encrypt512() {
    struct bedrock_aead512_struct aead;
    bedrock_aead512_init(&aead, strlen(seed), (const uint8_t*)seed);
    size_t at = 0;

    memcpy(buffer + at, hi, strlen(hi) + 1);
    at += bedrock_aead512_declear(&aead, strlen(hi) + 1, buffer + at); // plain, hashed only
    at += bedrock_aead512_enpad(&aead, 64, buffer + at);               // optional middle pad
    at += bedrock_aead512_entag(&aead, buffer + at);                    // middle tag
    memcpy(buffer + at, who, strlen(who) + 1);
    at += bedrock_aead512_encipher(&aead, strlen(who) + 1, buffer + at);// ciphertext
    at += bedrock_aead512_enpad(&aead, 64, buffer + at);                // required final pad
    at += bedrock_aead512_entag(&aead, buffer + at);                    // final tag
    bedrock_aead512_fini(&aead);
    return at;
}

size_t decrypt512() {
    struct bedrock_aead512_struct aead;
    bedrock_aead512_init(&aead, strlen(seed), (const uint8_t*)seed);
    size_t at = 0;

    const char *hi0 = (const char *)(buffer + at);
    at += bedrock_aead512_declear(&aead, strlen(hi) + 1, buffer + at);
    size_t p1 = bedrock_aead512_depad(&aead, sizeof(buffer) - at, buffer + at);
    if (!p1) { fprintf(stderr, "first depad failed (512)\n"); bedrock_aead512_fini(&aead); return 0; }
    at += p1;
    size_t t1 = bedrock_aead512_detag(&aead, sizeof(buffer) - at, buffer + at);
    if (t1 != 64) { fprintf(stderr, "first tag failed (512)\n"); bedrock_aead512_fini(&aead); return 0; }
    at += t1;
    const char *who0 = (const char *)(buffer + at);
    at += bedrock_aead512_decipher(&aead, strlen(who) + 1, buffer + at);
    size_t p2 = bedrock_aead512_depad(&aead, sizeof(buffer) - at, buffer + at);
    if (!p2) { fprintf(stderr, "second depad failed (512)\n"); bedrock_aead512_fini(&aead); return 0; }
    at += p2;
    size_t t2 = bedrock_aead512_detag(&aead, sizeof(buffer) - at, buffer + at);
    if (t2 != 64) { fprintf(stderr, "second tag failed (512)\n"); bedrock_aead512_fini(&aead); return 0; }
    at += t2;
    bedrock_aead512_fini(&aead);
    if (strcmp(hi, hi0) == 0 && strcmp(who, who0) == 0) {
        return at;
    }
    return 0;
}

int main(void) {
    encrypt512();
    if (decrypt512()) {
        printf("AEAD512 test passed\n");
        return 0;
    }
    fprintf(stderr, "AEAD512 test FAILED\n");
    return 1;
}


