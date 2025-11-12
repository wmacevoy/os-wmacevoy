#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

uint8_t buffer[1024];
const char *seed = "secret";
const char *hi = "Hello";
const char *who = "World";
struct bedrock_aead256_struct aead;

size_t encrypt256() {
    bedrock_aead256_init(&aead,strlen(seed),seed);
    size_t at = 0;

    strcpy(buffer+at,hi);
    at += bedrock_aead256_enclear(&aead,strlen(hi)+1,buffer+at);
    /* optional pad/digest in middle of stream */
    at += bedrock_aead256_enpad(&aead,32,buffer+at);
    at += bedrock_aead256_entag(&aead,buffer+at);
    strcpy(buffer+at,who);
    at += bedrock_aead256_encipher(&aead,strlen(who)+1,buffer+at);
    /* required pad/digest at end of stream */
    at += bedrock_aead256_enpad(&aead,32,buffer+at);
    at += bedrock_aead256_entag(&aead,buffer+at);
    bedrock_aead256_fini(&aead);
    return at;
}

size_t decrypt256() {
    struct bedrock_aead256_struct aead;
    bedrock_aead256_init(&aead,strlen(seed),seed);
    size_t at = 0;

    const char *hi0 = (const char *)(buffer + at);
    at += bedrock_aead256_declear(&aead,strlen(hi)+1,buffer+at);
    /* optional pad/digest in middle of stream */
    size_t p1 = bedrock_aead256_depad(&aead,sizeof(buffer)-at,buffer+at);
    if (!p1) { fprintf(stderr, "first depad failed\n"); bedrock_aead256_fini(&aead); return 0; }
    at += p1;
    size_t t1 = bedrock_aead256_detag(&aead,sizeof(buffer)-at,buffer+at);
    if (t1 != 32) {
        fprintf(stderr, "first tag failed\n");
        bedrock_aead256_fini(&aead);
        return 0;
    }
    at += t1;
    const char *who0 = (const char *)(buffer + at);
    at += bedrock_aead256_decipher(&aead,strlen(who)+1,buffer+at);
    /* required pad/digest at end of stream */
    size_t p2 = bedrock_aead256_depad(&aead,sizeof(buffer)-at,buffer+at);
    if (!p2) { fprintf(stderr, "second depad failed\n"); bedrock_aead256_fini(&aead); return 0; }
    at += p2;
    size_t t2 = bedrock_aead256_detag(&aead,sizeof(buffer)-at,buffer+at);
    if (t2 != 32) {
        fprintf(stderr, "second tag failed\n");
        bedrock_aead256_fini(&aead);
        return 0;
    }
    at += t2;
    bedrock_aead256_fini(&aead);
    if (strcmp(hi,hi0) == 0 && strcmp(who,who0) == 0) {
        return at;
    }
    return 0;
}


int main(void) {
    encrypt256();
    if (decrypt256()) {
        printf("AEAD test passed\n");
        return 0;
    }
    fprintf(stderr, "AEAD256 test FAILED\n");
    return 1;
}


