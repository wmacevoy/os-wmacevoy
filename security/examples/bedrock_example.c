#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../bedrock/bedrock.h"

static void hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; ++i) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    bedrock_sha256_struct s256;
    bedrock_sha512_struct s512;
    bedrock_sha256_init(&s256);
    bedrock_sha512_init(&s512);

    uint8_t buf[4096];
    if (argc > 1) {
        const char *msg = argv[1];
        bedrock_sha256_process(&s256, strlen(msg), (const uint8_t*)msg);
        bedrock_sha512_process(&s512, strlen(msg), (const uint8_t*)msg);
    } else {
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
            bedrock_sha256_process(&s256, n, buf);
            bedrock_sha512_process(&s512, n, buf);
        }
    }

    uint8_t d256[32];
    uint8_t d512[64];
    bedrock_sha256_digest(&s256, d256);
    bedrock_sha512_digest(&s512, d512);

    printf("SHA-256: "); hex(d256, 32); printf("\n");
    printf("SHA-512: "); hex(d512, 64); printf("\n");

    bedrock_sha256_fini(&s256);
    bedrock_sha512_fini(&s512);
    return 0;
}


