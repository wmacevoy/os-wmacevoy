#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "../bedrock/bedrock.h"

static void tohex(const uint8_t *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i*2]   = hex[in[i] >> 4];
        out[i*2+1] = hex[in[i] & 0xf];
    }
    out[len*2] = '\0';
}

static int test_case(const char *name, const char *msg,
                     const char *expect256, const char *expect512) {
    bedrock_sha256_struct s256; bedrock_sha512_struct s512;
    bedrock_sha256_init(&s256); bedrock_sha512_init(&s512);
    bedrock_sha256_process(&s256, strlen(msg), (const uint8_t*)msg);
    bedrock_sha512_process(&s512, strlen(msg), (const uint8_t*)msg);
    uint8_t d256[32]; uint8_t d512[64];
    bedrock_sha256_digest(&s256, d256);
    bedrock_sha512_digest(&s512, d512);
    char h256[65]; char h512[129];
    tohex(d256, 32, h256); tohex(d512, 64, h512);
    int ok = (strcmp(h256, expect256) == 0) && (strcmp(h512, expect512) == 0);
    if (!ok) {
        fprintf(stderr, "%s FAILED\n  got256=%s\n  exp256=%s\n  got512=%s\n  exp512=%s\n",
                name, h256, expect256, h512, expect512);
    }
    bedrock_sha256_fini(&s256); bedrock_sha512_fini(&s512);
    return ok ? 0 : 1;
}

int main(void) {
    int fails = 0;
    // From FIPS 180-4
    fails += test_case("empty",
        "",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");

    fails += test_case("abc",
        "abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

    if (fails) {
        fprintf(stderr, "%d test(s) failed\n", fails);
        return 1;
    }
    printf("All tests passed\n");
    return 0;
}


