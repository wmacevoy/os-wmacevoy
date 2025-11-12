#include "bedrock.h"
#include <string.h>

#if defined(BEDROCK_ENABLE_SPHINCS)
// When enabled, integrate a SPHINCS+ SHA2-128s-simple backend (e.g., PQClean)
// Expected symbols (example):
//   int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
//   int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen,
//       const uint8_t *m, size_t mlen, const uint8_t *sk);
//   int PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen,
//       const uint8_t *m, size_t mlen, const uint8_t *pk);
// Include the vendor headers here when added.
// #include "third_party/pqclean/sphincs-sha2-128s-simple/api.h"

int bedrock_sphincs_sha2_128s_keypair_random(uint8_t pk[32], uint8_t sk[64]) {
    (void)pk; (void)sk; return 0;
}

int bedrock_sphincs_sha2_128s_sign_detached(uint8_t sig[7856],
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t pk[32],
                                            const uint8_t sk[64]) {
    (void)sig; (void)msg; (void)msg_len; (void)pk; (void)sk; return 0;
}

int bedrock_sphincs_sha2_128s_verify_detached(const uint8_t sig[7856],
                                              const uint8_t *msg, size_t msg_len,
                                              const uint8_t pk[32]) {
    (void)sig; (void)msg; (void)msg_len; (void)pk; return 0;
}

#else

int bedrock_sphincs_sha2_128s_keypair_random(uint8_t pk[32], uint8_t sk[64]) {
    (void)pk; (void)sk; return 0;
}

int bedrock_sphincs_sha2_128s_sign_detached(uint8_t sig[7856],
                                            const uint8_t *msg, size_t msg_len,
                                            const uint8_t pk[32],
                                            const uint8_t sk[64]) {
    (void)sig; (void)msg; (void)msg_len; (void)pk; (void)sk; return 0;
}

int bedrock_sphincs_sha2_128s_verify_detached(const uint8_t sig[7856],
                                              const uint8_t *msg, size_t msg_len,
                                              const uint8_t pk[32]) {
    (void)sig; (void)msg; (void)msg_len; (void)pk; return 0;
}

#endif

