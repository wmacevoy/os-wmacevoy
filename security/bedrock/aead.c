#include "bedrock.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

void bedrock_aead256_init(struct bedrock_aead256_struct *ctx, size_t unique_key_len, const uint8_t *unique_key) {
    bedrock_sha256_init(&ctx->hash);
    bedrock_sha256_process(&ctx->hash, unique_key_len, unique_key);
    ctx->size = 0;
}

size_t bedrock_aead256_enclear(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 32) == 0) {
            bedrock_sha256_digest(&ctx->hash, ctx->pad);
        }
        bedrock_sha256_process(&ctx->hash, 1, buffer);
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead256_encipher(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 32) == 0) {
            bedrock_sha256_digest(&ctx->hash, ctx->pad);
        }
        bedrock_sha256_process(&ctx->hash, 1, buffer);
        buffer[0] ^= ctx->pad[ctx->size % 32];
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead256_enpad(struct bedrock_aead256_struct *ctx, uint8_t pad_block_size, uint8_t *pad) {
    if (pad_block_size <= 1) {
        return 0;
    }
    size_t new_size = pad_block_size * ((ctx->size / pad_block_size) + 1);
    uint8_t pad_len = (uint8_t)(new_size - ctx->size);
    for (uint8_t i = 0; i < pad_len; ++i) pad[i] = pad_len;
    bedrock_aead256_encipher(ctx, pad_len, pad);
    return pad_len;
}

size_t bedrock_aead256_entag(struct bedrock_aead256_struct *ctx, uint8_t tag[32]) {
    bedrock_sha256_digest(&ctx->hash, tag);
    bedrock_aead256_encipher(ctx, 32, tag);
    return 32;
}

size_t bedrock_aead256_declear(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer) {
    return bedrock_aead256_enclear(ctx, len, buffer);
}

size_t bedrock_aead256_decipher(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 32) == 0) {
            bedrock_sha256_digest(&ctx->hash, ctx->pad);
        }
        buffer[0] ^= ctx->pad[ctx->size % 32];
        bedrock_sha256_process(&ctx->hash, 1, buffer);
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead256_depad(struct bedrock_aead256_struct *ctx, size_t len, uint8_t *buffer) {
    if (len < 1) return 0;
    uint8_t pad[256];
    // Decrypt first byte from input into pad[0]
    pad[0] = buffer[0];
    bedrock_aead256_decipher(ctx, 1, pad);
    uint8_t pad_len = pad[0];
    if (pad_len == 0 || len < pad_len) return 0;
    // Decrypt remaining pad bytes from input
    for (uint8_t i = 1; i < pad_len; ++i) pad[i] = buffer[i];
    if (pad_len > 1) bedrock_aead256_decipher(ctx, (size_t)(pad_len - 1), pad + 1);
    // Validate padding bytes
    for (uint8_t i = 1; i < pad_len; ++i) {
        if (pad[i] != pad_len) return 0;
    }
    return pad_len;
}

size_t bedrock_aead256_detag(struct bedrock_aead256_struct *ctx, size_t len, const uint8_t *buffer) {
    if (len < 32) return 0;
    uint8_t tag[32], check[32];
    bedrock_sha256_digest(&ctx->hash, check);
    memcpy(tag, buffer, 32);
    bedrock_aead256_decipher(ctx, 32, tag);
    if (memcmp(tag, check, 32) != 0) return 0;
    return 32;
}

void bedrock_aead256_fini(struct bedrock_aead256_struct *ctx) {
    bedrock_sha256_fini(&ctx->hash);
    memset(ctx, 0, sizeof(struct bedrock_aead256_struct));
}

void bedrock_aead512_init(struct bedrock_aead512_struct *ctx, size_t unique_key_len, const uint8_t *unique_key) {
    bedrock_sha512_init(&ctx->hash);
    bedrock_sha512_process(&ctx->hash, unique_key_len, unique_key);
    ctx->size = 0;
}

size_t bedrock_aead512_enclear(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 64) == 0) {
            bedrock_sha512_digest(&ctx->hash, ctx->pad);
        }
        bedrock_sha512_process(&ctx->hash, 1, buffer);
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead512_encipher(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 64) == 0) {
            bedrock_sha512_digest(&ctx->hash, ctx->pad);
        }
        bedrock_sha512_process(&ctx->hash, 1, buffer);
        buffer[0] ^= ctx->pad[ctx->size % 64];
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead512_enpad(struct bedrock_aead512_struct *ctx, uint8_t pad_block_size, uint8_t *pad) {
    if (pad_block_size <= 1) {
        return 0;
    }
    size_t new_size = pad_block_size * ((ctx->size / pad_block_size) + 1);
    uint8_t pad_len = (uint8_t)(new_size - ctx->size);
    for (uint8_t i = 0; i < pad_len; ++i) pad[i] = pad_len;
    bedrock_aead512_encipher(ctx, pad_len, pad);
    return pad_len;
}

size_t bedrock_aead512_entag(struct bedrock_aead512_struct *ctx, uint8_t tag[64]) {
    bedrock_sha512_digest(&ctx->hash, tag);
    bedrock_aead512_encipher(ctx, 64, tag);
    return 64;
}

size_t bedrock_aead512_declear(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer) {
    return bedrock_aead512_enclear(ctx, len, buffer);
}

size_t bedrock_aead512_decipher(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer) {
    size_t remaining = len;
    while (remaining > 0) {
        if ((ctx->size % 64) == 0) {
            bedrock_sha512_digest(&ctx->hash, ctx->pad);
        }
        buffer[0] ^= ctx->pad[ctx->size % 64];
        bedrock_sha512_process(&ctx->hash, 1, buffer);
        buffer += 1;
        remaining -= 1;
        ctx->size += 1;
    }
    return len;
}

size_t bedrock_aead512_depad(struct bedrock_aead512_struct *ctx, size_t len, uint8_t *buffer) {
    if (len < 1) return 0;
    uint8_t pad[256];
    pad[0] = buffer[0];
    bedrock_aead512_decipher(ctx, 1, pad);
    uint8_t pad_len = pad[0];
    if (pad_len == 0 || len < pad_len) return 0;
    for (uint8_t i = 1; i < pad_len; ++i) pad[i] = buffer[i];
    if (pad_len > 1) bedrock_aead512_decipher(ctx, (size_t)(pad_len - 1), pad + 1);
    for (uint8_t i = 1; i < pad_len; ++i) {
        if (pad[i] != pad_len) return 0;
    }
    return pad_len;
}

size_t bedrock_aead512_detag(struct bedrock_aead512_struct *ctx, size_t len, const uint8_t *buffer) {
    if (len < 64) return 0;
    uint8_t tag[64], check[64];
    bedrock_sha512_digest(&ctx->hash, check);
    memcpy(tag, buffer, 64);
    bedrock_aead512_decipher(ctx, 64, tag);
    if (memcmp(tag, check, 64) != 0) return 0;
    return 64;
}

void bedrock_aead512_fini(struct bedrock_aead512_struct *ctx) {
    bedrock_sha512_fini(&ctx->hash);
    memset(ctx, 0, sizeof(struct bedrock_aead512_struct));
}


