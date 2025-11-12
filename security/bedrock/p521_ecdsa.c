#include "bedrock.h"
#include "p521_ec.h"
#include "p521_scalar.h"
#include "p521_field.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
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

static void scalar_to_be66(uint8_t be[66], const bedrock_p521_scalar *s) {
    for (int i = 0; i < 66; i++) be[i] = 0;
    for (int i = 0; i < 9; i++) {
        uint64_t limb = s->limb[i];
        for (int b = 0; b < 8; b++) {
            int idx = 66 - 1 - (i*8 + b);
            if (idx >= 0) { be[idx] = (uint8_t)(limb & 0xFF); limb >>= 8; }
        }
    }
}

int bedrock_p521_keypair_random(uint8_t pub[133], uint8_t priv[66]) {
    uint8_t rnd[66];
    if (!read_urandom(rnd, sizeof(rnd))) return 0;
    bedrock_p521_scalar d;
    bedrock_p521_scalar_from_random_bytes(&d, rnd);
    scalar_to_be66(priv, &d);
    // Q = d*G
    bedrock_p521_point G, Q;
    bedrock_p521_get_base(&G);
    bedrock_p521_point_mul(&Q, &G, &d);
    bedrock_p521_pub_to_bytes(pub, &Q);
    secure_bzero(rnd, sizeof(rnd));
    return 1;
}

int bedrock_p521_sign_detached(uint8_t sig[132],
                               const uint8_t *msg, size_t msg_len,
                               const uint8_t pub[133],
                               const uint8_t priv[66]) {
    // Hash message with SHA-512
    uint8_t md[64];
    bedrock_sha512_struct h;
    bedrock_sha512_init(&h);
    bedrock_sha512_process(&h, msg_len, msg);
    bedrock_sha512_digest(&h, md);
    bedrock_sha512_fini(&h);
    // Reduce hash mod n
    bedrock_p521_scalar e;
    bedrock_p521_scalar_reduce_hash64(&e, md);
    // Load private scalar
    bedrock_p521_scalar d;
    bedrock_p521_scalar_from_bytes(&d, priv);
    // Derive public and compare to provided pub
    bedrock_p521_point G, Qchk;
    bedrock_p521_get_base(&G);
    bedrock_p521_point_mul(&Qchk, &G, &d);
    uint8_t chk_pub[133];
    bedrock_p521_pub_to_bytes(chk_pub, &Qchk);
    if (memcmp(chk_pub, pub, 133) != 0) { secure_bzero(md, sizeof(md)); return 0; }
    int ok = 0;
    // Loop until non-zero r,s
    for (;;) {
        uint8_t krnd[66];
        if (!read_urandom(krnd, sizeof(krnd))) break;
        bedrock_p521_scalar k;
        bedrock_p521_scalar_from_random_bytes(&k, krnd);
        // R = k*G
        bedrock_p521_point R;
        bedrock_p521_point_mul(&R, &G, &k);
        bedrock_p521_fe Rx, Ry;
        bedrock_p521_point_to_affine(&Rx, &Ry, &R);
        uint8_t rx_be[66];
        bedrock_p521_fe_to_bytes(rx_be, &Rx);
        bedrock_p521_scalar r, s, tmp;
        bedrock_p521_scalar_from_bytes(&r, rx_be); // r = x_R mod n (from_bytes reduces if >= n)
        if (bedrock_p521_scalar_is_zero(&r)) continue;
        // s = k^{-1} (e + r*d) mod n
        bedrock_p521_scalar rd; bedrock_p521_scalar_mul_mod(&rd, &r, &d);
        bedrock_p521_scalar ed; bedrock_p521_scalar_add_mod(&ed, &e, &rd);
        bedrock_p521_scalar kinv; bedrock_p521_scalar_inv_mod(&kinv, &k);
        bedrock_p521_scalar_mul_mod(&s, &kinv, &ed);
        if (bedrock_p521_scalar_is_zero(&s)) continue;
        // write out r||s
        uint8_t rbe[66], sbe[66];
        scalar_to_be66(rbe, &r);
        scalar_to_be66(sbe, &s);
        memcpy(sig, rbe, 66);
        memcpy(sig + 66, sbe, 66);
        ok = 1;
        secure_bzero(krnd, sizeof(krnd));
        break;
    }
    secure_bzero(md, sizeof(md));
    if (!ok) secure_bzero(sig, 132);
    return ok;
}

int bedrock_p521_verify_detached(const uint8_t sig[132],
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t pub[133]) {
    // parse pub
    bedrock_p521_point Q;
    if (!bedrock_p521_pub_from_bytes(&Q, pub)) return 0;
    // parse r,s
    bedrock_p521_scalar r, s;
    bedrock_p521_scalar_from_bytes(&r, sig);
    bedrock_p521_scalar_from_bytes(&s, sig + 66);
    if (bedrock_p521_scalar_is_zero(&r) || bedrock_p521_scalar_is_zero(&s)) return 0;
    // hash
    uint8_t md[64];
    bedrock_sha512_struct h;
    bedrock_sha512_init(&h);
    bedrock_sha512_process(&h, msg_len, msg);
    bedrock_sha512_digest(&h, md);
    bedrock_sha512_fini(&h);
    bedrock_p521_scalar e;
    bedrock_p521_scalar_reduce_hash64(&e, md);
    // w = s^{-1}
    bedrock_p521_scalar w; bedrock_p521_scalar_inv_mod(&w, &s);
    bedrock_p521_scalar u1, u2;
    bedrock_p521_scalar_mul_mod(&u1, &e, &w);
    bedrock_p521_scalar_mul_mod(&u2, &r, &w);
    // P = u1*G + u2*Q
    bedrock_p521_point G, P1, P2, P;
    bedrock_p521_get_base(&G);
    bedrock_p521_point_mul(&P1, &G, &u1);
    bedrock_p521_point_mul(&P2, &Q, &u2);
    bedrock_p521_point_add(&P, &P1, &P2);
    if (bedrock_p521_point_is_inf(&P)) { secure_bzero(md, sizeof(md)); return 0; }
    bedrock_p521_fe X, Y;
    bedrock_p521_point_to_affine(&X, &Y, &P);
    uint8_t xbe[66];
    bedrock_p521_fe_to_bytes(xbe, &X);
    bedrock_p521_scalar xmodn;
    bedrock_p521_scalar_from_bytes(&xmodn, xbe);
    uint8_t rbe[66], xbe2[66];
    bedrock_p521_scalar_to_bytes(rbe, &r);
    bedrock_p521_scalar_to_bytes(xbe2, &xmodn);
    secure_bzero(md, sizeof(md));
    return memcmp(rbe, xbe2, 66) == 0 ? 1 : 0;
}
