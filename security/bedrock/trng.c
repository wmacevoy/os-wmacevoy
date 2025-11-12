// trng.c  —  public-domain/CC0 style snippet (adjust license as you wish)
#include <stdint.h>
#include <stddef.h>
#include <string.h>


/* ---------- CPU RNG: x86 RDSEED / RDRAND ---------- */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386) || defined(_M_IX86)
#include <immintrin.h>
#include <cpuid.h>

static int have_rdrand(void) {
    unsigned a,b,c,d;
    if (!__get_cpuid(1, &a,&b,&c,&d)) return 0;
    return (c >> 30) & 1; /* ECX.RDRAND */
}
static int have_rdseed(void) {
    unsigned a,b,c,d;
    if (!__get_cpuid_count(7, 0, &a,&b,&c,&d)) return 0;
    return (b >> 18) & 1; /* EBX.RDSEED */
}
static int rdrand64(uint64_t *out) {
    unsigned char ok = 0;
#if defined(__RDRND__)
    ok = _rdrand64_step(out);
#else
    (void)out; ok = 0;
#endif
    return ok ? 0 : -1;
}
static int rdseed64(uint64_t *out) {
    unsigned char ok = 0;
#if defined(__RDSEED__)
    ok = _rdseed64_step(out);
#else
    (void)out; ok = 0;
#endif
    return ok ? 0 : -1;
}
static size_t cpu_rng_x86(void *buf, size_t len) {
    if (!have_rdrand() && !have_rdseed()) return 0;
    uint8_t *p = (uint8_t*)buf;
    size_t need = len, taken = 0;
    uint64_t w;
    int tries;
    /* Prefer RDSEED (raw entropy), else RDRAND (DRBG). */
    while (need >= 8) {
        tries = 16;
        int ok = -1;
        if (have_rdseed()) { while (tries-- && (ok = rdseed64(&w)) != 0) ; }
        if (ok != 0 && have_rdrand()) { tries = 16; while (tries-- && (ok = rdrand64(&w)) != 0) ; }
        if (ok != 0) break;
        memcpy(p, &w, 8);
        p += 8; need -= 8; taken += 8;
    }
    if (need) { /* tail */
        tries = 16;
        int ok = -1;
        if (have_rdseed()) { while (tries-- && (ok = rdseed64(&w)) != 0) ; }
        if (ok != 0 && have_rdrand()) { tries = 16; while (tries-- && (ok = rdrand64(&w)) != 0) ; }
        if (ok == 0) { memcpy(p, &w, need); taken += need; }
    }
    secure_bzero(&w, sizeof w);
    return taken;
}
#else
static size_t cpu_rng_x86(void *buf, size_t len) { (void)buf; (void)len; return 0; }
#endif

/* ---------- CPU RNG: ARM64 RNDR/RNDRRS (Linux) ---------- */
#if defined(__aarch64__)
#include <sys/auxv.h>
#ifndef HWCAP2_RNG
#define HWCAP2_RNG (1 << 16) /* if not defined by headers */
#endif
static int have_rndr(void) {
#ifdef AT_HWCAP2
    unsigned long caps = getauxval(AT_HWCAP2);
    return (caps & HWCAP2_RNG) != 0;
#else
    return 0;
#endif
}
static int read_rndr(uint64_t *out) {
    unsigned long x;
    int ok;
    /* RNDR sets condition flags; we test via C flag through asm. */
    asm volatile(
        "mrs %0, RNDR\n"
        "cset %w1, ne\n"     /* ok=1 if not equal to failure condition */
        : "=r"(x), "=r"(ok)
        :
        : "cc"
    );
    if (ok) { *out = (uint64_t)x; return 0; }
    return -1;
}
static size_t cpu_rng_arm64(void *buf, size_t len) {
    if (!have_rndr()) return 0;
    uint8_t *p = (uint8_t*)buf;
    size_t need = len, taken = 0;
    uint64_t w; int tries;
    while (need >= 8) {
        tries = 16;
        int ok = -1; while (tries-- && (ok = read_rndr(&w)) != 0) ;
        if (ok != 0) break;
        memcpy(p, &w, 8); p += 8; need -= 8; taken += 8;
    }
    if (need) {
        tries = 16; int ok = -1; while (tries-- && (ok = read_rndr(&w)) != 0) ;
        if (ok == 0) { memcpy(p, &w, need); taken += need; }
    }
    secure_bzero(&w, sizeof w);
    return taken;
}
#else
static size_t cpu_rng_arm64(void *buf, size_t len) { (void)buf; (void)len; return 0; }
#endif

/* ---------- OS RNGs ---------- */
static int os_getrandom(void *buf, size_t len) {
#if defined(_WIN32)
    #include <windows.h>
    #include <bcrypt.h>
    NTSTATUS st = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (st == 0) ? 0 : -1;

#elif defined(__APPLE__)
    #include <Security/SecRandom.h>
    return SecRandomCopyBytes(kSecRandomDefault, len, buf) == 0 ? 0 : -1;

#elif defined(__linux__)
    #include <sys/random.h>
    size_t off = 0;
    while (off < len) {
        ssize_t n = getrandom((char*)buf + off, len - off, 0);
        if (n < 0) return -1;
        off += (size_t)n;
    }
    return 0;

#elif defined(__OpenBSD__) || defined(__FreeBSD__)
    #include <unistd.h>
    #if defined(__OpenBSD__)
    if (getentropy(buf, len < 256 ? len : 256) == 0 && len <= 256) return 0;
    #endif
    /* Fallback to /dev/urandom */
    #include <fcntl.h>
    #include <unistd.h>
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0; while (off < len) {
        ssize_t n = read(fd, (char*)buf + off, len - off);
        if (n <= 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#else
    /* Very conservative default: /dev/urandom */
    #include <fcntl.h>
    #include <unistd.h>
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t off = 0; while (off < len) {
        ssize_t n = read(fd, (char*)buf + off, len - off);
        if (n <= 0) { close(fd); return -1; }
        off += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

/* ---------- Public API: gather & mix ---------- */
int trng_getbytes(void *out, size_t len) {
    if (len == 0) return 0;

    /* 1) Start with OS CSPRNG */
    if (os_getrandom(out, len) != 0) return -1;

    /* 2) Try CPU RNG and mix it in (best effort) */
    uint8_t tmp[256];
    size_t take = (len < sizeof tmp) ? len : sizeof tmp;

    size_t k = 0;
    k += cpu_rng_x86(tmp + k, take - k);
    k += cpu_rng_arm64(tmp + k, take - k);

    if (k) {
        /* Replace this with HKDF-SHA512(out = HKDF(out||tmp)) for real use. */
        poor_mix(out, len, tmp, k);
        secure_bzero(tmp, sizeof tmp);
    }
    return 0;
}