#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/sm4.h"

typedef uint8_t u8;
typedef uint32_t u32;

#if defined(__GNUC__) && !defined(STRICT_ALIGNMENT)
typedef size_t size_t_aX __attribute((__aligned__(1)));
#else
typedef size_t size_t_aX;
#endif

#define IS_LITTLE_ENDIAN 1

static uint32_t bswap32(uint32_t x)
{
    return ((x & 0x000000ffU) << 24) |
           ((x & 0x0000ff00U) << 8) |
           ((x & 0x00ff0000U) >> 8) |
           ((x & 0xff000000U) >> 24);
}

#define PUTU32(p, v)                          \
    do {                                      \
        (p)[0] = (u8)((v) >> 24);             \
        (p)[1] = (u8)((v) >> 16);             \
        (p)[2] = (u8)((v) >> 8);              \
        (p)[3] = (u8)(v);                     \
    } while (0)

union u128_u {
    u8 c[16];
    u32 d[4];
    size_t_aX t[16 / sizeof(size_t)];
};

typedef struct {
    union u128_u Yi;
    union u128_u EKi;
} bench_ctx;

typedef void (*block128_f)(const u8 *in, u8 *out, const void *key);

int hw_x86_64_sm4_set_key(const unsigned char *userKey, SM4_KEY *key);
void hw_x86_64_sm4_encrypt(const unsigned char *in, unsigned char *out,
    const SM4_KEY *key);
void hw_x86_64_sm4_encrypt256(const unsigned char *in1,
    const unsigned char *in2, unsigned char *out1, unsigned char *out2,
    const SM4_KEY *key);

static uint64_t now_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void init_ctx(bench_ctx *ctx)
{
    size_t i;

    for (i = 0; i < 16; ++i) {
        ctx->Yi.c[i] = (u8)(0xA0 + i);
        ctx->EKi.c[i] = (u8)(0x5A + i);
    }
}

static void run_fast_path(bench_ctx *ctx, const u8 *in, u8 *out, size_t bytes,
    unsigned int ctr, const void *key)
{
    size_t i;
    size_t j = bytes;

    while (j >= 32) {
        size_t_aX *out_t = (size_t_aX *)out;
        const size_t_aX *in_t = (const size_t_aX *)in;
        union {
            u8 c[16];
            size_t_aX t[16 / sizeof(size_t)];
        } EKi2;
        union {
            u32 d[4];
            u8 c[16];
        } Yi2;

        memcpy(Yi2.c, ctx->Yi.c, sizeof(Yi2.c));
        ++ctr;
        if (IS_LITTLE_ENDIAN)
            Yi2.d[3] = bswap32(ctr);
        else
            Yi2.d[3] = ctr;

        hw_x86_64_sm4_encrypt256(ctx->Yi.c, Yi2.c, ctx->EKi.c, EKi2.c, key);

        ++ctr;
        if (IS_LITTLE_ENDIAN)
            ctx->Yi.d[3] = bswap32(ctr);
        else
            ctx->Yi.d[3] = ctr;

        for (i = 0; i < 16 / sizeof(size_t); ++i) {
            out_t[i] = in_t[i] ^ ctx->EKi.t[i];
            out_t[i + 16 / sizeof(size_t)] =
                in_t[i + 16 / sizeof(size_t)] ^ EKi2.t[i];
        }

        out += 32;
        in += 32;
        j -= 32;
    }
}

static void run_ref_path(bench_ctx *ctx, const u8 *in, u8 *out, size_t bytes,
    unsigned int ctr, block128_f block, const void *key)
{
    size_t i;
    size_t j = bytes;

    while (j) {
        size_t_aX *out_t = (size_t_aX *)out;
        const size_t_aX *in_t = (const size_t_aX *)in;

        (*block)(ctx->Yi.c, ctx->EKi.c, key);
        ++ctr;
        if (IS_LITTLE_ENDIAN)
            ctx->Yi.d[3] = bswap32(ctr);
        else
            ctx->Yi.d[3] = ctr;

        for (i = 0; i < 16 / sizeof(size_t); ++i)
            out_t[i] = in_t[i] ^ ctx->EKi.t[i];

        out += 16;
        in += 16;
        j -= 16;
    }
}

static int verify_equal(const u8 *a, const u8 *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

int main(int argc, char **argv)
{
    const size_t default_block_count = 1U << 20; /* 16 MiB payload */
    const size_t blocks = (argc > 1) ? (size_t)strtoull(argv[1], NULL, 10)
                                     : default_block_count;
    const size_t bytes = blocks * 16;
    const size_t rounds = (argc > 2) ? (size_t)strtoull(argv[2], NULL, 10) : 50;

    u8 *in = NULL;
    u8 *out_fast = NULL;
    u8 *out_ref = NULL;
    u8 key[16];
    SM4_KEY ks;
    bench_ctx ctx_fast;
    bench_ctx ctx_ref;
    unsigned int ctr0 = 1;

    uint64_t t1;
    uint64_t t2;
    uint64_t fast_ns;
    uint64_t ref_ns;
    size_t r;

    if ((blocks % 2) != 0) {
        fprintf(stderr, "blocks must be even so bytes are multiples of 32\n");
        return 2;
    }

    for (r = 0; r < sizeof(key); ++r)
        key[r] = (u8)(0x11 * (r + 1));

    if (posix_memalign((void **)&in, 64, bytes) != 0 ||
        posix_memalign((void **)&out_fast, 64, bytes) != 0 ||
        posix_memalign((void **)&out_ref, 64, bytes) != 0) {
        fprintf(stderr, "allocation failed\n");
        free(in);
        free(out_fast);
        free(out_ref);
        return 3;
    }

    if (!hw_x86_64_sm4_set_key(key, &ks)) {
        fprintf(stderr, "hw_x86_64_sm4_set_key failed\n");
        free(in);
        free(out_fast);
        free(out_ref);
        return 5;
    }

    for (r = 0; r < bytes; ++r)
        in[r] = (u8)((r * 131U + 17U) & 0xffU);

    init_ctx(&ctx_fast);
    init_ctx(&ctx_ref);

    run_fast_path(&ctx_fast, in, out_fast, bytes, ctr0, &ks);
    run_ref_path(&ctx_ref, in, out_ref, bytes, ctr0,
        (block128_f)hw_x86_64_sm4_encrypt, &ks);

    if (!verify_equal(out_fast, out_ref, bytes)) {
        fprintf(stderr, "mismatch: fast path output differs from reference path\n");
        free(in);
        free(out_fast);
        free(out_ref);
        return 4;
    }

    init_ctx(&ctx_fast);
    t1 = now_ns();
    for (r = 0; r < rounds; ++r) {
        run_fast_path(&ctx_fast, in, out_fast, bytes, ctr0, &ks);
    }
    t2 = now_ns();
    fast_ns = t2 - t1;

    init_ctx(&ctx_ref);
    t1 = now_ns();
    for (r = 0; r < rounds; ++r) {
        run_ref_path(&ctx_ref, in, out_ref, bytes, ctr0,
            (block128_f)hw_x86_64_sm4_encrypt, &ks);
    }
    t2 = now_ns();
    ref_ns = t2 - t1;

    printf("blocks           : %zu (bytes=%zu)\n", blocks, bytes);
    printf("rounds           : %zu\n", rounds);
    printf("fast_path_ns     : %llu\n", (unsigned long long)fast_ns);
    printf("ref_path_ns      : %llu\n", (unsigned long long)ref_ns);
    printf("fast_throughput  : %.2f MiB/s\n",
        (double)bytes * (double)rounds / (1024.0 * 1024.0) /
            ((double)fast_ns / 1e9));
    printf("ref_throughput   : %.2f MiB/s\n",
        (double)bytes * (double)rounds / (1024.0 * 1024.0) /
            ((double)ref_ns / 1e9));
    printf("speedup          : %.3fx\n", (double)ref_ns / (double)fast_ns);

    free(in);
    free(out_fast);
    free(out_ref);
    return 0;
}
