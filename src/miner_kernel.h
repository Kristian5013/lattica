// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// Lattica SHA3-256d OpenCL kernel source, embedded so lattica-miner-gpu is a single
// self-contained binary (no external .cl to ship or lose). One proof-of-work
// attempt is SHA3-256(SHA3-256(80-byte header)) — NIST FIPS 202, domain pad 0x06 —
// exactly the node's CBlockHeader::GetPoWHash(). Portable across NVIDIA/AMD/Intel.

#ifndef LATTICA_MINER_KERNEL_H
#define LATTICA_MINER_KERNEL_H

inline constexpr const char* SHA3D_CL_SOURCE = R"CLSRC(
inline ulong rotl64(ulong x, uint n) { return (x << n) | (x >> (64 - n)); }

// Keccak-f[1600], fully unrolled with literal lane indices (keeps the 25 lanes in
// registers). Same rho/pi schedule + round constants as the reference; the host
// self-test against the FIPS-202 vectors proves it byte-for-byte.
#define KR(RC) \
  C0=s[0]^s[5]^s[10]^s[15]^s[20]; C1=s[1]^s[6]^s[11]^s[16]^s[21]; \
  C2=s[2]^s[7]^s[12]^s[17]^s[22]; C3=s[3]^s[8]^s[13]^s[18]^s[23]; \
  C4=s[4]^s[9]^s[14]^s[19]^s[24]; \
  D0=C4^rotl64(C1,1); D1=C0^rotl64(C2,1); D2=C1^rotl64(C3,1); D3=C2^rotl64(C4,1); D4=C3^rotl64(C0,1); \
  s[0]^=D0; s[5]^=D0; s[10]^=D0; s[15]^=D0; s[20]^=D0; \
  s[1]^=D1; s[6]^=D1; s[11]^=D1; s[16]^=D1; s[21]^=D1; \
  s[2]^=D2; s[7]^=D2; s[12]^=D2; s[17]^=D2; s[22]^=D2; \
  s[3]^=D3; s[8]^=D3; s[13]^=D3; s[18]^=D3; s[23]^=D3; \
  s[4]^=D4; s[9]^=D4; s[14]^=D4; s[19]^=D4; s[24]^=D4; \
  t=s[1]; \
  b0=s[10]; s[10]=rotl64(t,1);  t=b0; b0=s[7];  s[7]=rotl64(t,3);  t=b0; \
  b0=s[11]; s[11]=rotl64(t,6);  t=b0; b0=s[17]; s[17]=rotl64(t,10); t=b0; \
  b0=s[18]; s[18]=rotl64(t,15); t=b0; b0=s[3];  s[3]=rotl64(t,21); t=b0; \
  b0=s[5];  s[5]=rotl64(t,28);  t=b0; b0=s[16]; s[16]=rotl64(t,36); t=b0; \
  b0=s[8];  s[8]=rotl64(t,45);  t=b0; b0=s[21]; s[21]=rotl64(t,55); t=b0; \
  b0=s[24]; s[24]=rotl64(t,2);  t=b0; b0=s[4];  s[4]=rotl64(t,14); t=b0; \
  b0=s[15]; s[15]=rotl64(t,27); t=b0; b0=s[23]; s[23]=rotl64(t,41); t=b0; \
  b0=s[19]; s[19]=rotl64(t,56); t=b0; b0=s[13]; s[13]=rotl64(t,8);  t=b0; \
  b0=s[12]; s[12]=rotl64(t,25); t=b0; b0=s[2];  s[2]=rotl64(t,43); t=b0; \
  b0=s[20]; s[20]=rotl64(t,62); t=b0; b0=s[14]; s[14]=rotl64(t,18); t=b0; \
  b0=s[22]; s[22]=rotl64(t,39); t=b0; b0=s[9];  s[9]=rotl64(t,61); t=b0; \
  b0=s[6];  s[6]=rotl64(t,20);  t=b0; b0=s[1];  s[1]=rotl64(t,44); t=b0; \
  b0=s[0]; b1=s[1]; b2=s[2]; b3=s[3]; b4=s[4]; \
  s[0]=b0^((~b1)&b2); s[1]=b1^((~b2)&b3); s[2]=b2^((~b3)&b4); s[3]=b3^((~b4)&b0); s[4]=b4^((~b0)&b1); \
  b0=s[5]; b1=s[6]; b2=s[7]; b3=s[8]; b4=s[9]; \
  s[5]=b0^((~b1)&b2); s[6]=b1^((~b2)&b3); s[7]=b2^((~b3)&b4); s[8]=b3^((~b4)&b0); s[9]=b4^((~b0)&b1); \
  b0=s[10]; b1=s[11]; b2=s[12]; b3=s[13]; b4=s[14]; \
  s[10]=b0^((~b1)&b2); s[11]=b1^((~b2)&b3); s[12]=b2^((~b3)&b4); s[13]=b3^((~b4)&b0); s[14]=b4^((~b0)&b1); \
  b0=s[15]; b1=s[16]; b2=s[17]; b3=s[18]; b4=s[19]; \
  s[15]=b0^((~b1)&b2); s[16]=b1^((~b2)&b3); s[17]=b2^((~b3)&b4); s[18]=b3^((~b4)&b0); s[19]=b4^((~b0)&b1); \
  b0=s[20]; b1=s[21]; b2=s[22]; b3=s[23]; b4=s[24]; \
  s[20]=b0^((~b1)&b2); s[21]=b1^((~b2)&b3); s[22]=b2^((~b3)&b4); s[23]=b3^((~b4)&b0); s[24]=b4^((~b0)&b1); \
  s[0]^=(RC);

inline void keccakf(ulong *s)
{
    ulong C0, C1, C2, C3, C4, D0, D1, D2, D3, D4, t, b0, b1, b2, b3, b4;
    KR(0x0000000000000001UL) KR(0x0000000000008082UL) KR(0x800000000000808aUL) KR(0x8000000080008000UL)
    KR(0x000000000000808bUL) KR(0x0000000080000001UL) KR(0x8000000080008081UL) KR(0x8000000000008009UL)
    KR(0x000000000000008aUL) KR(0x0000000000000088UL) KR(0x0000000080008009UL) KR(0x000000008000000aUL)
    KR(0x000000008000808bUL) KR(0x800000000000008bUL) KR(0x8000000000008089UL) KR(0x8000000000008003UL)
    KR(0x8000000000008002UL) KR(0x8000000000000080UL) KR(0x000000000000800aUL) KR(0x800000008000000aUL)
    KR(0x8000000080008081UL) KR(0x8000000000008080UL) KR(0x0000000080000001UL) KR(0x8000000080008008UL)
}

// SHA3-256d over the 80-byte header (10 lanes; lane 9's high 32 bits = nNonce).
// Writes the 4 little-endian limbs of the pow value (out[0] = least significant).
inline void sha3d(const ulong h[9], ulong lane9_lo, uint nonce, ulong out[4])
{
    ulong s[25];
    s[0] = h[0]; s[1] = h[1]; s[2] = h[2]; s[3] = h[3]; s[4] = h[4];
    s[5] = h[5]; s[6] = h[6]; s[7] = h[7]; s[8] = h[8];
    s[9] = lane9_lo | ((ulong)nonce << 32);
    s[10] = 0x06UL;
    s[11] = 0; s[12] = 0; s[13] = 0; s[14] = 0; s[15] = 0;
    s[16] = 0x8000000000000000UL;
    s[17] = 0; s[18] = 0; s[19] = 0; s[20] = 0; s[21] = 0; s[22] = 0; s[23] = 0; s[24] = 0;
    keccakf(s);

    ulong a = s[0], b = s[1], c = s[2], d = s[3];
    s[0] = a; s[1] = b; s[2] = c; s[3] = d;
    s[4] = 0x06UL;
    s[5] = 0; s[6] = 0; s[7] = 0; s[8] = 0; s[9] = 0; s[10] = 0; s[11] = 0; s[12] = 0;
    s[13] = 0; s[14] = 0; s[15] = 0;
    s[16] = 0x8000000000000000UL;
    s[17] = 0; s[18] = 0; s[19] = 0; s[20] = 0; s[21] = 0; s[22] = 0; s[23] = 0; s[24] = 0;
    keccakf(s);

    out[0] = s[0]; out[1] = s[1]; out[2] = s[2]; out[3] = s[3];
}

inline void sha3_256_small(const uchar *msg, int len, __global uchar *dst)
{
    uchar buf[136];
    for (int i = 0; i < len; ++i) buf[i] = msg[i];
    for (int i = len; i < 136; ++i) buf[i] = 0;
    buf[len] ^= 0x06;
    buf[135] ^= 0x80;
    ulong s[25];
    for (int i = 0; i < 25; ++i) s[i] = 0;
    for (int i = 0; i < 17; ++i) {
        ulong lane = 0;
        for (int b = 0; b < 8; ++b) lane |= ((ulong)buf[8 * i + b]) << (8 * b);
        s[i] ^= lane;
    }
    keccakf(s);
    for (int i = 0; i < 4; ++i)
        for (int b = 0; b < 8; ++b) dst[8 * i + b] = (uchar)(s[i] >> (8 * b));
}

__kernel void selftest(__global uchar *out)
{
    uchar empty[1];
    sha3_256_small(empty, 0, out);
    uchar abc[3] = {'a', 'b', 'c'};
    sha3_256_small(abc, 3, out + 32);
}

__kernel void bench(__constant ulong *hdr, ulong nonce_base, uint iters, __global ulong *sink)
{
    const size_t gid = get_global_id(0);
    ulong h[9];
    for (int i = 0; i < 9; ++i) h[i] = hdr[i];
    const ulong lane9_lo = hdr[9] & 0x00000000FFFFFFFFUL;
    ulong acc = 0;
    uint nonce = (uint)(nonce_base + (ulong)gid * iters);
    for (uint k = 0; k < iters; ++k, ++nonce) {
        ulong out[4];
        sha3d(h, lane9_lo, nonce, out);
        acc ^= out[0] ^ out[3];
    }
    sink[gid] = acc;
}

// Keep the smallest nonce whose SHA3-256d is at or under `target`
// (4 little-endian limbs, target[0] = least significant).
__kernel void mine(__constant ulong *hdr, __constant ulong *target,
                   ulong nonce_base, uint iters, __global uint *found)
{
    const size_t gid = get_global_id(0);
    ulong h[9];
    for (int i = 0; i < 9; ++i) h[i] = hdr[i];
    const ulong lane9_lo = hdr[9] & 0x00000000FFFFFFFFUL;
    const ulong t0 = target[0], t1 = target[1], t2 = target[2], t3 = target[3];
    uint nonce = (uint)(nonce_base + (ulong)gid * iters);
    for (uint k = 0; k < iters; ++k, ++nonce) {
        ulong out[4];
        sha3d(h, lane9_lo, nonce, out);
        bool ok;
        if (out[3] != t3)      ok = out[3] < t3;
        else if (out[2] != t2) ok = out[2] < t2;
        else if (out[1] != t1) ok = out[1] < t1;
        else                   ok = out[0] <= t0;
        if (ok) atomic_min(found, nonce);
    }
}
)CLSRC";

#endif // LATTICA_MINER_KERNEL_H
