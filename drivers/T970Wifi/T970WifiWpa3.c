/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 PongWifi contributors
 * All rights reserved.
 *
 * Clean-room WPA3-Personal (SAE Group 19), KDF-SHA256, AES-128-CMAC,
 * and BIP-CMAC-128 (IEEE 802.11w) implementation for PongWifi.
 */
#include "T970WifiWpa3.h"
#include <string.h>

static void put_be32(uint8_t *d, uint32_t v) {
  d[0] = (uint8_t)(v >> 24);
  d[1] = (uint8_t)(v >> 16);
  d[2] = (uint8_t)(v >> 8);
  d[3] = (uint8_t)v;
}

static uint32_t get_be32(const uint8_t *s) {
  return ((uint32_t)s[0] << 24) | ((uint32_t)s[1] << 16) |
         ((uint32_t)s[2] << 8) | (uint32_t)s[3];
}

static void put_le16(uint8_t *d, uint16_t v) {
  d[0] = (uint8_t)v;
  d[1] = (uint8_t)(v >> 8);
}

static uint16_t get_le16(const uint8_t *s) {
  return (uint16_t)s[0] | ((uint16_t)s[1] << 8);
}

static uint32_t ror32(uint32_t x, unsigned n) {
  return (x >> n) | (x << (32u - n));
}

void pw3_ct_zero(void *ptr, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) *p++ = 0;
}

int pw3_ct_memcmp(const void *a, const void *b, size_t len) {
  const volatile uint8_t *pa = (const volatile uint8_t *)a;
  const volatile uint8_t *pb = (const volatile uint8_t *)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) diff |= (uint8_t)(pa[i] ^ pb[i]);
  return diff != 0;
}

/* ---- FIPS 180-4 SHA-256 ---- */

static const uint32_t SHA256_K[64] = {
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

typedef struct {
  uint32_t h[8];
  uint64_t total;
  uint8_t buf[64];
  size_t fill;
} sha256_state;

static void sha256_init(sha256_state *s) {
  static const uint32_t iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
  };
  memcpy(s->h, iv, sizeof(iv));
  s->total = 0;
  s->fill = 0;
}

static void sha256_compress(uint32_t h[8], const uint8_t blk[64]) {
  uint32_t w[64], a, b, c, d, e, f, g, hh;
  for (unsigned i = 0; i < 16; i++) w[i] = get_be32(blk + 4u * i);
  for (unsigned i = 16; i < 64; i++) {
    uint32_t s0 = ror32(w[i - 15], 7) ^ ror32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ror32(w[i - 2], 17) ^ ror32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  a = h[0]; b = h[1]; c = h[2]; d = h[3];
  e = h[4]; f = h[5]; g = h[6]; hh = h[7];
  for (unsigned i = 0; i < 64; i++) {
    uint32_t S1 = ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t t1 = hh + S1 + ch + SHA256_K[i] + w[i];
    uint32_t S0 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + maj;
    hh = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  pw3_ct_zero(w, sizeof(w));
}

static void sha256_update(sha256_state *s, const uint8_t *in, size_t len) {
  if (!len) return;
  s->total += (uint64_t)len;
  if (s->fill && s->fill + len >= 64) {
    size_t take = 64 - s->fill;
    memcpy(s->buf + s->fill, in, take);
    sha256_compress(s->h, s->buf);
    in += take;
    len -= take;
    s->fill = 0;
  }
  while (len >= 64) {
    sha256_compress(s->h, in);
    in += 64;
    len -= 64;
  }
  if (len) {
    memcpy(s->buf + s->fill, in, len);
    s->fill += len;
  }
}

static void sha256_final(sha256_state *s, uint8_t out[32]) {
  uint64_t bits = s->total * 8u;
  uint8_t pad = 0x80;
  sha256_update(s, &pad, 1);
  pad = 0;
  while (s->fill != 56) sha256_update(s, &pad, 1);
  uint8_t lenbe[8];
  put_be32(lenbe, (uint32_t)(bits >> 32));
  put_be32(lenbe + 4, (uint32_t)bits);
  sha256_update(s, lenbe, 8);
  for (unsigned i = 0; i < 8; i++) put_be32(out + 4u * i, s->h[i]);
  pw3_ct_zero(s, sizeof(*s));
}

void pw3_sha256_vec(const uint8_t *const *segs, const size_t *lens,
                    size_t nsegs, uint8_t digest[32]) {
  sha256_state st;
  sha256_init(&st);
  for (size_t i = 0; i < nsegs; i++) {
    if (lens[i]) sha256_update(&st, segs[i], lens[i]);
  }
  sha256_final(&st, digest);
}

void pw3_sha256(const uint8_t *msg, size_t len, uint8_t digest[32]) {
  pw3_sha256_vec(&msg, &len, 1, digest);
}

/* ---- RFC 2104 / 4231 HMAC-SHA256 ---- */

void pw3_hmac_sha256_vec(const uint8_t *key, size_t key_len,
                         const uint8_t *const *segs, const size_t *lens,
                         size_t nsegs, uint8_t mac[32]) {
  uint8_t k0[64], ipad[64], opad[64], inner[32];
  sha256_state st;
  memset(k0, 0, sizeof(k0));
  if (key_len > 64) {
    pw3_sha256(key, key_len, k0);
  } else if (key_len) {
    memcpy(k0, key, key_len);
  }
  for (size_t i = 0; i < 64; i++) {
    ipad[i] = k0[i] ^ 0x36u;
    opad[i] = k0[i] ^ 0x5cu;
  }
  sha256_init(&st);
  sha256_update(&st, ipad, 64);
  for (size_t i = 0; i < nsegs; i++) {
    if (lens[i]) sha256_update(&st, segs[i], lens[i]);
  }
  sha256_final(&st, inner);

  sha256_init(&st);
  sha256_update(&st, opad, 64);
  sha256_update(&st, inner, 32);
  sha256_final(&st, mac);

  pw3_ct_zero(k0, sizeof(k0));
  pw3_ct_zero(ipad, sizeof(ipad));
  pw3_ct_zero(opad, sizeof(opad));
  pw3_ct_zero(inner, sizeof(inner));
}

void pw3_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len, uint8_t mac[32]) {
  pw3_hmac_sha256_vec(key, key_len, &msg, &msg_len, 1, mac);
}

/* ---- RFC 5869 HKDF-SHA256 & IEEE 802.11 KDF-SHA256 ---- */

void pw3_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
  static const uint8_t zero_salt[32] = { 0 };
  if (!salt || !salt_len) {
    salt = zero_salt;
    salt_len = sizeof(zero_salt);
  }
  pw3_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int pw3_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                    size_t info_len, uint8_t *okm, size_t okm_len) {
  uint8_t t[32], ctr = 1;
  size_t pos = 0, tlen = 0;
  if (okm_len > 255u * 32u) return -1;
  while (pos < okm_len) {
    const uint8_t *segs[3] = { t, info, &ctr };
    size_t lens[3] = { tlen, info_len, 1 };
    pw3_hmac_sha256_vec(prk, 32, segs, lens, 3, t);
    tlen = 32;
    size_t take = okm_len - pos;
    if (take > 32) take = 32;
    memcpy(okm + pos, t, take);
    pos += take;
    ctr++;
  }
  pw3_ct_zero(t, sizeof(t));
  return 0;
}

int pw3_kdf_sha256_bits(const uint8_t *key, size_t key_len, const char *label,
                        const uint8_t *ctx, size_t ctx_len,
                        uint8_t *out, size_t out_bits) {
  if (!label || out_bits > 0xffffu) return -1;
  size_t label_len = strlen(label);
  size_t out_bytes = (out_bits + 7u) / 8u;
  uint8_t ctr_le[2], len_le[2], blk[32];
  put_le16(len_le, (uint16_t)out_bits);

  uint16_t ctr = 1;
  size_t pos = 0;
  while (pos < out_bytes) {
    put_le16(ctr_le, ctr++);
    const uint8_t *segs[4] = { ctr_le, (const uint8_t *)label, ctx, len_le };
    size_t lens[4] = { 2, label_len, ctx_len, 2 };
    pw3_hmac_sha256_vec(key, key_len, segs, lens, 4, blk);
    size_t take = out_bytes - pos;
    if (take > 32) take = 32;
    memcpy(out + pos, blk, take);
    pos += take;
  }
  unsigned rem = (unsigned)(out_bits % 8u);
  if (rem && out_bytes) {
    unsigned shift = 8u - rem;
    uint8_t carry = 0;
    for (size_t i = 0; i < out_bytes; i++) {
      uint8_t cur = out[i];
      out[i] = (uint8_t)((cur >> shift) | carry);
      carry = (uint8_t)(cur << rem);
    }
  }
  pw3_ct_zero(blk, sizeof(blk));
  return 0;
}

/* ---- Side-channel-resistant FIPS 197 AES-128 & RFC 4493 CMAC ---- */

static uint8_t gf256_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; i++) {
    uint8_t mask = (uint8_t)(-(b & 1u));
    p ^= (uint8_t)(a & mask);
    uint8_t hi = (uint8_t)(-(a >> 7));
    a = (uint8_t)((a << 1) ^ (0x1bu & hi));
    b >>= 1;
  }
  return p;
}

static uint8_t aes_sbox(uint8_t x) {
  /* Compute multiplicative inverse x^254 in GF(2^8) in constant time. */
  uint8_t x2 = gf256_mul(x, x);
  uint8_t x3 = gf256_mul(x2, x);
  uint8_t x6 = gf256_mul(x3, x3);
  uint8_t x12 = gf256_mul(x6, x6);
  uint8_t x14 = gf256_mul(x12, x2);
  uint8_t x15 = gf256_mul(x12, x3);
  uint8_t x30 = gf256_mul(x15, x15);
  uint8_t x60 = gf256_mul(x30, x30);
  uint8_t x120 = gf256_mul(x60, x60);
  uint8_t x240 = gf256_mul(x120, x120);
  uint8_t inv = gf256_mul(x240, x14);
  uint8_t y = inv;
  for (int i = 1; i <= 4; i++) y ^= (uint8_t)((inv << i) | (inv >> (8 - i)));
  return (uint8_t)(y ^ 0x63u);
}

static void aes128_expand(const uint8_t key[16], uint8_t rk[176]) {
  static const uint8_t rcon[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 27, 54 };
  memcpy(rk, key, 16);
  for (unsigned i = 4; i < 44; i++) {
    uint8_t t[4];
    memcpy(t, rk + 4u * (i - 1u), 4);
    if ((i & 3u) == 0) {
      uint8_t tmp = aes_sbox(t[0]);
      t[0] = (uint8_t)(aes_sbox(t[1]) ^ rcon[(i / 4u) - 1u]);
      t[1] = aes_sbox(t[2]);
      t[2] = aes_sbox(t[3]);
      t[3] = tmp;
    }
    for (unsigned j = 0; j < 4; j++) {
      rk[4u * i + j] = rk[4u * (i - 4u) + j] ^ t[j];
    }
  }
}

static uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ ((x & 0x80u) ? 0x1bu : 0u));
}

static void aes128_encrypt(const uint8_t rk[176], const uint8_t in[16],
                           uint8_t out[16]) {
  uint8_t s[16];
  for (unsigned i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
  for (unsigned r = 1; r <= 10; r++) {
    for (unsigned i = 0; i < 16; i++) s[i] = aes_sbox(s[i]);
    uint8_t t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
    if (r < 10) {
      for (unsigned c = 0; c < 4; c++) {
        uint8_t a0 = s[4u * c], a1 = s[4u * c + 1u];
        uint8_t a2 = s[4u * c + 2u], a3 = s[4u * c + 3u];
        uint8_t sum = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
        s[4u * c]      ^= sum ^ xtime((uint8_t)(a0 ^ a1));
        s[4u * c + 1u] ^= sum ^ xtime((uint8_t)(a1 ^ a2));
        s[4u * c + 2u] ^= sum ^ xtime((uint8_t)(a2 ^ a3));
        s[4u * c + 3u] ^= sum ^ xtime((uint8_t)(a3 ^ a0));
      }
    }
    for (unsigned i = 0; i < 16; i++) s[i] ^= rk[16u * r + i];
  }
  memcpy(out, s, 16);
  pw3_ct_zero(s, sizeof(s));
}

static void cmac_subkey(const uint8_t in[16], uint8_t out[16]) {
  uint8_t carry = 0;
  for (int i = 15; i >= 0; i--) {
    uint8_t b = in[i];
    out[i] = (uint8_t)((b << 1) | carry);
    carry = (uint8_t)(b >> 7);
  }
  if (in[0] & 0x80u) out[15] ^= 0x87u;
}

void pw3_aes128_cmac_vec(const uint8_t key[16], const uint8_t *const *segs,
                         const size_t *lens, size_t nsegs, uint8_t mac[16]) {
  uint8_t rk[176], L[16], K1[16], K2[16], x[16], blk[16];
  size_t total = 0, fill = 0;
  aes128_expand(key, rk);
  memset(blk, 0, 16);
  aes128_encrypt(rk, blk, L);
  cmac_subkey(L, K1);
  cmac_subkey(K1, K2);

  for (size_t i = 0; i < nsegs; i++) total += lens[i];
  memset(x, 0, 16);
  size_t seen = 0;
  for (size_t s = 0; s < nsegs; s++) {
    const uint8_t *p = segs[s];
    size_t n = lens[s];
    while (n > 0) {
      size_t take = 16u - fill;
      if (take > n) take = n;
      memcpy(blk + fill, p, take);
      fill += take;
      p += take;
      n -= take;
      seen += take;
      if (fill == 16 && seen < total) {
        for (int i = 0; i < 16; i++) x[i] ^= blk[i];
        aes128_encrypt(rk, x, x);
        fill = 0;
      }
    }
  }

  if (total > 0 && fill == 16) {
    for (int i = 0; i < 16; i++) blk[i] ^= K1[i];
  } else {
    blk[fill] = 0x80u;
    for (size_t i = fill + 1u; i < 16; i++) blk[i] = 0;
    for (int i = 0; i < 16; i++) blk[i] ^= K2[i];
  }
  for (int i = 0; i < 16; i++) x[i] ^= blk[i];
  aes128_encrypt(rk, x, mac);

  pw3_ct_zero(rk, sizeof(rk));
  pw3_ct_zero(L, sizeof(L));
  pw3_ct_zero(K1, sizeof(K1));
  pw3_ct_zero(K2, sizeof(K2));
  pw3_ct_zero(x, sizeof(x));
  pw3_ct_zero(blk, sizeof(blk));
}

void pw3_aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
                     uint8_t mac[16]) {
  pw3_aes128_cmac_vec(key, &msg, &len, 1, mac);
}

int pw3_bip_cmac128_verify(const uint8_t igtk[16], uint16_t expected_keyid,
                           uint8_t rx_pn_be[6], const uint8_t *frame,
                           size_t frame_len) {
  static const uint8_t zero8[8] = { 0 };
  if (frame_len < 24u + 18u) return -1;
  const uint8_t *mmie = frame + frame_len - 18u;
  if (mmie[0] != 76u || mmie[1] != 16u) return -1;
  if (get_le16(mmie + 2) != expected_keyid) return -1;

  uint8_t ipn[6];
  for (int i = 0; i < 6; i++) ipn[i] = mmie[4 + (5 - i)];
  if (memcmp(ipn, rx_pn_be, 6) <= 0) return -2;

  uint8_t aad[20];
  aad[0] = frame[0];
  aad[1] = (uint8_t)(frame[1] & (uint8_t)~0x38u);
  memcpy(aad + 2, frame + 4, 18);

  uint8_t mac[16];
  const uint8_t *segs[4];
  size_t lens[4];
  size_t nsegs;
  if ((frame[0] & 0xfcu) == 0x80u && frame_len >= 24u + 8u + 18u) {
    segs[0] = aad; lens[0] = 20;
    segs[1] = zero8; lens[1] = 8;
    segs[2] = frame + 32; lens[2] = frame_len - 32u - 8u;
    segs[3] = zero8; lens[3] = 8;
    nsegs = 4;
  } else {
    segs[0] = aad; lens[0] = 20;
    segs[1] = frame + 24; lens[1] = frame_len - 24u - 8u;
    segs[2] = zero8; lens[2] = 8;
    nsegs = 3;
  }
  pw3_aes128_cmac_vec(igtk, segs, lens, nsegs, mac);
  int bad = pw3_ct_memcmp(mac, mmie + 10, 8);
  pw3_ct_zero(mac, sizeof(mac));
  if (bad) return -3;
  memcpy(rx_pn_be, ipn, 6);
  return 0;
}

/* ---- NIST P-256 (secp256r1) 256-bit arithmetic & complete EC math ---- */

typedef struct {
  uint32_t v[8];
} u256;

typedef struct {
  u256 x, y, z;
} ec_proj;

static const u256 P256_P = {
  { 0xffffffffu, 0xffffffffu, 0xffffffffu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu }
};
static const uint8_t P256_P_BE[32] = {
  0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
  0x00,0x00,0x00,0x00, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff
};
static const u256 P256_R = {
  { 0xfc632551u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
    0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu }
};
static const u256 P256_RM1 = {
  { 0xfc632550u, 0xf3b9cac2u, 0xa7179e84u, 0xbce6faadu,
    0xffffffffu, 0xffffffffu, 0x00000000u, 0xffffffffu }
};
static const u256 P256_P_M2 = {
  { 0xfffffffdu, 0xffffffffu, 0xffffffffu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xffffffffu }
};
static const u256 P256_P_P1D4 = {
  { 0x00000000u, 0x00000000u, 0x40000000u, 0x00000000u,
    0x00000000u, 0x40000000u, 0xc0000000u, 0x3fffffffu }
};
static const u256 P256_ONE_MONT = {
  { 0x00000001u, 0x00000000u, 0x00000000u, 0xffffffffu,
    0xffffffffu, 0xffffffffu, 0xfffffffeu, 0x00000000u }
};
static const u256 P256_R2 = {
  { 0x00000003u, 0x00000000u, 0xffffffffu, 0xfffffffbu,
    0xfffffffeu, 0xffffffffu, 0xfffffffdu, 0x00000004u }
};
static const u256 P256_B_MONT = {
  { 0x29c4bddfu, 0xd89cdf62u, 0x78843090u, 0xacf005cdu,
    0xf7212ed6u, 0xe5a220abu, 0x04874834u, 0xdc30061du }
};
static const u256 P256_AM3_MONT = {
  { 0xfffffffcu, 0xffffffffu, 0xffffffffu, 0x00000003u,
    0x00000000u, 0x00000000u, 0x00000004u, 0xfffffffcu }
};
static const u256 P256_ZM10_MONT = {
  { 0xfffffff5u, 0xffffffffu, 0xffffffffu, 0x0000000au,
    0x00000000u, 0x00000000u, 0x0000000bu, 0xfffffff5u }
};
static const u256 P256_SSWU_C1_MONT = {
  { 0x6341949fu, 0x9d899fcbu, 0x7d816585u, 0x8efaac9au,
    0xa7b5ba47u, 0xa1e0b58eu, 0x01826d67u, 0xf4100209u }
};
static const u256 P256_SSWU_C2_MONT = {
  { 0xf0535ba9u, 0x5c8dc32du, 0x8c8cf08du, 0xc17f77a9u,
    0x43f892a0u, 0x7696788eu, 0x99c03e24u, 0x98680033u }
};
static const u256 U256_ONE = { { 1, 0, 0, 0, 0, 0, 0, 0 } };
static const u256 U256_ZERO = { { 0, 0, 0, 0, 0, 0, 0, 0 } };

static void u256_from_be(u256 *a, const uint8_t be[32]) {
  for (int i = 0; i < 8; i++) a->v[7 - i] = get_be32(be + 4 * i);
}

static void u256_to_be(const u256 *a, uint8_t be[32]) {
  for (int i = 0; i < 8; i++) put_be32(be + 4 * i, a->v[7 - i]);
}

static uint32_t u256_is_zero(const u256 *a) {
  uint32_t x = 0;
  for (int i = 0; i < 8; i++) x |= a->v[i];
  return (uint32_t)(((x | (0u - x)) >> 31) ^ 1u);
}

static uint32_t u256_add_raw(u256 *r, const u256 *a, const u256 *b) {
  uint64_t c = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t s = (uint64_t)a->v[i] + b->v[i] + c;
    r->v[i] = (uint32_t)s;
    c = s >> 32;
  }
  return (uint32_t)c;
}

static uint32_t u256_sub_raw(u256 *r, const u256 *a, const u256 *b) {
  uint64_t bw = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t d = (uint64_t)a->v[i] - b->v[i] - bw;
    r->v[i] = (uint32_t)d;
    bw = (d >> 63) & 1u;
  }
  return (uint32_t)bw;
}

static uint32_t u256_gte(const u256 *a, const u256 *b) {
  u256 t;
  return 1u - u256_sub_raw(&t, a, b);
}

static void u256_cmov(u256 *r, const u256 *a, uint32_t cond) {
  uint32_t m = 0u - (cond & 1u);
  for (int i = 0; i < 8; i++) {
    r->v[i] = (r->v[i] & ~m) | (a->v[i] & m);
  }
}

static void ec_proj_cmov(ec_proj *r, const ec_proj *a, uint32_t cond) {
  u256_cmov(&r->x, &a->x, cond);
  u256_cmov(&r->y, &a->y, cond);
  u256_cmov(&r->z, &a->z, cond);
}

static void mod_add(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
  u256 t, t2;
  uint32_t c = u256_add_raw(&t, a, b);
  uint32_t bw = u256_sub_raw(&t2, &t, m);
  u256_cmov(&t, &t2, c | (1u - bw));
  *r = t;
}

static void mod_sub(u256 *r, const u256 *a, const u256 *b, const u256 *m) {
  u256 t, t2;
  uint32_t bw = u256_sub_raw(&t, a, b);
  u256_add_raw(&t2, &t, m);
  u256_cmov(&t, &t2, bw);
  *r = t;
}

static void bytes_mod(const uint8_t *be, size_t nbytes, const u256 *m,
                      u256 *out) {
  u256 acc = U256_ZERO, sub;
  for (size_t i = 0; i < nbytes; i++) {
    uint8_t byte = be[i];
    for (int b = 7; b >= 0; b--) {
      uint32_t carry = acc.v[7] >> 31;
      for (int k = 7; k > 0; k--) {
        acc.v[k] = (acc.v[k] << 1) | (acc.v[k - 1] >> 31);
      }
      acc.v[0] = (acc.v[0] << 1) | ((uint32_t)(byte >> b) & 1u);
      uint32_t bw = u256_sub_raw(&sub, &acc, m);
      u256_cmov(&acc, &sub, carry | (1u - bw));
    }
  }
  *out = acc;
}

static void fp_add(u256 *r, const u256 *a, const u256 *b) {
  mod_add(r, a, b, &P256_P);
}

static void fp_sub(u256 *r, const u256 *a, const u256 *b) {
  mod_sub(r, a, b, &P256_P);
}

static void fp_mont_mul(u256 *r, const u256 *a, const u256 *b) {
  uint32_t t[10] = { 0 };
  for (int i = 0; i < 8; i++) {
    uint64_t c = 0;
    for (int j = 0; j < 8; j++) {
      uint64_t uv = (uint64_t)t[j] + (uint64_t)a->v[j] * b->v[i] + c;
      t[j] = (uint32_t)uv;
      c = uv >> 32;
    }
    uint64_t uv = (uint64_t)t[8] + c;
    t[8] = (uint32_t)uv;
    t[9] = (uint32_t)(uv >> 32);

    /* -P256_P[0]^(-1) mod 2^32 == 1 because P256_P[0] == 0xffffffff */
    uint32_t q = t[0];
    uv = (uint64_t)t[0] + (uint64_t)q * P256_P.v[0];
    c = uv >> 32;
    for (int j = 1; j < 8; j++) {
      uv = (uint64_t)t[j] + (uint64_t)q * P256_P.v[j] + c;
      t[j - 1] = (uint32_t)uv;
      c = uv >> 32;
    }
    uv = (uint64_t)t[8] + c;
    t[7] = (uint32_t)uv;
    t[8] = (uint32_t)(t[9] + (uv >> 32));
    t[9] = 0;
  }
  u256 res, sub;
  for (int i = 0; i < 8; i++) res.v[i] = t[i];
  uint32_t bw = u256_sub_raw(&sub, &res, &P256_P);
  u256_cmov(&res, &sub, t[8] | (1u - bw));
  *r = res;
}

static void fp_mont_sqr(u256 *r, const u256 *a) {
  fp_mont_mul(r, a, a);
}

static void fp_to_mont(u256 *r, const u256 *a) {
  fp_mont_mul(r, a, &P256_R2);
}

static void fp_from_mont(u256 *r, const u256 *a) {
  fp_mont_mul(r, a, &U256_ONE);
}

static void fp_pow_mont(u256 *r, const u256 *base_m, const u256 *exp) {
  u256 acc = P256_ONE_MONT;
  for (int i = 255; i >= 0; i--) {
    fp_mont_sqr(&acc, &acc);
    u256 prod;
    fp_mont_mul(&prod, &acc, base_m);
    uint32_t bit = (exp->v[i >> 5] >> (i & 31)) & 1u;
    u256_cmov(&acc, &prod, bit);
  }
  *r = acc;
}

static void fp_inv_mont(u256 *r, const u256 *a_m) {
  fp_pow_mont(r, a_m, &P256_P_M2);
}

static void fp_sqrt_mont(u256 *r, const u256 *a_m) {
  fp_pow_mont(r, a_m, &P256_P_P1D4);
}

static uint32_t p256_rhs_mont(u256 *rhs_m, const u256 *x_m) {
  u256 x2, x3, ax;
  fp_mont_sqr(&x2, x_m);
  fp_mont_mul(&x3, &x2, x_m);
  fp_mont_mul(&ax, x_m, &P256_AM3_MONT);
  fp_add(&x3, &x3, &ax);
  fp_add(rhs_m, &x3, &P256_B_MONT);
  return 0;
}

static uint32_t p256_on_curve_aff(const u256 *x, const u256 *y) {
  uint32_t ok = (1u - u256_gte(x, &P256_P)) & (1u - u256_gte(y, &P256_P));
  u256 xm, ym, rhs, y2, diff;
  fp_to_mont(&xm, x);
  fp_to_mont(&ym, y);
  p256_rhs_mont(&rhs, &xm);
  fp_mont_sqr(&y2, &ym);
  fp_sub(&diff, &y2, &rhs);
  return ok & u256_is_zero(&diff) & (1u - (u256_is_zero(x) & u256_is_zero(y)));
}

/* Complete addition formula (Renes-Costello-Batina, a = -3) in Mont coords. */
static void ec_add_proj(ec_proj *out, const ec_proj *p, const ec_proj *q) {
  u256 t0, t1, t2, t3, t4, x3, y3, z3;
  fp_mont_mul(&t0, &p->x, &q->x);
  fp_mont_mul(&t1, &p->y, &q->y);
  fp_mont_mul(&t2, &p->z, &q->z);

  fp_add(&t3, &p->x, &p->y);
  fp_add(&t4, &q->x, &q->y);
  fp_mont_mul(&t3, &t3, &t4);
  fp_add(&t4, &t0, &t1);
  fp_sub(&t3, &t3, &t4);

  fp_add(&t4, &p->y, &p->z);
  fp_add(&x3, &q->y, &q->z);
  fp_mont_mul(&t4, &t4, &x3);
  fp_add(&x3, &t1, &t2);
  fp_sub(&t4, &t4, &x3);

  fp_add(&x3, &p->x, &p->z);
  fp_add(&y3, &q->x, &q->z);
  fp_mont_mul(&x3, &x3, &y3);
  fp_add(&y3, &t0, &t2);
  fp_sub(&y3, &x3, &y3);

  fp_mont_mul(&z3, &P256_B_MONT, &t2);
  fp_sub(&x3, &y3, &z3);
  fp_add(&z3, &x3, &x3);
  fp_add(&x3, &x3, &z3);

  fp_sub(&z3, &t1, &x3);
  fp_add(&x3, &t1, &x3);

  fp_mont_mul(&y3, &P256_B_MONT, &y3);
  fp_add(&t1, &t2, &t2);
  fp_add(&t2, &t1, &t2);
  fp_sub(&y3, &y3, &t2);
  fp_sub(&y3, &y3, &t0);
  fp_add(&t1, &y3, &y3);
  fp_add(&y3, &t1, &y3);

  fp_add(&t1, &t0, &t0);
  fp_add(&t0, &t1, &t0);
  fp_sub(&t0, &t0, &t2);

  fp_mont_mul(&t1, &t4, &y3);
  fp_mont_mul(&t2, &t0, &y3);
  fp_mont_mul(&y3, &x3, &z3);
  fp_add(&y3, &y3, &t2);

  fp_mont_mul(&x3, &t3, &x3);
  fp_sub(&x3, &x3, &t1);

  fp_mont_mul(&z3, &t4, &z3);
  fp_mont_mul(&t1, &t3, &t0);
  fp_add(&z3, &z3, &t1);

  out->x = x3;
  out->y = y3;
  out->z = z3;
}

static void ec_from_aff(ec_proj *r, const u256 *x, const u256 *y) {
  fp_to_mont(&r->x, x);
  fp_to_mont(&r->y, y);
  r->z = P256_ONE_MONT;
}

static int ec_to_aff(const ec_proj *p, u256 *x, u256 *y) {
  if (u256_is_zero(&p->z)) return -1;
  u256 zinv, xm, ym;
  fp_inv_mont(&zinv, &p->z);
  fp_mont_mul(&xm, &p->x, &zinv);
  fp_mont_mul(&ym, &p->y, &zinv);
  fp_from_mont(x, &xm);
  fp_from_mont(y, &ym);
  return 0;
}

static void ec_mul_proj(ec_proj *out, const u256 *k, const ec_proj *base) {
  ec_proj acc = { U256_ZERO, P256_ONE_MONT, U256_ZERO };
  for (int i = 255; i >= 0; i--) {
    ec_add_proj(&acc, &acc, &acc);
    ec_proj added;
    ec_add_proj(&added, &acc, base);
    uint32_t bit = (k->v[i >> 5] >> (i & 31)) & 1u;
    ec_proj_cmov(&acc, &added, bit);
  }
  *out = acc;
}

int pw3_p256_is_on_curve(const uint8_t x[32], const uint8_t y[32]) {
  u256 ax, ay;
  u256_from_be(&ax, x);
  u256_from_be(&ay, y);
  return p256_on_curve_aff(&ax, &ay) ? 1 : 0;
}

int pw3_p256_point_add(const uint8_t ax[32], const uint8_t ay[32],
                       const uint8_t bx[32], const uint8_t by[32],
                       uint8_t rx[32], uint8_t ry[32]) {
  u256 px, py, qx, qy, ox, oy;
  u256_from_be(&px, ax);
  u256_from_be(&py, ay);
  u256_from_be(&qx, bx);
  u256_from_be(&qy, by);
  if (!p256_on_curve_aff(&px, &py) || !p256_on_curve_aff(&qx, &qy)) return -1;
  ec_proj ep, eq, er;
  ec_from_aff(&ep, &px, &py);
  ec_from_aff(&eq, &qx, &qy);
  ec_add_proj(&er, &ep, &eq);
  if (ec_to_aff(&er, &ox, &oy) != 0) return -1;
  u256_to_be(&ox, rx);
  u256_to_be(&oy, ry);
  return 0;
}

int pw3_p256_scalar_mul(const uint8_t k_be[32], const uint8_t px[32],
                        const uint8_t py[32], uint8_t rx[32], uint8_t ry[32]) {
  u256 k, ax, ay, ox, oy;
  u256_from_be(&k, k_be);
  u256_from_be(&ax, px);
  u256_from_be(&ay, py);
  if (!p256_on_curve_aff(&ax, &ay)) return -1;
  ec_proj ep, er;
  ec_from_aff(&ep, &ax, &ay);
  ec_mul_proj(&er, &k, &ep);
  int res = ec_to_aff(&er, &ox, &oy);
  if (res == 0) {
    u256_to_be(&ox, rx);
    u256_to_be(&oy, ry);
  }
  pw3_ct_zero(&k, sizeof(k));
  return res;
}

void pw3_p256_sswu(const uint8_t u_be[32], uint8_t rx[32], uint8_t ry[32]) {
  u256 u, um, u2, tv1, tv2, tv2p1, inv_tv2, x1, x2, gx1, gx2, y1, y2, y1sq, diff;
  u256_from_be(&u, u_be);
  u256 u_mod;
  bytes_mod(u_be, 32, &P256_P, &u_mod);
  fp_to_mont(&um, &u_mod);

  fp_mont_sqr(&u2, &um);
  fp_mont_mul(&tv1, &P256_ZM10_MONT, &u2);
  fp_mont_sqr(&tv2, &tv1);
  fp_add(&tv2, &tv2, &tv1);

  fp_inv_mont(&inv_tv2, &tv2);
  fp_add(&tv2p1, &tv2, &P256_ONE_MONT);
  fp_mont_mul(&x1, &tv2p1, &inv_tv2);
  fp_mont_mul(&x1, &x1, &P256_SSWU_C1_MONT);
  u256_cmov(&x1, &P256_SSWU_C2_MONT, u256_is_zero(&tv2));

  fp_mont_mul(&x2, &tv1, &x1);
  p256_rhs_mont(&gx1, &x1);
  p256_rhs_mont(&gx2, &x2);

  fp_sqrt_mont(&y1, &gx1);
  fp_sqrt_mont(&y2, &gx2);
  fp_mont_sqr(&y1sq, &y1);
  fp_sub(&diff, &y1sq, &gx1);
  uint32_t qr1 = u256_is_zero(&diff);

  u256 xm = x2, ym = y2;
  u256_cmov(&xm, &x1, qr1);
  u256_cmov(&ym, &y1, qr1);

  u256 x_aff, y_aff, ny;
  fp_from_mont(&x_aff, &xm);
  fp_from_mont(&y_aff, &ym);
  u256_sub_raw(&ny, &P256_P, &y_aff);
  uint32_t flip = (u_mod.v[0] ^ y_aff.v[0]) & 1u;
  u256_cmov(&y_aff, &ny, flip);

  u256_to_be(&x_aff, rx);
  u256_to_be(&y_aff, ry);
  (void)u;
}

/* ---- SAE Group 19 Protocol (IEEE 802.11-2020 §12.4) ---- */

static void sae_order_macs(const uint8_t a[6], const uint8_t b[6],
                           uint8_t out[12]) {
  int gt = memcmp(a, b, 6) >= 0;
  memcpy(out, gt ? a : b, 6);
  memcpy(out + 6, gt ? b : a, 6);
}

int pw3_sae_derive_pwe_hnp(pw3_sae_ctx *ctx, const uint8_t sta_mac[6],
                           const uint8_t ap_mac[6], const uint8_t *pass,
                           size_t pass_len) {
  if (!ctx || !pass || !pass_len) return -1;
  uint8_t addrs[12], pwd_seed[32], pwd_val[32];
  sae_order_macs(sta_mac, ap_mac, addrs);

  u256 best_x = U256_ZERO, best_y = U256_ZERO;
  uint32_t found = 0;
  uint8_t ctr = 1;
  for (unsigned step = 1; step <= 255u; step++) {
    if (found && step > 40u) break;
    ctr = (uint8_t)step;
    const uint8_t *segs[2] = { pass, &ctr };
    size_t lens[2] = { pass_len, 1 };
    pw3_hmac_sha256_vec(addrs, 12, segs, lens, 2, pwd_seed);
    pw3_kdf_sha256_bits(pwd_seed, 32, "SAE Hunting and Pecking",
                        P256_P_BE, 32, pwd_val, 256);

    u256 x, xm, rhs, ym, ym2, diff, y, ny;
    u256_from_be(&x, pwd_val);
    uint32_t lt_p = 1u - u256_gte(&x, &P256_P);
    fp_to_mont(&xm, &x);
    p256_rhs_mont(&rhs, &xm);
    fp_sqrt_mont(&ym, &rhs);
    fp_mont_sqr(&ym2, &ym);
    fp_sub(&diff, &ym2, &rhs);
    uint32_t is_qr = u256_is_zero(&diff);
    fp_from_mont(&y, &ym);
    u256_sub_raw(&ny, &P256_P, &y);
    uint32_t flip = (y.v[0] ^ (uint32_t)pwd_seed[31]) & 1u;
    u256_cmov(&y, &ny, flip);

    uint32_t valid = lt_p & is_qr;
    uint32_t take = valid & (1u - found);
    u256_cmov(&best_x, &x, take);
    u256_cmov(&best_y, &y, take);
    found |= valid;
  }

  pw3_ct_zero(pwd_seed, sizeof(pwd_seed));
  pw3_ct_zero(pwd_val, sizeof(pwd_val));
  if (!found) return -1;

  u256_to_be(&best_x, ctx->pwe_x);
  u256_to_be(&best_y, ctx->pwe_y);
  ctx->use_h2e = 0;
  return 0;
}

int pw3_sae_derive_pt_h2e(const uint8_t *ssid, size_t ssid_len,
                          const uint8_t *pass, size_t pass_len,
                          uint8_t pt_x[32], uint8_t pt_y[32]) {
  static const uint8_t info1[] = "SAE Hash to Element u1 P1";
  static const uint8_t info2[] = "SAE Hash to Element u2 P2";
  if (!ssid || !pass || !pass_len) return -1;

  uint8_t pwd_seed[32], pwd_val[48], u_be[32];
  uint8_t p1x[32], p1y[32], p2x[32], p2y[32];
  u256 u;

  pw3_hkdf_extract(ssid, ssid_len, pass, pass_len, pwd_seed);

  pw3_hkdf_expand(pwd_seed, info1, sizeof(info1) - 1u, pwd_val, 48);
  bytes_mod(pwd_val, 48, &P256_P, &u);
  u256_to_be(&u, u_be);
  pw3_p256_sswu(u_be, p1x, p1y);

  pw3_hkdf_expand(pwd_seed, info2, sizeof(info2) - 1u, pwd_val, 48);
  bytes_mod(pwd_val, 48, &P256_P, &u);
  u256_to_be(&u, u_be);
  pw3_p256_sswu(u_be, p2x, p2y);

  int rc = pw3_p256_point_add(p1x, p1y, p2x, p2y, pt_x, pt_y);
  pw3_ct_zero(pwd_seed, sizeof(pwd_seed));
  pw3_ct_zero(pwd_val, sizeof(pwd_val));
  return rc;
}

int pw3_sae_derive_pwe_h2e(pw3_sae_ctx *ctx, const uint8_t *ssid,
                           size_t ssid_len, const uint8_t sta_mac[6],
                           const uint8_t ap_mac[6], const uint8_t *pass,
                           size_t pass_len) {
  if (!ctx) return -1;
  uint8_t pt_x[32], pt_y[32], addrs[12], seed[32], val_be[32];
  if (pw3_sae_derive_pt_h2e(ssid, ssid_len, pass, pass_len, pt_x, pt_y) != 0) {
    return -1;
  }
  sae_order_macs(sta_mac, ap_mac, addrs);
  pw3_hkdf_extract(NULL, 0, addrs, 12, seed);

  u256 val;
  bytes_mod(seed, 32, &P256_RM1, &val);
  u256_add_raw(&val, &val, &U256_ONE);
  u256_to_be(&val, val_be);

  int rc = pw3_p256_scalar_mul(val_be, pt_x, pt_y, ctx->pwe_x, ctx->pwe_y);
  pw3_ct_zero(pt_x, sizeof(pt_x));
  pw3_ct_zero(pt_y, sizeof(pt_y));
  pw3_ct_zero(seed, sizeof(seed));
  if (rc == 0) ctx->use_h2e = 1;
  return rc;
}

int pw3_sae_commit_begin(pw3_sae_ctx *ctx, const uint8_t rand64[64]) {
  if (!ctx || !rand64) return -1;
  if (!pw3_p256_is_on_curve(ctx->pwe_x, ctx->pwe_y)) return -1;

  u256 rnd, msk, sc, neg_msk;
  bytes_mod(rand64, 32, &P256_RM1, &rnd);
  u256_add_raw(&rnd, &rnd, &U256_ONE);
  bytes_mod(rand64 + 32, 32, &P256_RM1, &msk);
  u256_add_raw(&msk, &msk, &U256_ONE);

  mod_add(&sc, &rnd, &msk, &P256_R);
  if (u256_gte(&U256_ONE, &sc)) return -1;

  u256_sub_raw(&neg_msk, &P256_R, &msk);
  uint8_t neg_be[32];
  u256_to_be(&neg_msk, neg_be);
  if (pw3_p256_scalar_mul(neg_be, ctx->pwe_x, ctx->pwe_y,
                          ctx->own_elem, ctx->own_elem + 32) != 0) {
    pw3_ct_zero(neg_be, sizeof(neg_be));
    return -1;
  }
  pw3_ct_zero(neg_be, sizeof(neg_be));

  u256_to_be(&rnd, ctx->rand_priv);
  u256_to_be(&msk, ctx->mask_priv);
  u256_to_be(&sc, ctx->own_scalar);
  ctx->send_confirm = 0;
  ctx->peer_commit_ok = 0;
  ctx->confirm_ok = 0;
  pw3_ct_zero(&rnd, sizeof(rnd));
  pw3_ct_zero(&msk, sizeof(msk));
  pw3_ct_zero(&neg_msk, sizeof(neg_msk));
  return 0;
}

int pw3_sae_process_peer_commit(pw3_sae_ctx *ctx,
                                const uint8_t peer_scalar[32],
                                const uint8_t peer_elem[64]) {
  if (!ctx || !peer_scalar || !peer_elem) return -1;

  u256 ps;
  u256_from_be(&ps, peer_scalar);
  if (u256_gte(&U256_ONE, &ps) || u256_gte(&ps, &P256_R)) return -1;
  if (!pw3_p256_is_on_curve(peer_elem, peer_elem + 32)) return -1;

  /* Reject reflected commit values (IEEE 802.11 §12.4.7.2). */
  if (pw3_ct_memcmp(peer_scalar, ctx->own_scalar, 32) == 0 &&
      pw3_ct_memcmp(peer_elem, ctx->own_elem, 64) == 0) {
    return -2;
  }
  if (pw3_ct_memcmp(peer_scalar, ctx->own_scalar, 32) == 0 ||
      pw3_ct_memcmp(peer_elem, ctx->own_elem, 64) == 0) {
    return -2;
  }

  uint8_t s_pwe[64], combined[64], K[64];
  if (pw3_p256_scalar_mul(peer_scalar, ctx->pwe_x, ctx->pwe_y,
                          s_pwe, s_pwe + 32) != 0) {
    return -3;
  }
  if (pw3_p256_point_add(s_pwe, s_pwe + 32, peer_elem, peer_elem + 32,
                         combined, combined + 32) != 0) {
    return -3;
  }
  if (pw3_p256_scalar_mul(ctx->rand_priv, combined, combined + 32,
                          K, K + 32) != 0) {
    pw3_ct_zero(K, sizeof(K));
    return -3;
  }

  static const uint8_t zero32[32] = { 0 };
  uint8_t keyseed[32], sval_be[32], keys[64];
  pw3_hmac_sha256(zero32, 32, K, 32, keyseed);

  u256 os, sval;
  u256_from_be(&os, ctx->own_scalar);
  mod_add(&sval, &os, &ps, &P256_R);
  u256_to_be(&sval, sval_be);

  pw3_kdf_sha256_bits(keyseed, 32, "SAE KCK and PMK", sval_be, 32, keys, 512);
  memcpy(ctx->kck, keys, 32);
  memcpy(ctx->pmk, keys + 32, 32);
  memcpy(ctx->pmkid, sval_be, 16);
  memcpy(ctx->peer_scalar, peer_scalar, 32);
  memcpy(ctx->peer_elem, peer_elem, 64);
  ctx->peer_commit_ok = 1;

  pw3_ct_zero(s_pwe, sizeof(s_pwe));
  pw3_ct_zero(combined, sizeof(combined));
  pw3_ct_zero(K, sizeof(K));
  pw3_ct_zero(keyseed, sizeof(keyseed));
  pw3_ct_zero(keys, sizeof(keys));
  return 0;
}

void pw3_sae_build_confirm(pw3_sae_ctx *ctx, uint16_t *sc_out,
                           uint8_t confirm_out[32]) {
  uint8_t sc_le[2];
  uint16_t sc = ctx->send_confirm;
  if (ctx->send_confirm < 0xffffu) ctx->send_confirm++;
  if (sc_out) *sc_out = sc;
  put_le16(sc_le, sc);

  const uint8_t *segs[5] = {
    sc_le, ctx->own_scalar, ctx->own_elem, ctx->peer_scalar, ctx->peer_elem
  };
  size_t lens[5] = { 2, 32, 64, 32, 64 };
  pw3_hmac_sha256_vec(ctx->kck, 32, segs, lens, 5, confirm_out);
}

int pw3_sae_verify_confirm(pw3_sae_ctx *ctx, uint16_t peer_sc,
                           const uint8_t peer_confirm[32]) {
  if (!ctx || !ctx->peer_commit_ok || !peer_confirm) return -1;
  uint8_t sc_le[2], expected[32];
  put_le16(sc_le, peer_sc);

  const uint8_t *segs[5] = {
    sc_le, ctx->peer_scalar, ctx->peer_elem, ctx->own_scalar, ctx->own_elem
  };
  size_t lens[5] = { 2, 32, 64, 32, 64 };
  pw3_hmac_sha256_vec(ctx->kck, 32, segs, lens, 5, expected);

  int bad = pw3_ct_memcmp(expected, peer_confirm, 32);
  pw3_ct_zero(expected, sizeof(expected));
  if (bad) return -1;
  ctx->peer_send_confirm = peer_sc;
  ctx->confirm_ok = 1;
  return 0;
}

void pw3_sae_wipe(pw3_sae_ctx *ctx) {
  if (ctx) pw3_ct_zero(ctx, sizeof(*ctx));
}

/* ---- RSN / RSNXE / SAE Frame / 4-way KDF / KDE Helpers ---- */

static const uint8_t PW3_RSN_OUI[3] = { 0x00u, 0x0fu, 0xacu };

static const uint8_t *pw3_find_ie(const uint8_t *ies, size_t len, uint8_t eid) {
  size_t off = 0;
  while (off + 2u <= len) {
    uint8_t id = ies[off];
    uint8_t elen = ies[off + 1u];
    if (off + 2u + elen > len) break;
    if (id == eid) return ies + off;
    off += 2u + elen;
  }
  return NULL;
}

int pw3_parse_rsn_ap(const uint8_t *ies, size_t ies_len, pw3_rsn_info *out) {
  if (!ies || !out) return -1;
  memset(out, 0, sizeof(*out));
  const uint8_t *rsn = pw3_find_ie(ies, ies_len, 48u);
  if (!rsn) return -1;

  const uint8_t *p = rsn + 2;
  const uint8_t *end = p + rsn[1];
  if ((size_t)(end - p) < 2u || get_le16(p) != 1u) return -1;
  p += 2;

  if ((size_t)(end - p) < 4u) return -1;
  memcpy(out->grp_cipher, p, 4);
  p += 4;

  if ((size_t)(end - p) < 2u) return -1;
  uint16_t n = get_le16(p);
  p += 2;
  if ((size_t)(end - p) < 4u * (size_t)n) return -1;
  int ccmp = 0;
  for (uint16_t i = 0; i < n; i++, p += 4) {
    if (!memcmp(p, PW3_RSN_OUI, 3) && p[3] == 4u) ccmp = 1;
  }

  if ((size_t)(end - p) < 2u) return -1;
  n = get_le16(p);
  p += 2;
  if ((size_t)(end - p) < 4u * (size_t)n) return -1;
  int has_psk = 0, has_psk256 = 0, has_sae = 0;
  for (uint16_t i = 0; i < n; i++, p += 4) {
    if (!memcmp(p, PW3_RSN_OUI, 3)) {
      if (p[3] == 2u) has_psk = 1;
      else if (p[3] == 6u) has_psk256 = 1;
      else if (p[3] == 8u) has_sae = 1;
    }
  }

  uint16_t caps = ((size_t)(end - p) >= 2u) ? (uint16_t)(p += 2, get_le16(p - 2)) : 0u;
  out->mfpc = (caps & 0x0080u) ? 1u : 0u;
  out->mfpr = (caps & 0x0040u) ? 1u : 0u;

  if ((size_t)(end - p) >= 2u) {
    uint16_t kcnt = get_le16(p);
    p += 2;
    if ((size_t)(end - p) < 16u * (size_t)kcnt) return -1;
    p += 16u * (size_t)kcnt;
  }

  int bip_bad = 0;
  if ((size_t)(end - p) >= 4u) {
    if (memcmp(p, PW3_RSN_OUI, 3) != 0 || p[3] != 6u) bip_bad = 1;
  }

  if (!ccmp) return -2;
  if (has_sae) out->akm = 8u;
  else if (has_psk256 && (out->mfpc || out->mfpr || !has_psk)) out->akm = 6u;
  else if (has_psk) out->akm = 2u;
  else return -2;

  out->use_mfp = (out->akm == 8u || out->mfpc || out->mfpr) ? 1u : 0u;
  if (bip_bad && (out->mfpr || out->akm == 8u)) return -2;
  if (bip_bad && out->use_mfp && !out->mfpr) {
    /* Non-CMAC-128 group mgmt with optional MFP: fall back to no MFP for AKM 2 */
    if (out->akm == 2u) out->use_mfp = 0u;
    else return -2;
  }

  const uint8_t *rsnx = pw3_find_ie(ies, ies_len, 244u);
  if (rsnx && rsnx[1] >= 1u && (rsnx[2] & 0x20u)) out->use_h2e = 1u;
  return 0;
}

size_t pw3_build_assoc_rsn(const pw3_rsn_info *info, const uint8_t *pmkid16,
                           uint8_t *out, size_t max_out) {
  if (!info || !info->akm) return 0;
  size_t has_pmkid = (info->akm == 8u && pmkid16 != NULL);
  size_t body_len = 20u + (has_pmkid ? 18u : 0u);
  if (max_out < 2u + body_len) return 0;

  out[0] = 48u;
  out[1] = (uint8_t)body_len;
  out[2] = 1u; out[3] = 0u;                      /* version 1 */
  memcpy(out + 4, info->grp_cipher, 4);          /* group cipher */
  out[8] = 1u; out[9] = 0u;                      /* 1 pairwise cipher */
  memcpy(out + 10, PW3_RSN_OUI, 3); out[13] = 4u; /* CCMP-128 */
  out[14] = 1u; out[15] = 0u;                    /* 1 AKM */
  memcpy(out + 16, PW3_RSN_OUI, 3); out[19] = info->akm;
  uint16_t caps = 0u;
  if (info->use_mfp) {
    caps |= 0x0080u;
    if (info->mfpr) caps |= 0x0040u;
  }
  put_le16(out + 20, caps);
  if (has_pmkid) {
    out[22] = 1u; out[23] = 0u;
    memcpy(out + 24, pmkid16, 16);
  }
  return 2u + body_len;
}

size_t pw3_build_assoc_rsnxe(const pw3_rsn_info *info,
                             uint8_t *out, size_t max_out) {
  if (!info || info->akm != 8u || !info->use_h2e || max_out < 3u) return 0;
  out[0] = 244u;
  out[1] = 1u;
  out[2] = 0x20u;
  return 3u;
}

size_t pw3_build_sae_commit(const pw3_sae_ctx *ctx, const uint8_t *token,
                            size_t token_len, uint8_t *out, size_t max_out) {
  if (!ctx || token_len > 64u) return 0;
  size_t extra_tok = (!ctx->use_h2e && token_len) ? token_len : 0u;
  size_t container = (ctx->use_h2e && token_len) ? (3u + token_len) : 0u;
  size_t total = 8u + extra_tok + 96u + container;
  if (max_out < total) return 0;

  put_le16(out + 0, 3u); /* WLAN_AUTH_SAE */
  put_le16(out + 2, 1u); /* SAE Commit */
  put_le16(out + 4, ctx->use_h2e ? (uint16_t)PW3_SAE_H2E_STATUS : 0u);
  put_le16(out + 6, (uint16_t)PW3_SAE_GROUP_P256);

  size_t pos = 8u;
  if (extra_tok) {
    memcpy(out + pos, token, token_len);
    pos += token_len;
  }
  memcpy(out + pos, ctx->own_scalar, 32); pos += 32u;
  memcpy(out + pos, ctx->own_elem, 64);   pos += 64u;
  if (container) {
    out[pos++] = 255u;
    out[pos++] = (uint8_t)(1u + token_len);
    out[pos++] = (uint8_t)PW3_SAE_EID_EXT_TOKEN;
    memcpy(out + pos, token, token_len);
    pos += token_len;
  }
  return pos;
}

size_t pw3_build_sae_confirm(pw3_sae_ctx *ctx, uint8_t *out, size_t max_out) {
  if (!ctx || max_out < 40u) return 0;
  uint16_t sc = 0;
  uint8_t conf[32];
  pw3_sae_build_confirm(ctx, &sc, conf);
  put_le16(out + 0, 3u);
  put_le16(out + 2, 2u);
  put_le16(out + 4, 0u);
  put_le16(out + 6, sc);
  memcpy(out + 8, conf, 32);
  pw3_ct_zero(conf, sizeof(conf));
  return 40u;
}

int pw3_parse_sae_auth(const uint8_t *body, size_t len, pw3_sae_rx *out) {
  if (!body || !out || len < 6u) return -1;
  memset(out, 0, sizeof(*out));
  if (get_le16(body + 0) != 3u) return -1;
  out->seq = get_le16(body + 2);
  out->status = get_le16(body + 4);

  if (out->seq == 1u) {
    if (len < 8u) {
      /* Status-only rejection (e.g. status 126 forcing H2E or auth failure). */
      return (out->status != 0u && out->status != PW3_SAE_ANTI_CLOG_STATUS) ? 0 : -1;
    }
    out->group = get_le16(body + 6);
    const uint8_t *rem = body + 8;
    size_t rlen = len - 8u;
    if (out->status == PW3_SAE_ANTI_CLOG_STATUS) {
      if (out->group != PW3_SAE_GROUP_P256) return -1;
      if (rlen >= 3u && rem[0] == 255u && rem[1] + 2u == rlen &&
          rem[2] == PW3_SAE_EID_EXT_TOKEN) {
        size_t tlen = rlen - 3u;
        if (!tlen || tlen > sizeof(out->token)) return -1;
        memcpy(out->token, rem + 3, tlen);
        out->token_len = (uint8_t)tlen;
      } else {
        if (!rlen || rlen > sizeof(out->token)) return -1;
        memcpy(out->token, rem, rlen);
        out->token_len = (uint8_t)rlen;
      }
      return 0;
    }
    if (out->status == 0u || out->status == PW3_SAE_H2E_STATUS) {
      if (out->status == PW3_SAE_H2E_STATUS && rlen == 0u) return 0;
      if (out->group != PW3_SAE_GROUP_P256 || rlen < 96u) return -1;
      if (out->status == 0u) {
        size_t tlen = rlen - 96u;
        if (tlen > sizeof(out->token)) return -1;
        if (tlen) {
          memcpy(out->token, rem, tlen);
          out->token_len = (uint8_t)tlen;
        }
        memcpy(out->scalar, rem + tlen, 32);
        memcpy(out->elem, rem + tlen + 32u, 64);
      } else {
        memcpy(out->scalar, rem, 32);
        memcpy(out->elem, rem + 32u, 64);
        const uint8_t *opt = rem + 96u;
        size_t olen = rlen - 96u;
        while (olen >= 2u) {
          uint8_t eid = opt[0], elen = opt[1];
          if (2u + elen > olen) break;
          if (eid == 255u && elen >= 2u && opt[2] == PW3_SAE_EID_EXT_TOKEN) {
            size_t tlen = elen - 1u;
            if (tlen <= sizeof(out->token)) {
              memcpy(out->token, opt + 3u, tlen);
              out->token_len = (uint8_t)tlen;
            }
          }
          opt += 2u + elen;
          olen -= 2u + elen;
        }
      }
      out->has_scalar_elem = 1u;
    }
    return 0;
  }

  if (out->seq == 2u) {
    if (out->status == 0u) {
      if (len < 40u) return -1;
      out->send_confirm = get_le16(body + 6);
      memcpy(out->confirm, body + 8, 32);
      out->has_confirm = 1u;
    }
    return 0;
  }

  return -1;
}

void pw3_derive_ptk_sha256(const uint8_t pmk[32], const uint8_t aa[6],
                            const uint8_t spa[6], const uint8_t anonce[32],
                            const uint8_t snonce[32], uint8_t ptk[48]) {
  uint8_t ctx[76];
  int mac_a = memcmp(aa, spa, 6) < 0;
  int non_a = memcmp(anonce, snonce, 32) < 0;
  memcpy(ctx + 0,  mac_a ? aa  : spa, 6);
  memcpy(ctx + 6,  mac_a ? spa : aa,  6);
  memcpy(ctx + 12, non_a ? anonce : snonce, 32);
  memcpy(ctx + 44, non_a ? snonce : anonce, 32);
  pw3_kdf_sha256_bits(pmk, 32, "Pairwise key expansion", ctx, sizeof(ctx),
                      ptk, 384u);
  pw3_ct_zero(ctx, sizeof(ctx));
}

int pw3_find_igtk_kde(const uint8_t *data, size_t len, uint16_t *key_id,
                      uint8_t rx_pn_be[6], uint8_t igtk[16]) {
  if (!data || !key_id || !rx_pn_be || !igtk) return -1;
  size_t off = 0;
  while (off + 2u <= len) {
    uint8_t id = data[off];
    uint8_t klen = data[off + 1u];
    if (id == 0xdd && klen == 0 && off + 2u < len) break;
    if (off + 2u + klen > len) break;
    if (id == 0xdd && klen >= 28u &&
        memcmp(data + off + 2u, PW3_RSN_OUI, 3) == 0 &&
        data[off + 5u] == 9u) {
      const uint8_t *kde = data + off + 6u;
      *key_id = get_le16(kde);
      for (int i = 0; i < 6; i++) rx_pn_be[i] = kde[2u + (5 - i)];
      memcpy(igtk, kde + 8u, 16);
      return 0;
    }
    off += 2u + klen;
  }
  return -1;
}

int pw3_find_pmkid_kde(const uint8_t *data, size_t len, uint8_t pmkid[16]) {
  if (!data || !pmkid) return -1;
  size_t off = 0;
  while (off + 2u <= len) {
    uint8_t id = data[off];
    uint8_t klen = data[off + 1u];
    if (id == 0xdd && klen == 0) break;
    if (off + 2u + klen > len) break;
    if (id == 0xdd && klen >= 20u &&
        memcmp(data + off + 2u, PW3_RSN_OUI, 3) == 0 &&
        data[off + 5u] == 4u) {
      memcpy(pmkid, data + off + 6u, 16);
      return 0;
    }
    off += 2u + klen;
  }
  return -1;
}
