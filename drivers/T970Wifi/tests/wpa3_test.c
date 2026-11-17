/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Host unit & standard test-vector verification for T970WifiWpa3.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "T970WifiWpa3.h"

static int g_fails = 0;

static int hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static size_t unhex(const char *s, uint8_t *out, size_t max_len) {
  size_t n = 0;
  while (*s) {
    if (*s == ' ' || *s == ':' || *s == '\n') { s++; continue; }
    int hi = hex_val(s[0]), lo = hex_val(s[1]);
    if (hi < 0 || lo < 0 || n >= max_len) abort();
    out[n++] = (uint8_t)((hi << 4) | lo);
    s += 2;
  }
  return n;
}

static void check_eq(const char *name, const void *got, const void *exp, size_t n) {
  if (memcmp(got, exp, n) != 0) {
    const uint8_t *g = (const uint8_t *)got;
    const uint8_t *e = (const uint8_t *)exp;
    printf("FAIL [%s]\n  got: ", name);
    for (size_t i = 0; i < n; i++) printf("%02x", g[i]);
    printf("\n  exp: ");
    for (size_t i = 0; i < n; i++) printf("%02x", e[i]);
    printf("\n");
    g_fails++;
  }
}

static void check_cond(const char *name, int cond) {
  if (!cond) {
    printf("FAIL [%s]\n", name);
    g_fails++;
  }
}

static void test_sha256_and_hmac(void) {
  uint8_t out[32], exp[32], key[131], msg[128];

  pw3_sha256((const uint8_t *)"", 0, out);
  unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", exp, 32);
  check_eq("sha256 empty", out, exp, 32);

  pw3_sha256((const uint8_t *)"abc", 3, out);
  unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", exp, 32);
  check_eq("sha256 abc", out, exp, 32);

  const char *two_blk = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  pw3_sha256((const uint8_t *)two_blk, strlen(two_blk), out);
  unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", exp, 32);
  check_eq("sha256 2blk", out, exp, 32);

  /* RFC 4231 Test Case 1 */
  memset(key, 0x0b, 20);
  pw3_hmac_sha256(key, 20, (const uint8_t *)"Hi There", 8, out);
  unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", exp, 32);
  check_eq("rfc4231 tc1", out, exp, 32);

  /* RFC 4231 Test Case 2 */
  pw3_hmac_sha256((const uint8_t *)"Jefe", 4,
                  (const uint8_t *)"what do ya want for nothing?", 28, out);
  unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", exp, 32);
  check_eq("rfc4231 tc2", out, exp, 32);

  /* RFC 4231 Test Case 3 */
  memset(key, 0xaa, 20);
  memset(msg, 0xdd, 50);
  pw3_hmac_sha256(key, 20, msg, 50, out);
  unhex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", exp, 32);
  check_eq("rfc4231 tc3", out, exp, 32);

  /* RFC 4231 Test Case 4 */
  size_t klen = unhex("0102030405060708090a0b0c0d0e0f10111213141516171819", key, sizeof(key));
  memset(msg, 0xcd, 50);
  pw3_hmac_sha256(key, klen, msg, 50, out);
  unhex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", exp, 32);
  check_eq("rfc4231 tc4", out, exp, 32);

  /* RFC 4231 Test Case 6 (> 64 byte key) */
  memset(key, 0xaa, 131);
  const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
  pw3_hmac_sha256(key, 131, (const uint8_t *)m6, strlen(m6), out);
  unhex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", exp, 32);
  check_eq("rfc4231 tc6", out, exp, 32);
}

static void test_hkdf_and_kdf(void) {
  /* RFC 5869 Test Case 1 */
  uint8_t ikm[22], salt[13], info[10], prk[32], okm[42], exp_prk[32], exp_okm[42];
  memset(ikm, 0x0b, sizeof(ikm));
  unhex("000102030405060708090a0b0c", salt, sizeof(salt));
  unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
  pw3_hkdf_extract(salt, sizeof(salt), ikm, sizeof(ikm), prk);
  unhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", exp_prk, 32);
  check_eq("rfc5869 tc1 prk", prk, exp_prk, 32);

  check_cond("rfc5869 tc1 expand", pw3_hkdf_expand(prk, info, sizeof(info), okm, 42) == 0);
  unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", exp_okm, 42);
  check_eq("rfc5869 tc1 okm", okm, exp_okm, 42);

  /* IEEE 802.11 KDF-384 ("Pairwise key expansion") */
  uint8_t pmk[32], ctx[76], ptk[48], exp_ptk[48];
  memset(pmk, 0x0b, 32);
  unhex("020000000100" "020000000200", ctx, 12);
  memset(ctx + 12, 0x11, 32);
  memset(ctx + 44, 0x22, 32);
  check_cond("kdf384", pw3_kdf_sha256_bits(pmk, 32, "Pairwise key expansion", ctx, sizeof(ctx), ptk, 384) == 0);
  unhex("59cdd7d9d85b8c3c6584e9a067ba2f901447e70ebe6ddf0b07d02a9d359caab35aad39dc44f6df065bb11a7cf9c19637", exp_ptk, 48);
  check_eq("kdf384 vec", ptk, exp_ptk, 48);
}

static void test_aes_cmac_and_bip(void) {
  /* RFC 4493 Examples 1-4 */
  uint8_t key[16], msg[64], mac[16], exp[16];
  unhex("2b7e151628aed2a6abf7158809cf4f3c", key, 16);

  pw3_aes128_cmac(key, (const uint8_t *)"", 0, mac);
  unhex("bb1d6929e95937287fa37d129b756746", exp, 16);
  check_eq("rfc4493 ex1 (0B)", mac, exp, 16);

  unhex("6bc1bee22e409f96e93d7e117393172a", msg, 16);
  pw3_aes128_cmac(key, msg, 16, mac);
  unhex("070a16b46b4d4144f79bdd9dd04a287c", exp, 16);
  check_eq("rfc4493 ex2 (16B)", mac, exp, 16);

  unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", msg, 40);
  pw3_aes128_cmac(key, msg, 40, mac);
  unhex("dfa66747de9ae63030ca32611497c827", exp, 16);
  check_eq("rfc4493 ex3 (40B)", mac, exp, 16);

  unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", msg, 64);
  pw3_aes128_cmac(key, msg, 64, mac);
  unhex("51f0bebf7e3b9d92fc49741779363cfe", exp, 16);
  check_eq("rfc4493 ex4 (64B)", mac, exp, 16);

  /* BIP-CMAC-128 MMIE test (Deauth broadcast + replay + tamper + wrong keyid) */
  uint8_t igtk[16], frame[24 + 2 + 18];
  memset(igtk, 0x42, 16);
  memset(frame, 0, sizeof(frame));
  frame[0] = 0xc0; /* Deauth */
  frame[1] = 0x08; /* Retry bit set (must be masked in BIP AAD!) */
  memset(frame + 4, 0xff, 6); /* A1 = broadcast */
  unhex("020000000100", frame + 10, 6); /* A2 = BSSID */
  unhex("020000000100", frame + 16, 6); /* A3 = BSSID */
  frame[24] = 7; frame[25] = 0;       /* Reason 7 */
  uint8_t *mmie = frame + 26;
  mmie[0] = 76; mmie[1] = 16;         /* WLAN_EID_MMIE */
  mmie[2] = 4;  mmie[3] = 0;          /* key_id = 4 */
  mmie[4] = 1;                        /* IPN = 1 LE */

  uint8_t aad[20], zero8[8] = { 0 };
  aad[0] = frame[0]; aad[1] = 0x00;   /* Retry masked */
  memcpy(aad + 2, frame + 4, 18);
  const uint8_t *segs[3] = { aad, frame + 24, zero8 };
  size_t lens[3] = { 20, 2 + 10, 8 };
  pw3_aes128_cmac_vec(igtk, segs, lens, 3, mac);
  memcpy(mmie + 10, mac, 8);

  uint8_t rx_pn[6] = { 0 };
  check_cond("bip verify ok", pw3_bip_cmac128_verify(igtk, 4, rx_pn, frame, sizeof(frame)) == 0);
  check_cond("bip replay reject", pw3_bip_cmac128_verify(igtk, 4, rx_pn, frame, sizeof(frame)) == -2);
  check_cond("bip wrong keyid", pw3_bip_cmac128_verify(igtk, 5, rx_pn, frame, sizeof(frame)) == -1);
  mmie[4] = 2; /* bump IPN, stale MIC */
  check_cond("bip stale mic reject", pw3_bip_cmac128_verify(igtk, 4, rx_pn, frame, sizeof(frame)) == -3);
}

static void test_p256_and_sswu(void) {
  uint8_t gx[32], gy[32], r_m1[32], r[32], k2[32], ox[32], oy[32], exp_x[32], exp_y[32];
  unhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", gx, 32);
  unhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", gy, 32);
  unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550", r_m1, 32);
  unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", r, 32);
  unhex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", k2, 32);

  check_cond("G on curve", pw3_p256_is_on_curve(gx, gy) == 1);
  uint8_t zero[32] = { 0 };
  check_cond("0 off curve", pw3_p256_is_on_curve(zero, zero) == 0);

  check_cond("k2*G ok", pw3_p256_scalar_mul(k2, gx, gy, ox, oy) == 0);
  unhex("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6", exp_x, 32);
  unhex("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299", exp_y, 32);
  check_eq("k2*G.x", ox, exp_x, 32);
  check_eq("k2*G.y", oy, exp_y, 32);

  /* (r - 1) * G == -G = (Gx, p - Gy) */
  check_cond("(r-1)*G ok", pw3_p256_scalar_mul(r_m1, gx, gy, ox, oy) == 0);
  unhex("b01cbd1c01e58065711814b583f061e9d431cca994cea1313449bf97c840ae0a", exp_y, 32);
  check_eq("(r-1)*G.x", ox, gx, 32);
  check_eq("(r-1)*G.y", oy, exp_y, 32);

  /* r * G == Infinity */
  check_cond("r*G == inf", pw3_p256_scalar_mul(r, gx, gy, ox, oy) == -1);

  /* RFC 9380 P256_XMD:SHA-256_SSWU_RO_ u[0], u[1], Q0 + Q1 == P */
  uint8_t u0[32], u1[32], q0x[32], q0y[32], q1x[32], q1y[32], px[32], py[32];
  unhex("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009", u0, 32);
  unhex("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a", u1, 32);
  pw3_p256_sswu(u0, q0x, q0y);
  pw3_p256_sswu(u1, q1x, q1y);
  unhex("ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5", exp_x, 32);
  unhex("dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1", exp_y, 32);
  check_eq("sswu u0.x", q0x, exp_x, 32);
  check_eq("sswu u0.y", q0y, exp_y, 32);

  unhex("51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5", exp_x, 32);
  unhex("b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac", exp_y, 32);
  check_eq("sswu u1.x", q1x, exp_x, 32);
  check_eq("sswu u1.y", q1y, exp_y, 32);

  check_cond("Q0+Q1", pw3_p256_point_add(q0x, q0y, q1x, q1y, px, py) == 0);
  unhex("2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4", exp_x, 32);
  unhex("8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415", exp_y, 32);
  check_eq("Q0+Q1.x", px, exp_x, 32);
  check_eq("Q0+Q1.y", py, exp_y, 32);
}

static void test_sae_handshake_and_adversarial(void) {
  static const uint8_t sta[6] = { 0x82, 0x7b, 0x91, 0x9d, 0xd4, 0xb9 };
  static const uint8_t ap[6]  = { 0x1e, 0xec, 0x49, 0xea, 0x64, 0x88 };
  const char *pass = "mekmitasdigoat";
  const char *ssid = "WPA3-Test-Net";

  uint8_t sta_rnd[64], ap_rnd[64];
  for (int i = 0; i < 64; i++) {
    sta_rnd[i] = (uint8_t)(0x11u + i);
    ap_rnd[i]  = (uint8_t)(0xa5u ^ (i * 3u));
  }

  /* 1. Hunting-and-Pecking handshake */
  pw3_sae_ctx c_sta, c_ap;
  memset(&c_sta, 0, sizeof(c_sta));
  memset(&c_ap, 0, sizeof(c_ap));
  check_cond("hnp sta pwe", pw3_sae_derive_pwe_hnp(&c_sta, sta, ap, (const uint8_t *)pass, strlen(pass)) == 0);
  check_cond("hnp ap  pwe", pw3_sae_derive_pwe_hnp(&c_ap,  ap, sta, (const uint8_t *)pass, strlen(pass)) == 0);
  check_eq("hnp pwe.x", c_sta.pwe_x, c_ap.pwe_x, 32);
  check_eq("hnp pwe.y", c_sta.pwe_y, c_ap.pwe_y, 32);

  check_cond("hnp sta commit", pw3_sae_commit_begin(&c_sta, sta_rnd) == 0);
  check_cond("hnp ap  commit", pw3_sae_commit_begin(&c_ap,  ap_rnd) == 0);
  check_cond("hnp sta peer", pw3_sae_process_peer_commit(&c_sta, c_ap.own_scalar, c_ap.own_elem) == 0);
  check_cond("hnp ap  peer", pw3_sae_process_peer_commit(&c_ap,  c_sta.own_scalar, c_sta.own_elem) == 0);
  check_eq("hnp kck",   c_sta.kck,   c_ap.kck,   32);
  check_eq("hnp pmk",   c_sta.pmk,   c_ap.pmk,   32);
  check_eq("hnp pmkid", c_sta.pmkid, c_ap.pmkid, 16);

  uint16_t sc_sta = 0, sc_ap = 0;
  uint8_t cf_sta[32], cf_ap[32];
  pw3_sae_build_confirm(&c_sta, &sc_sta, cf_sta);
  pw3_sae_build_confirm(&c_ap,  &sc_ap,  cf_ap);
  check_cond("hnp sc start 0", sc_sta == 0 && sc_ap == 0);
  check_cond("hnp ap verifies sta",  pw3_sae_verify_confirm(&c_ap,  sc_sta, cf_sta) == 0);
  check_cond("hnp sta verifies ap",  pw3_sae_verify_confirm(&c_sta, sc_ap,  cf_ap) == 0);

  /* Reflection and bad peer commit rejection */
  check_cond("reflect reject", pw3_sae_process_peer_commit(&c_sta, c_sta.own_scalar, c_sta.own_elem) == -2);
  uint8_t bad_scalar[32];
  memset(bad_scalar, 0, 32); bad_scalar[31] = 1;
  check_cond("scalar 1 reject", pw3_sae_process_peer_commit(&c_sta, bad_scalar, c_ap.own_elem) == -1);
  uint8_t bad_elem[64];
  memcpy(bad_elem, c_ap.own_elem, 64);
  bad_elem[63] ^= 1;
  check_cond("off-curve elem reject", pw3_sae_process_peer_commit(&c_sta, c_ap.own_scalar, bad_elem) == -1);

  /* 2. Hash-to-Element (H2E) handshake */
  pw3_sae_ctx h_sta, h_ap, h_bad;
  memset(&h_sta, 0, sizeof(h_sta));
  memset(&h_ap,  0, sizeof(h_ap));
  memset(&h_bad, 0, sizeof(h_bad));
  check_cond("h2e sta pwe", pw3_sae_derive_pwe_h2e(&h_sta, (const uint8_t *)ssid, strlen(ssid), sta, ap, (const uint8_t *)pass, strlen(pass)) == 0);
  check_cond("h2e ap  pwe", pw3_sae_derive_pwe_h2e(&h_ap,  (const uint8_t *)ssid, strlen(ssid), ap, sta, (const uint8_t *)pass, strlen(pass)) == 0);
  check_eq("h2e pwe.x", h_sta.pwe_x, h_ap.pwe_x, 32);
  check_eq("h2e pwe.y", h_sta.pwe_y, h_ap.pwe_y, 32);
  check_cond("h2e vs hnp differ", memcmp(h_sta.pwe_x, c_sta.pwe_x, 32) != 0);

  check_cond("h2e sta commit", pw3_sae_commit_begin(&h_sta, sta_rnd) == 0);
  check_cond("h2e ap  commit", pw3_sae_commit_begin(&h_ap,  ap_rnd) == 0);
  check_cond("h2e sta peer", pw3_sae_process_peer_commit(&h_sta, h_ap.own_scalar, h_ap.own_elem) == 0);
  check_cond("h2e ap  peer", pw3_sae_process_peer_commit(&h_ap,  h_sta.own_scalar, h_sta.own_elem) == 0);
  check_eq("h2e kck",   h_sta.kck,   h_ap.kck,   32);
  check_eq("h2e pmk",   h_sta.pmk,   h_ap.pmk,   32);
  check_eq("h2e pmkid", h_sta.pmkid, h_ap.pmkid, 16);

  pw3_sae_build_confirm(&h_sta, &sc_sta, cf_sta);
  pw3_sae_build_confirm(&h_ap,  &sc_ap,  cf_ap);
  check_cond("h2e ap verifies sta",  pw3_sae_verify_confirm(&h_ap,  sc_sta, cf_sta) == 0);
  check_cond("h2e sta verifies ap",  pw3_sae_verify_confirm(&h_sta, sc_ap,  cf_ap) == 0);
  check_cond("h2e sc tamper fail",   pw3_sae_verify_confirm(&h_sta, (uint16_t)(sc_ap + 1u), cf_ap) == -1);

  /* Wrong passphrase must fail confirm */
  check_cond("h2e bad pw", pw3_sae_derive_pwe_h2e(&h_bad, (const uint8_t *)ssid, strlen(ssid), ap, sta, (const uint8_t *)"wrong-pw", 8) == 0);
  check_cond("h2e bad commit", pw3_sae_commit_begin(&h_bad, ap_rnd) == 0);
  check_cond("h2e bad peer", pw3_sae_process_peer_commit(&h_bad, h_sta.own_scalar, h_sta.own_elem) == 0);
  check_cond("h2e bad confirm", pw3_sae_verify_confirm(&h_bad, sc_sta, cf_sta) == -1);

  uint8_t exp_pmk[32], exp_pmkid[16], exp_x[32], exp_y[32];
  unhex("69fdf86f627405902901384ca7ac713dcc6e89b3f5707d5980a3d6af7ee4c925", exp_x, 32);
  unhex("db41b30c5b8cf9d292959e1dd6a63d79669ee28d1b3281d4a6ad015cfb5c4a4f", exp_y, 32);
  unhex("6f8f686093ab14ebffeaf00f461b1606c4533fbd92ac75720f0a6da8b9588e91", exp_pmk, 32);
  check_eq("hnp pwe.x vec", c_sta.pwe_x, exp_x, 32);
  check_eq("hnp pwe.y vec", c_sta.pwe_y, exp_y, 32);
  check_eq("hnp pmk   vec", c_sta.pmk,   exp_pmk, 32);

  unhex("1bf5e9c88bb0aeab0164278edd732f01b47ed0f7ad481fe0cf4b8fa7a17cfe21", exp_x, 32);
  unhex("935563fe8952d5c6280ac0d6fb7d566ac4ad616d7df11c71305a823151900932", exp_y, 32);
  unhex("6fe8aa4382c36660a13fb6a07d6e434f2e9125e76744ed7bd8fb215d772a47af", exp_pmk, 32);
  unhex("adb1adc2bdc1ddd0edf1ed00fd011d11", exp_pmkid, 16);
  check_eq("h2e pwe.x vec", h_sta.pwe_x, exp_x, 32);
  check_eq("h2e pwe.y vec", h_sta.pwe_y, exp_y, 32);
  check_eq("h2e pmk   vec", h_sta.pmk,   exp_pmk, 32);
  check_eq("h2e pmkid vec", h_sta.pmkid, exp_pmkid, 16);

  pw3_sae_wipe(&c_sta); pw3_sae_wipe(&c_ap);
  pw3_sae_wipe(&h_sta); pw3_sae_wipe(&h_ap); pw3_sae_wipe(&h_bad);
}

static void test_rsn_kde_and_sae_frames(void) {
  /* 1. WPA2/WPA3 mixed RSN (TKIP group + CCMP pairwise + AKMs 2 & 8, MFPC=1, MFPR=0) + RSNXE H2E */
  const uint8_t mixed_ies[] = {
    48, 24, 1, 0,
    0x00,0x0f,0xac,2,        /* TKIP group */
    1, 0, 0x00,0x0f,0xac,4,  /* CCMP pairwise */
    2, 0, 0x00,0x0f,0xac,2, 0x00,0x0f,0xac,8, /* AKM 2 + AKM 8 */
    0x80, 0x00,              /* MFPC=1, MFPR=0 */
    244, 1, 0x20             /* RSNXE H2E */
  };
  pw3_rsn_info info;
  check_cond("mixed rsn parse", pw3_parse_rsn_ap(mixed_ies, sizeof(mixed_ies), &info) == 0);
  check_cond("mixed prefers SAE", info.akm == 8 && info.use_mfp == 1 && info.mfpr == 0 && info.use_h2e == 1);

  uint8_t pmkid[16]; memset(pmkid, 0xab, 16);
  uint8_t assoc_rsn[64], assoc_rsnxe[8];
  size_t rlen = pw3_build_assoc_rsn(&info, pmkid, assoc_rsn, sizeof(assoc_rsn));
  size_t xlen = pw3_build_assoc_rsnxe(&info, assoc_rsnxe, sizeof(assoc_rsnxe));
  check_cond("assoc rsn len", rlen == 40 && assoc_rsn[19] == 8 && assoc_rsn[20] == 0x80);
  check_cond("assoc rsnxe", xlen == 3 && assoc_rsnxe[0] == 244 && assoc_rsnxe[2] == 0x20);

  /* 2. WPA2 PSK-SHA256 + MFPR=1 + PMKID_CNT=0 + BIP-CMAC-128 */
  const uint8_t pmf_req_ies[] = {
    48, 26, 1, 0,
    0x00,0x0f,0xac,4,
    1, 0, 0x00,0x0f,0xac,4,
    1, 0, 0x00,0x0f,0xac,6,
    0xc0, 0x00,
    0x00, 0x00,               /* PMKID count = 0 */
    0x00,0x0f,0xac,6          /* BIP-CMAC-128 */
  };
  check_cond("psk256 rsn", pw3_parse_rsn_ap(pmf_req_ies, sizeof(pmf_req_ies), &info) == 0);
  check_cond("psk256 fields", info.akm == 6 && info.mfpr == 1 && info.use_mfp == 1 && info.use_h2e == 0);
  rlen = pw3_build_assoc_rsn(&info, pmkid, assoc_rsn, sizeof(assoc_rsn));
  check_cond("psk256 assoc caps mfpr", rlen == 22 && assoc_rsn[20] == 0xc0);

  uint8_t bad_bip[sizeof(pmf_req_ies)];
  memcpy(bad_bip, pmf_req_ies, sizeof(bad_bip));
  bad_bip[27] = 13u; /* BIP-CMAC-256 unsupported when MFPR=1 */
  check_cond("unsupported bip reject", pw3_parse_rsn_ap(bad_bip, sizeof(bad_bip), &info) == -2);

  /* 3. SAE commit/confirm build + parse + anti-clogging (H&P raw + H2E container) + 6B H2E reject */
  pw3_sae_ctx s;
  memset(&s, 0, sizeof(s));
  s.use_h2e = 1;
  memset(s.own_scalar, 0x22, 32);
  memset(s.own_elem, 0x33, 64);
  uint8_t tok[4] = { 0xde, 0xad, 0xbe, 0xef };
  uint8_t frame[160];
  size_t flen = pw3_build_sae_commit(&s, tok, sizeof(tok), frame, sizeof(frame));
  check_cond("h2e commit tok len", flen == 8 + 96 + 7 && frame[4] == 126 && frame[104] == 255 && frame[106] == 93);

  pw3_sae_rx rx;
  uint8_t aclog_h2e[15] = { 3,0, 1,0, 76,0, 19,0, 255,5,93, 1,2,3,4 };
  check_cond("parse aclog h2e", pw3_parse_sae_auth(aclog_h2e, sizeof(aclog_h2e), &rx) == 0);
  check_cond("aclog h2e tok", rx.status == 76 && rx.token_len == 4 && memcmp(rx.token, aclog_h2e + 11, 4) == 0);

  uint8_t h2e_rej6[6] = { 3,0, 1,0, 126,0 };
  check_cond("parse 6B h2e reject", pw3_parse_sae_auth(h2e_rej6, sizeof(h2e_rej6), &rx) == 0);
  check_cond("h2e rej6 status", rx.seq == 1 && rx.status == 126 && rx.has_scalar_elem == 0);

  /* 4. IGTK KDE + padding stop */
  const uint8_t key_data[] = {
    0xdd, 28, 0x00,0x0f,0xac, 9,
    0x04,0x00,                      /* key_id = 4 LE */
    0x10,0x00,0x00,0x00,0x00,0x00,  /* IPN = 0x10 LE -> 00 00 00 00 00 10 BE */
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    0xdd, 0x00                      /* AES key-wrap padding */
  };
  uint16_t kid = 0; uint8_t ipn[6], igtk[16];
  check_cond("igtk kde parse", pw3_find_igtk_kde(key_data, sizeof(key_data), &kid, ipn, igtk) == 0);
  check_cond("igtk values", kid == 4 && ipn[5] == 0x10 && ipn[0] == 0 && igtk[0] == 1 && igtk[15] == 16);
}

int main(void) {
  test_sha256_and_hmac();
  test_hkdf_and_kdf();
  test_aes_cmac_and_bip();
  test_p256_and_sswu();
  test_sae_handshake_and_adversarial();
  test_rsn_kde_and_sae_frames();
  if (g_fails) {
    printf("FAILED %d checks\n", g_fails);
    return 1;
  }
  printf("ALL wpa3_test CHECKS PASSED\n");
  return 0;
}
