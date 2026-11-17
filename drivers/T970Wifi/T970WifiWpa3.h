/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 PongWifi contributors
 * All rights reserved.
 *
 * Clean-room WPA3-Personal (SAE Group 19), KDF-SHA256, AES-128-CMAC,
 * and BIP-CMAC-128 (IEEE 802.11w) implementation for PongWifi.
 */
#ifndef PONG_WIFI_WPA3_H
#define PONG_WIFI_WPA3_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PW3_SAE_GROUP_P256       19u
#define PW3_SAE_H2E_STATUS       126u
#define PW3_SAE_ANTI_CLOG_STATUS 76u
#define PW3_SAE_EID_EXT_TOKEN    93u

typedef struct pw3_sae_ctx {
  uint8_t pwe_x[32];
  uint8_t pwe_y[32];
  uint8_t rand_priv[32];
  uint8_t mask_priv[32];
  uint8_t own_scalar[32];
  uint8_t own_elem[64];
  uint8_t peer_scalar[32];
  uint8_t peer_elem[64];
  uint8_t kck[32];
  uint8_t pmk[32];
  uint8_t pmkid[16];
  uint16_t send_confirm;
  uint16_t peer_send_confirm;
  uint8_t use_h2e;
  uint8_t peer_commit_ok;
  uint8_t confirm_ok;
} pw3_sae_ctx;

void pw3_ct_zero(void *ptr, size_t len);
int pw3_ct_memcmp(const void *a, const void *b, size_t len);

void pw3_sha256(const uint8_t *msg, size_t len, uint8_t digest[32]);
void pw3_sha256_vec(const uint8_t *const *segs, const size_t *lens,
                    size_t nsegs, uint8_t digest[32]);
void pw3_hmac_sha256(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len, uint8_t mac[32]);
void pw3_hmac_sha256_vec(const uint8_t *key, size_t key_len,
                         const uint8_t *const *segs, const size_t *lens,
                         size_t nsegs, uint8_t mac[32]);
void pw3_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]);
int pw3_hkdf_expand(const uint8_t prk[32], const uint8_t *info,
                    size_t info_len, uint8_t *okm, size_t okm_len);
int pw3_kdf_sha256_bits(const uint8_t *key, size_t key_len, const char *label,
                        const uint8_t *ctx, size_t ctx_len,
                        uint8_t *out, size_t out_bits);

void pw3_aes128_cmac(const uint8_t key[16], const uint8_t *msg, size_t len,
                     uint8_t mac[16]);
void pw3_aes128_cmac_vec(const uint8_t key[16], const uint8_t *const *segs,
                         const size_t *lens, size_t nsegs, uint8_t mac[16]);
int pw3_bip_cmac128_verify(const uint8_t igtk[16], uint16_t expected_keyid,
                           uint8_t rx_pn_be[6], const uint8_t *frame,
                           size_t frame_len);

int pw3_p256_is_on_curve(const uint8_t x[32], const uint8_t y[32]);
int pw3_p256_point_add(const uint8_t ax[32], const uint8_t ay[32],
                       const uint8_t bx[32], const uint8_t by[32],
                       uint8_t rx[32], uint8_t ry[32]);
int pw3_p256_scalar_mul(const uint8_t k_be[32], const uint8_t px[32],
                        const uint8_t py[32], uint8_t rx[32], uint8_t ry[32]);
void pw3_p256_sswu(const uint8_t u_be[32], uint8_t rx[32], uint8_t ry[32]);

int pw3_sae_derive_pwe_hnp(pw3_sae_ctx *ctx, const uint8_t sta_mac[6],
                           const uint8_t ap_mac[6], const uint8_t *pass,
                           size_t pass_len);
int pw3_sae_derive_pt_h2e(const uint8_t *ssid, size_t ssid_len,
                          const uint8_t *pass, size_t pass_len,
                          uint8_t pt_x[32], uint8_t pt_y[32]);
int pw3_sae_derive_pwe_h2e(pw3_sae_ctx *ctx, const uint8_t *ssid,
                           size_t ssid_len, const uint8_t sta_mac[6],
                           const uint8_t ap_mac[6], const uint8_t *pass,
                           size_t pass_len);
int pw3_sae_commit_begin(pw3_sae_ctx *ctx, const uint8_t rand64[64]);
int pw3_sae_process_peer_commit(pw3_sae_ctx *ctx,
                                const uint8_t peer_scalar[32],
                                const uint8_t peer_elem[64]);
void pw3_sae_build_confirm(pw3_sae_ctx *ctx, uint16_t *sc_out,
                           uint8_t confirm_out[32]);
int pw3_sae_verify_confirm(pw3_sae_ctx *ctx, uint16_t peer_sc,
                           const uint8_t peer_confirm[32]);
typedef struct pw3_rsn_info {
  uint8_t grp_cipher[4];
  uint8_t akm;       /* 0 = open, 2 = PSK, 6 = PSK-SHA256, 8 = SAE */
  uint8_t mfpc;      /* 1 if AP advertises MFPC (0x0080) */
  uint8_t mfpr;      /* 1 if AP requires MFPR (0x0040) */
  uint8_t use_mfp;   /* 1 if STA enables PMF (ap_mfpc || ap_mfpr || akm == 8) */
  uint8_t use_h2e;   /* 1 if RSNXE SAE H2E bit (0x20) advertised */
} pw3_rsn_info;

typedef struct pw3_sae_rx {
  uint16_t seq;
  uint16_t status;
  uint16_t group;
  uint16_t send_confirm;
  uint8_t has_scalar_elem;
  uint8_t scalar[32];
  uint8_t elem[64];
  uint8_t has_confirm;
  uint8_t confirm[32];
  uint8_t token[64];
  uint8_t token_len;
} pw3_sae_rx;

int pw3_parse_rsn_ap(const uint8_t *ies, size_t ies_len, pw3_rsn_info *out);
size_t pw3_build_assoc_rsn(const pw3_rsn_info *info, const uint8_t *pmkid16,
                           uint8_t *out, size_t max_out);
size_t pw3_build_assoc_rsnxe(const pw3_rsn_info *info,
                             uint8_t *out, size_t max_out);

size_t pw3_build_sae_commit(const pw3_sae_ctx *ctx, const uint8_t *token,
                            size_t token_len, uint8_t *out, size_t max_out);
size_t pw3_build_sae_confirm(pw3_sae_ctx *ctx, uint8_t *out, size_t max_out);
int pw3_parse_sae_auth(const uint8_t *body, size_t len, pw3_sae_rx *out);

void pw3_derive_ptk_sha256(const uint8_t pmk[32], const uint8_t aa[6],
                            const uint8_t spa[6], const uint8_t anonce[32],
                            const uint8_t snonce[32], uint8_t ptk[48]);
int pw3_find_igtk_kde(const uint8_t *data, size_t len, uint16_t *key_id,
                      uint8_t rx_pn_be[6], uint8_t igtk[16]);
int pw3_find_pmkid_kde(const uint8_t *data, size_t len, uint8_t pmkid[16]);

void pw3_sae_wipe(pw3_sae_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif
