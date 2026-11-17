/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Standalone station-AP WPA3-SAE / WPA2/WPA3 Mixed / PMF (802.11w)
 * protocol state-machine simulator exercising T970WifiWpa3 helpers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "T970WifiWpa3.h"

static int g_fails = 0;

#define ASSERT_TRUE(name, cond) do { \
  if (!(cond)) { printf("FAIL [%s] line %d\n", (name), __LINE__); g_fails++; } \
} while (0)

typedef enum {
  SIM_AP_WPA2_PSK,
  SIM_AP_WPA2_PSK_SHA256_PMF,
  SIM_AP_WPA3_HNP,
  SIM_AP_WPA3_H2E,
  SIM_AP_MIXED_SAE_H2E,
  SIM_AP_HNP_REQUIRE_H2E_STATUS126
} sim_ap_mode;

typedef struct {
  sim_ap_mode mode;
  int anti_clog;
  int wrong_pass;
  int drop_unprotected_deauth_ok;
  uint8_t bssid[6];
  uint8_t sta_mac[6];
  const char *ssid;
  const char *ap_pass;
  const char *sta_pass;
  pw3_sae_ctx ap_sae;
  pw3_sae_ctx sta_sae;
  pw3_rsn_info sta_rsn;
  uint8_t pmk[32];
  uint8_t ptk[48];
  uint8_t anonce[32], snonce[32];
  uint8_t gtk[16];
  uint8_t igtk[16], sta_igtk[16], sta_igtk_pn[6];
  uint16_t igtk_id, sta_igtk_id;
  uint64_t ap_ipn;
  uint8_t pmkid[16];
  int sta_mfp_installed;
  int sta_ptk_ready;
  int sta_up;
  int ap_sent_126;
  int ap_sent_aclog;
  int saw_pmkid_in_assoc;
  int saw_rsnxe_in_assoc;
  uint8_t expected_eapol_ver;
} sim_env;

static void make_bytes(uint8_t seed, uint8_t *out, size_t n) {
  for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(seed + (uint8_t)(i * 17u));
}

static size_t build_ap_ies(sim_ap_mode mode, uint8_t *ies) {
  size_t pos = 0;
  /* SSID IE skipped; parse_rsn_ap reads 48 and 244 */
  if (mode == SIM_AP_WPA2_PSK) {
    const uint8_t rsn[] = {
      48, 20, 1, 0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,2, 0x00,0x00
    };
    memcpy(ies + pos, rsn, sizeof(rsn)); pos += sizeof(rsn);
  } else if (mode == SIM_AP_WPA2_PSK_SHA256_PMF) {
    const uint8_t rsn[] = {
      48, 26, 1, 0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,6, 0xc0,0x00, 0,0, 0x00,0x0f,0xac,6
    };
    memcpy(ies + pos, rsn, sizeof(rsn)); pos += sizeof(rsn);
  } else if (mode == SIM_AP_WPA3_HNP || mode == SIM_AP_HNP_REQUIRE_H2E_STATUS126) {
    const uint8_t rsn[] = {
      48, 26, 1, 0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,8, 0xc0,0x00, 0,0, 0x00,0x0f,0xac,6
    };
    memcpy(ies + pos, rsn, sizeof(rsn)); pos += sizeof(rsn);
  } else if (mode == SIM_AP_WPA3_H2E) {
    const uint8_t rsn[] = {
      48, 26, 1, 0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,4, 1,0, 0x00,0x0f,0xac,8, 0xc0,0x00, 0,0, 0x00,0x0f,0xac,6,
      244, 1, 0x20
    };
    memcpy(ies + pos, rsn, sizeof(rsn)); pos += sizeof(rsn);
  } else { /* SIM_AP_MIXED_SAE_H2E: TKIP group, AKM 2 + AKM 8, MFPC=1 MFPR=0, RSNXE H2E */
    const uint8_t rsn[] = {
      48, 24, 1, 0, 0x00,0x0f,0xac,2, 1,0, 0x00,0x0f,0xac,4, 2,0, 0x00,0x0f,0xac,2, 0x00,0x0f,0xac,8, 0x80,0x00,
      244, 1, 0x20
    };
    memcpy(ies + pos, rsn, sizeof(rsn)); pos += sizeof(rsn);
  }
  return pos;
}

static void sim_eapol_mic(uint8_t akm, const uint8_t *kck, const uint8_t *frame, size_t len, uint8_t mic[16]) {
  (void)akm;
  /* For AKM 6 and AKM 8, IEEE 802.11 uses AES-128-CMAC (16 bytes). */
  pw3_aes128_cmac(kck, frame, len, mic);
}

static void build_broadcast_deauth_mmie(const uint8_t bssid[6], const uint8_t igtk[16],
                                        uint16_t key_id, uint64_t pn, uint16_t reason,
                                        uint8_t *out_frame, size_t *out_len) {
  memset(out_frame, 0, 24 + 2 + 18);
  out_frame[0] = 0xc0; /* Deauth */
  out_frame[1] = 0x00;
  memset(out_frame + 4, 0xff, 6);
  memcpy(out_frame + 10, bssid, 6);
  memcpy(out_frame + 16, bssid, 6);
  out_frame[24] = (uint8_t)reason;
  out_frame[25] = (uint8_t)(reason >> 8);
  uint8_t *mmie = out_frame + 26;
  mmie[0] = 76; mmie[1] = 16;
  mmie[2] = (uint8_t)key_id; mmie[3] = (uint8_t)(key_id >> 8);
  for (int i = 0; i < 6; i++) mmie[4 + i] = (uint8_t)(pn >> (8 * i));

  uint8_t aad[20], zero8[8] = { 0 }, mac[16];
  aad[0] = out_frame[0]; aad[1] = 0x00;
  memcpy(aad + 2, out_frame + 4, 18);
  const uint8_t *segs[3] = { aad, out_frame + 24, zero8 };
  size_t lens[3] = { 20, 12, 8 };
  pw3_aes128_cmac_vec(igtk, segs, lens, 3, mac);
  memcpy(mmie + 10, mac, 8);
  *out_len = 24 + 2 + 18;
}

static int rx_deauth_pmf(sim_env *s, const uint8_t *frame, size_t len, int hw_decrypted) {
  if (len < 26) return 0;
  if (s->sta_rsn.use_mfp && s->sta_ptk_ready) {
    if (frame[4] & 1u) { /* Multicast/broadcast A1 */
      if (frame[1] & 0x40u) return 0; /* Protected bit invalid on broadcast */
      if (!s->sta_mfp_installed) return 0;
      if (pw3_bip_cmac128_verify(s->sta_igtk, s->sta_igtk_id, s->sta_igtk_pn, frame, len) != 0) return 0;
      return 1;
    } else {
      if (!(frame[1] & 0x40u)) return 0; /* Reject unprotected spoofed unicast deauth */
      if (!hw_decrypted) return 0;
      if (len < 42) return 0; /* 24 hdr + 8 CCMP + 2 reason + 8 MIC */
      return 1;
    }
  }
  return 1;
}

static void run_scenario(const char *name, sim_ap_mode mode, int anti_clog, int wrong_pass) {
  sim_env s;
  memset(&s, 0, sizeof(s));
  s.mode = mode;
  s.anti_clog = anti_clog;
  s.wrong_pass = wrong_pass;
  const uint8_t bssid[6] = { 0x1e,0xec,0x49,0xea,0x64,0x88 };
  const uint8_t sta_m[6] = { 0x82,0x7b,0x91,0x9d,0xd4,0xb9 };
  memcpy(s.bssid, bssid, 6);
  memcpy(s.sta_mac, sta_m, 6);
  s.ssid = "SimTestAP";
  s.ap_pass = "CorrectHorseBattery";
  s.sta_pass = wrong_pass ? "WrongPassword123" : "CorrectHorseBattery";
  s.igtk_id = 4;
  make_bytes(0x31, s.anonce, 32);
  make_bytes(0x73, s.snonce, 32);
  make_bytes(0x91, s.gtk, 16);
  make_bytes(0xa7, s.igtk, 16);
  s.ap_ipn = 1;

  uint8_t ies[128];
  size_t ilen = build_ap_ies(mode, ies);
  ASSERT_TRUE(name, pw3_parse_rsn_ap(ies, ilen, &s.sta_rsn) == 0);

  if (mode == SIM_AP_MIXED_SAE_H2E) {
    ASSERT_TRUE("mixed picks SAE", s.sta_rsn.akm == 8 && s.sta_rsn.use_h2e == 1 && s.sta_rsn.use_mfp == 1 && s.sta_rsn.mfpr == 0);
  } else if (mode == SIM_AP_WPA2_PSK_SHA256_PMF) {
    ASSERT_TRUE("psk256+pmf", s.sta_rsn.akm == 6 && s.sta_rsn.use_mfp == 1 && s.sta_rsn.mfpr == 1);
  } else if (mode == SIM_AP_WPA2_PSK) {
    ASSERT_TRUE("wpa2 psk", s.sta_rsn.akm == 2 && s.sta_rsn.use_mfp == 0);
  }

  /* Authentication Phase */
  if (s.sta_rsn.akm == 8u) {
    int sta_h2e = s.sta_rsn.use_h2e;
    int ap_h2e = (mode == SIM_AP_WPA3_H2E || mode == SIM_AP_MIXED_SAE_H2E || mode == SIM_AP_HNP_REQUIRE_H2E_STATUS126);

    uint8_t sta_rnd[64], ap_rnd[64];
    make_bytes(0x11, sta_rnd, 64);
    make_bytes(0x55, ap_rnd, 64);

    if (sta_h2e) {
      ASSERT_TRUE(name, pw3_sae_derive_pwe_h2e(&s.sta_sae, (const uint8_t *)s.ssid, strlen(s.ssid), s.sta_mac, s.bssid, (const uint8_t *)s.sta_pass, strlen(s.sta_pass)) == 0);
    } else {
      ASSERT_TRUE(name, pw3_sae_derive_pwe_hnp(&s.sta_sae, s.sta_mac, s.bssid, (const uint8_t *)s.sta_pass, strlen(s.sta_pass)) == 0);
    }
    ASSERT_TRUE(name, pw3_sae_commit_begin(&s.sta_sae, sta_rnd) == 0);

    uint8_t token[64]; size_t tok_len = 0;
    for (int step = 0; step < 4; step++) {
      uint8_t tx[200];
      size_t tx_len = pw3_build_sae_commit(&s.sta_sae, token, tok_len, tx, sizeof(tx));
      pw3_sae_rx rx;
      ASSERT_TRUE(name, pw3_parse_sae_auth(tx, tx_len, &rx) == 0);

      /* AP rejects H&P with 6B status 126 when requiring H2E */
      if (rx.status == 0 && ap_h2e) {
        uint8_t rej126[6] = { 3,0, 1,0, 126,0 };
        pw3_sae_rx srx;
        ASSERT_TRUE(name, pw3_parse_sae_auth(rej126, sizeof(rej126), &srx) == 0);
        ASSERT_TRUE("status 126", srx.seq == 1 && srx.status == PW3_SAE_H2E_STATUS);
        s.ap_sent_126 = 1;
        s.sta_rsn.use_h2e = 1;
        ASSERT_TRUE(name, pw3_sae_derive_pwe_h2e(&s.sta_sae, (const uint8_t *)s.ssid, strlen(s.ssid), s.sta_mac, s.bssid, (const uint8_t *)s.sta_pass, strlen(s.sta_pass)) == 0);
        ASSERT_TRUE(name, pw3_sae_commit_begin(&s.sta_sae, sta_rnd) == 0);
        continue;
      }

      /* AP requests anti-clogging token once */
      if (s.anti_clog && !s.ap_sent_aclog) {
        s.ap_sent_aclog = 1;
        uint8_t aclog[32];
        size_t alen = 0;
        aclog[0] = 3; aclog[1] = 0; aclog[2] = 1; aclog[3] = 0; aclog[4] = 76; aclog[5] = 0; aclog[6] = 19; aclog[7] = 0;
        if (ap_h2e) {
          aclog[8] = 255; aclog[9] = 9; aclog[10] = 93;
          make_bytes(0xc1, aclog + 11, 8); alen = 19;
        } else {
          make_bytes(0xc1, aclog + 8, 8); alen = 16;
        }
        pw3_sae_rx srx;
        ASSERT_TRUE(name, pw3_parse_sae_auth(aclog, alen, &srx) == 0);
        ASSERT_TRUE("aclog rx", srx.status == 76 && srx.token_len == 8);
        memcpy(token, srx.token, srx.token_len);
        tok_len = srx.token_len;
        continue;
      }

      /* AP verifies token when required and performs commit + confirm */
      if (s.anti_clog) ASSERT_TRUE("ap saw token", rx.token_len == 8);
      if (ap_h2e) {
        ASSERT_TRUE(name, pw3_sae_derive_pwe_h2e(&s.ap_sae, (const uint8_t *)s.ssid, strlen(s.ssid), s.bssid, s.sta_mac, (const uint8_t *)s.ap_pass, strlen(s.ap_pass)) == 0);
      } else {
        ASSERT_TRUE(name, pw3_sae_derive_pwe_hnp(&s.ap_sae, s.bssid, s.sta_mac, (const uint8_t *)s.ap_pass, strlen(s.ap_pass)) == 0);
      }
      ASSERT_TRUE(name, pw3_sae_commit_begin(&s.ap_sae, ap_rnd) == 0);
      ASSERT_TRUE(name, pw3_sae_process_peer_commit(&s.ap_sae, rx.scalar, rx.elem) == 0);
      ASSERT_TRUE(name, pw3_sae_process_peer_commit(&s.sta_sae, s.ap_sae.own_scalar, s.ap_sae.own_elem) == 0);

      uint8_t sta_cf[40], ap_cf[40];
      ASSERT_TRUE(name, pw3_build_sae_confirm(&s.sta_sae, sta_cf, sizeof(sta_cf)) == 40);
      ASSERT_TRUE(name, pw3_build_sae_confirm(&s.ap_sae,  ap_cf,  sizeof(ap_cf)) == 40);
      pw3_sae_rx r_ap, r_sta;
      ASSERT_TRUE(name, pw3_parse_sae_auth(sta_cf, 40, &r_ap) == 0);
      ASSERT_TRUE(name, pw3_parse_sae_auth(ap_cf,  40, &r_sta) == 0);

      int ok_ap  = pw3_sae_verify_confirm(&s.ap_sae,  r_ap.send_confirm,  r_ap.confirm);
      int ok_sta = pw3_sae_verify_confirm(&s.sta_sae, r_sta.send_confirm, r_sta.confirm);
      if (wrong_pass) {
        ASSERT_TRUE("wrong pass rejected", ok_ap != 0 && ok_sta != 0);
        return;
      }
      ASSERT_TRUE(name, ok_ap == 0 && ok_sta == 0);
      memcpy(s.pmk, s.sta_sae.pmk, 32);
      memcpy(s.pmkid, s.sta_sae.pmkid, 16);
      break;
    }
    if (mode == SIM_AP_HNP_REQUIRE_H2E_STATUS126) ASSERT_TRUE("did fallback to 126", s.ap_sent_126 == 1);
  } else {
    make_bytes(0x5a, s.pmk, 32);
  }

  /* Association Phase */
  uint8_t assoc_rsn[64], assoc_rsnxe[8];
  size_t rlen = pw3_build_assoc_rsn(&s.sta_rsn, s.sta_rsn.akm == 8u ? s.pmkid : NULL, assoc_rsn, sizeof(assoc_rsn));
  size_t xlen = pw3_build_assoc_rsnxe(&s.sta_rsn, assoc_rsnxe, sizeof(assoc_rsnxe));
  s.saw_pmkid_in_assoc = (s.sta_rsn.akm == 8u && rlen == 40);
  s.saw_rsnxe_in_assoc = (s.sta_rsn.akm == 8u && s.sta_rsn.use_h2e && xlen == 3);
  if (s.sta_rsn.akm == 8u) ASSERT_TRUE("sae assoc pmkid", s.saw_pmkid_in_assoc);

  /* 4-Way Handshake (AKM 6/8 AES-CMAC MIC & KDF-384 + IGTK KDE) */
  if (s.sta_rsn.akm >= 6u) {
    pw3_derive_ptk_sha256(s.pmk, s.bssid, s.sta_mac, s.anonce, s.snonce, s.ptk);
    s.sta_ptk_ready = 1;
    s.expected_eapol_ver = (s.sta_rsn.akm == 8u) ? 0u : 3u;
    uint8_t m2[160]; memset(m2, 0, sizeof(m2));
    m2[0] = 2; m2[1] = 3; m2[4] = 2;
    m2[5] = 0x01; m2[6] = (uint8_t)(0x08u | s.expected_eapol_ver);
    memcpy(m2 + 17, s.snonce, 32);
    m2[97] = (uint8_t)(rlen >> 8); m2[98] = (uint8_t)rlen;
    memcpy(m2 + 99, assoc_rsn, rlen);
    uint8_t mic[16], check_mic[16];
    sim_eapol_mic(s.sta_rsn.akm, s.ptk, m2, 99 + rlen, mic);
    memcpy(m2 + 81, mic, 16);
    memset(m2 + 81, 0, 16);
    sim_eapol_mic(s.sta_rsn.akm, s.ptk, m2, 99 + rlen, check_mic);
    ASSERT_TRUE("eapol m2 cmac mic", memcmp(mic, check_mic, 16) == 0);

    if (s.sta_rsn.use_mfp) {
      uint8_t m3_kd[32];
      m3_kd[0] = 0xdd; m3_kd[1] = 28;
      m3_kd[2] = 0x00; m3_kd[3] = 0x0f; m3_kd[4] = 0xac; m3_kd[5] = 9;
      m3_kd[6] = (uint8_t)s.igtk_id; m3_kd[7] = 0;
      m3_kd[8] = 0; m3_kd[9] = 0; m3_kd[10] = 0; m3_kd[11] = 0; m3_kd[12] = 0; m3_kd[13] = 0;
      memcpy(m3_kd + 14, s.igtk, 16);
      m3_kd[30] = 0xdd; m3_kd[31] = 0x00;
      ASSERT_TRUE("m3 igtk kde", pw3_find_igtk_kde(m3_kd, sizeof(m3_kd), &s.sta_igtk_id, s.sta_igtk_pn, s.sta_igtk) == 0);
      s.sta_mfp_installed = 1;
    }
  } else {
    s.sta_ptk_ready = 1;
  }
  s.sta_up = 1;

  /* PMF Deauth / Disassoc Tests */
  if (s.sta_rsn.use_mfp) {
    /* 1. Spoofed unprotected unicast deauth MUST be dropped */
    uint8_t unprot_deauth[26]; memset(unprot_deauth, 0, sizeof(unprot_deauth));
    unprot_deauth[0] = 0xc0; memcpy(unprot_deauth + 4, s.sta_mac, 6); memcpy(unprot_deauth + 10, s.bssid, 6);
    ASSERT_TRUE("drop unprot unicast deauth", rx_deauth_pmf(&s, unprot_deauth, sizeof(unprot_deauth), 0) == 0);

    /* 2. Valid HW-decrypted protected unicast deauth (with 8B CCMP hdr + 8B MIC as ath11k delivers) accepted */
    uint8_t prot_deauth[42]; memset(prot_deauth, 0, sizeof(prot_deauth));
    prot_deauth[0] = 0xc0; prot_deauth[1] = 0x40;
    memcpy(prot_deauth + 4, s.sta_mac, 6); memcpy(prot_deauth + 10, s.bssid, 6);
    prot_deauth[32] = 3;
    ASSERT_TRUE("accept prot unicast deauth", rx_deauth_pmf(&s, prot_deauth, sizeof(prot_deauth), 1) == 1);

    /* 3. Valid broadcast MMIE deauth accepted, and replay dropped */
    uint8_t bcast_deauth[64]; size_t blen = 0;
    build_broadcast_deauth_mmie(s.bssid, s.igtk, s.igtk_id, s.ap_ipn, 7, bcast_deauth, &blen);
    ASSERT_TRUE("accept bcast mmie deauth", rx_deauth_pmf(&s, bcast_deauth, blen, 0) == 1);
    ASSERT_TRUE("drop replay bcast deauth", rx_deauth_pmf(&s, bcast_deauth, blen, 0) == 0);
  }
}

int main(void) {
  run_scenario("wpa2_psk",               SIM_AP_WPA2_PSK,                0, 0);
  run_scenario("wpa2_psk_sha256_pmf",    SIM_AP_WPA2_PSK_SHA256_PMF,     0, 0);
  run_scenario("wpa3_sae_hnp",           SIM_AP_WPA3_HNP,                0, 0);
  run_scenario("wpa3_sae_hnp_aclog",     SIM_AP_WPA3_HNP,                1, 0);
  run_scenario("wpa3_sae_h2e",           SIM_AP_WPA3_H2E,                0, 0);
  run_scenario("wpa3_sae_h2e_aclog",     SIM_AP_WPA3_H2E,                1, 0);
  run_scenario("wpa2_wpa3_mixed",        SIM_AP_MIXED_SAE_H2E,           0, 0);
  run_scenario("wpa3_status126_fallback",SIM_AP_HNP_REQUIRE_H2E_STATUS126,1, 0);
  run_scenario("wpa3_wrong_password",    SIM_AP_WPA3_H2E,                0, 1);

  if (g_fails) {
    printf("FAILED %d simulation checks\n", g_fails);
    return 1;
  }
  printf("ALL sta_sim_wpa3 SCENARIOS PASSED\n");
  return 0;
}
