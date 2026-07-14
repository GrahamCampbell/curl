/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "first.h"

#if defined(USE_SSL) && defined(USE_SSLS_EXPORT)

#define T1678_IMPORT_COUNT 64
#define T1678_FIRST_TICKET_SIZE 4096
#define T1678_FIRST_QUICTP_SIZE 127
#define T1678_FIRST_ALPN_SIZE 10
#define T1678_PEER_KEY "example.test:443:G"
/* The share cache keeps at most two sessions for each peer. */
#define T1678_MAX_SESSIONS 2

static const uint8_t t1678_missing_ticket[] = {
  0x01,                         /* format version */
  0x02, 0x03, 0x04,             /* TLSv1.3 */
  0x03, 0, 0, 0, 0, 0, 0, 0, 0 /* unknown expiry */
};

static const uint8_t t1678_missing_ietf_id[] = {
  0x01,                         /* format version */
  0x04, 0, 1, 'C',              /* ticket */
  0x03, 0, 0, 0, 0, 0, 0, 0, 0 /* unknown expiry */
};

static const uint8_t t1678_missing_valid_until[] = {
  0x01,             /* format version */
  0x04, 0, 1, 'C',  /* ticket */
  0x02, 0x03, 0x04  /* TLSv1.3 */
};

static const uint8_t t1678_empty_ticket[] = {
  0x01,                         /* format version */
  0x04, 0, 0,                   /* empty ticket */
  0x02, 0x03, 0x04,             /* TLSv1.3 */
  0x03, 0, 0, 0, 0, 0, 0, 0, 0 /* unknown expiry */
};

static const uint8_t t1678_expired[] = {
  0x01,                         /* format version */
  0x04, 0, 1, 'E',              /* ticket */
  0x02, 0x03, 0x03,             /* TLSv1.2 */
  0x03, 0, 0, 0, 0, 0, 0, 0, 1 /* expired at 1970-01-01 00:00:01 */
};

struct t1678_export_ctx {
  size_t count;
};

static uint8_t *t1678_make_packet(size_t *packet_len)
{
  const size_t t1678_total =
    1 +                                /* format version */
    1 + 2 + T1678_FIRST_TICKET_SIZE +  /* first ticket */
    1 + 2 +                            /* TLS version */
    1 + 8 +                            /* expiry */
    1 + 2 + T1678_FIRST_QUICTP_SIZE +  /* first QUIC traffic params */
    1 + 2 + T1678_FIRST_ALPN_SIZE +    /* first ALPN params */
    1 + 2 + 1 +                        /* second ticket */
    1 + 2 + 1 +                        /* second ALPN */
    1 + 2 + 1;                         /* second QUIC traffic params */

  uint8_t *packet = curlx_malloc(t1678_total);
  uint8_t *p;

  if(!packet)
    return NULL;

  p = packet;

  /* CURL_SPACK_VERSION */
  *p++ = 0x01;

  /* First CURL_SPACK_TICKET */
  *p++ = 0x04;
  *p++ = (uint8_t)(T1678_FIRST_TICKET_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_TICKET_SIZE & 0x0ff);
  memset(p, 'A', T1678_FIRST_TICKET_SIZE);
  p += T1678_FIRST_TICKET_SIZE;

  /* CURL_SPACK_IETF_ID: TLSv1.3 */
  *p++ = 0x02;
  *p++ = 0x03;
  *p++ = 0x04;

  /* CURL_SPACK_VALID_UNTIL: unknown */
  *p++ = 0x03;
  memset(p, 0, 8);
  p += 8;

  /* First CURL_SPACK_QUICTP */
  *p++ = 0x07;
  *p++ = (uint8_t)(T1678_FIRST_QUICTP_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_QUICTP_SIZE & 0x0ff);
  memset(p, 'Q', T1678_FIRST_QUICTP_SIZE);
  p += T1678_FIRST_QUICTP_SIZE;

  /* First CURL_SPACK_ALPN */
  *p++ = 0x05;
  *p++ = (uint8_t)(T1678_FIRST_ALPN_SIZE >> 8);
  *p++ = (uint8_t)(T1678_FIRST_ALPN_SIZE & 0x0ff);
  memset(p, 'a', T1678_FIRST_ALPN_SIZE);
  p += T1678_FIRST_ALPN_SIZE;

  /* Second CURL_SPACK_TICKET: one byte. */
  *p++ = 0x04;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'B';

  /* Second CURL_SPACK_ALPN: one byte. */
  *p++ = 0x05;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'b';

  /* Second CURL_SPACK_QUICTP: one byte. */
  *p++ = 0x07;
  *p++ = 0x00;
  *p++ = 0x01;
  *p++ = 'R';

  DEBUGASSERT((size_t)(p - packet) == t1678_total);
  *packet_len = t1678_total;
  return packet;
}

static CURLcode t1678_import(CURL *easy,
                             const uint8_t *packet, size_t packet_len)
{
  return curl_easy_ssls_import(easy, T1678_PEER_KEY, NULL, 0,
                               packet, packet_len);
}

static CURLcode t1678_expect_rejected(CURL *easy,
                                      const uint8_t *packet,
                                      size_t packet_len,
                                      const char *name)
{
  CURLcode result = t1678_import(easy, packet, packet_len);

  if(result == CURLE_READ_ERROR)
    return CURLE_OK;

  curl_mfprintf(stderr, "%s packet was not rejected: %d (%s)\n",
                name, (int)result, curl_easy_strerror(result));
  return CURLE_FAILED_INIT;
}

static CURLcode t1678_export(CURL *easy, void *userptr,
                             const char *session_key,
                             const unsigned char *shmac, size_t shmac_len,
                             const unsigned char *sdata, size_t sdata_len,
                             curl_off_t valid_until, int ietf_tls_id,
                             const char *alpn, size_t earlydata_max)
{
  struct t1678_export_ctx *ctx = userptr;

  (void)easy;
  (void)alpn;
  (void)earlydata_max;

  if(!session_key || strcmp(session_key, T1678_PEER_KEY) ||
     !shmac || !shmac_len || !sdata || !sdata_len || valid_until <= 0 ||
     ietf_tls_id != 0x0304) {
    curl_mfprintf(stderr, "invalid exported session\n");
    return CURLE_FAILED_INIT;
  }

  ++ctx->count;
  return CURLE_OK;
}

static CURLcode test_lib1678(const char *URL)
{
  uint8_t *packet;
  size_t packet_len;
  CURLSH *share = NULL;
  CURL *easy = NULL;
  CURLSHcode shrc;
  CURLcode result = CURLE_FAILED_INIT;
  struct t1678_export_ctx export_ctx = { 0 };
  int i;

  (void)URL;
  packet = t1678_make_packet(&packet_len);
  if(!packet)
    goto test_cleanup;

  result = curl_global_init(CURL_GLOBAL_DEFAULT);
  if(result != CURLE_OK)
    goto test_cleanup;

  share = curl_share_init();
  easy = curl_easy_init();

  if(!share || !easy)
    goto test_cleanup;

  shrc = curl_share_setopt(share,
                           CURLSHOPT_SHARE,
                           CURL_LOCK_DATA_SSL_SESSION);
  if(shrc != CURLSHE_OK)
    goto test_cleanup;

  result = curl_easy_setopt(easy, CURLOPT_SHARE, share);
  if(result)
    goto test_cleanup;

  for(i = 0; i < T1678_IMPORT_COUNT; ++i) {
    result = t1678_import(easy, packet, packet_len);
    if(result) {
      curl_mfprintf(stderr,
                    "import %d failed: %d (%s)\n",
                    i, (int)result,
                    curl_easy_strerror(result));
      break;
    }
  }
  if(result)
    goto test_cleanup;

  result = t1678_expect_rejected(easy, t1678_missing_ticket,
                                 sizeof(t1678_missing_ticket),
                                 "missing ticket");
  if(result)
    goto test_cleanup;
  result = t1678_expect_rejected(easy, t1678_missing_ietf_id,
                                 sizeof(t1678_missing_ietf_id),
                                 "missing TLS version");
  if(result)
    goto test_cleanup;
  result = t1678_expect_rejected(easy, t1678_missing_valid_until,
                                 sizeof(t1678_missing_valid_until),
                                 "missing expiry");
  if(result)
    goto test_cleanup;
  result = t1678_expect_rejected(easy, t1678_empty_ticket,
                                 sizeof(t1678_empty_ticket),
                                 "empty ticket");
  if(result)
    goto test_cleanup;

  result = t1678_import(easy, t1678_expired, sizeof(t1678_expired));
  if(result) {
    curl_mfprintf(stderr, "expired packet was not discarded: %d (%s)\n",
                  (int)result, curl_easy_strerror(result));
    goto test_cleanup;
  }

  result = curl_easy_ssls_export(easy, t1678_export, &export_ctx);
  if(result)
    goto test_cleanup;
  if(export_ctx.count != T1678_MAX_SESSIONS) {
    curl_mfprintf(stderr, "expected %d cached sessions, got %zu\n",
                  T1678_MAX_SESSIONS, export_ctx.count);
    result = CURLE_FAILED_INIT;
  }

test_cleanup:
  curlx_free(packet);
  curl_easy_cleanup(easy);
  curl_share_cleanup(share);
  curl_global_cleanup();

  return result;
}
#else
static CURLcode test_lib1678(const char *URL)
{
  (void)URL;
  return CURLE_OK;
}
#endif /* USE_SSL && USE_SSLS_EXPORT */
