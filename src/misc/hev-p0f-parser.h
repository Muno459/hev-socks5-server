/*
 ============================================================================
 Name        : hev-p0f-parser.h
 Description : Parse p0f v3 signature strings into HevFingerprint
 ============================================================================
 */

#ifndef __HEV_P0F_PARSER_H__
#define __HEV_P0F_PARSER_H__

#include "hev-fingerprint.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Parse a p0f v3 or JA4T signature string into a HevFingerprint struct.
 * Auto-detects the format.
 *
 * p0f format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
 *   "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0"
 *
 * JA4T format: window_options_mss_wscale_rto
 *   "65535_2-1-3-1-1-4_1460_8_1-2-4-8"
 *
 * Returns heap-allocated HevFingerprint on success, NULL on parse error.
 */
HevFingerprint *hev_p0f_parse (const char *sig);

/*
 * Try to parse a SOCKS5 username as an encoded fingerprint.
 * Dot-separated p0f format, optionally with active params after '~'.
 *
 * "4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0"
 * "4.64.0.1460.mss*20,7.mss,sok,ts,nop,ws.df.0~rto=l,isn=r,ts=1000"
 *
 * Returns NULL if username doesn't match the pattern.
 */
HevFingerprint *hev_p0f_parse_username (const char *username,
                                        unsigned int len);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_P0F_PARSER_H__ */
