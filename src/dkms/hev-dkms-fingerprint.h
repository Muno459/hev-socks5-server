/*
 ============================================================================
 Name        : hev-dkms-fingerprint.h
 Description : DKMS kernel module backend for deep TCP/IP fingerprint spoofing
 ============================================================================
 */

#ifndef __HEV_DKMS_FINGERPRINT_H__
#define __HEV_DKMS_FINGERPRINT_H__

#include "hev-fingerprint.h"

#ifdef __cplusplus
extern "C" {
#endif

int hev_dkms_fingerprint_init (void);
int hev_dkms_fingerprint_apply (int fd, const HevFingerprint *fp);
void hev_dkms_fingerprint_fini (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_DKMS_FINGERPRINT_H__ */
