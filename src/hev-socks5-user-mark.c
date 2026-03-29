/*
 ============================================================================
 Name        : hev-socks5-user-mark.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2023 hev
 Description : Socks5 User with mark
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "hev-logger.h"
#include "hev-p0f-parser.h"

#include "hev-socks5-user-mark.h"

HevSocks5UserMark *
hev_socks5_user_mark_new (const char *name, unsigned int name_len,
                          const char *pass, unsigned int pass_len,
                          unsigned int mark)
{
    HevSocks5UserMark *self;
    int res;

    self = calloc (1, sizeof (HevSocks5UserMark));
    if (!self)
        return NULL;

    res = hev_socks5_user_mark_construct (self, name, name_len, pass, pass_len,
                                          mark);
    if (res < 0) {
        free (self);
        return NULL;
    }

    LOG_D ("%p socks5 user mark new", self);

    return self;
}

int
hev_socks5_user_mark_construct (HevSocks5UserMark *self, const char *name,
                                unsigned int name_len, const char *pass,
                                unsigned int pass_len, unsigned int mark)
{
    int res;

    res =
        hev_socks5_user_construct (&self->base, name, name_len, pass, pass_len);
    if (res < 0)
        return res;

    LOG_D ("%p socks5 user mark construct", self);

    HEV_OBJECT (self)->klass = HEV_SOCKS5_USER_MARK_TYPE;

    self->mark = mark;

    /*
     * Password format:
     *   "pass(*)"  — password is "pass", client sends FP dynamically
     *   "pass"     — just a password, FP comes from "p0f" field in auth
     *   "(*)"      — no password required, client sends FP dynamically
     *   "*"        — no password required, client sends FP dynamically
     */
    if (pass_len == 1 && pass[0] == '*') {
        self->wildcard = 1;
    } else if (pass_len >= 3) {
        const char *open = memchr (pass, '(', pass_len);
        if (open && pass[pass_len - 1] == ')') {
            int real_len = open - pass;
            int inner_len = (pass + pass_len - 1) - (open + 1);

            if (real_len > 0) {
                self->base.pass[real_len] = '\0';
                self->base.pass_len = real_len;
            } else {
                self->wildcard = 1;
            }

            if (inner_len == 1 && *(open + 1) == '*')
                self->wildcard = 1;
        }
    }

    return 0;
}

static int
hev_socks5_user_mark_checker (HevSocks5User *self, const char *pass,
                              unsigned int pass_len)
{
    HevSocks5UserMark *um = HEV_SOCKS5_USER_MARK (self);
    const char *client_fp = NULL;
    unsigned int client_fp_len = 0;
    const char *client_real = pass;
    unsigned int client_real_len = pass_len;

    /*
     * Client password can be:
     *   "realpass"                — just the password
     *   "4.128.0.1460.65535,..."  — dynamic FP (when wildcard, no real pass)
     *   "realpass(4.128.0...)"    — password + dynamic FP override
     */

    /* Check if client sent password(fp) format */
    if (pass_len > 3) {
        const char *open = memchr (pass, '(', pass_len);
        if (open && pass[pass_len - 1] == ')') {
            client_real_len = open - pass;
            client_fp = open + 1;
            client_fp_len = (pass + pass_len - 1) - client_fp;
        }
    }

    /* Validate password */
    if (um->wildcard && self->pass_len == 0) {
        /* No password required — if no parens, entire pass is the FP */
        if (!client_fp) {
            client_fp = pass;
            client_fp_len = pass_len;
        }
    } else if (um->wildcard) {
        /* Has a real password to check */
        if (client_real_len != self->pass_len ||
            memcmp (client_real, self->pass, self->pass_len) != 0)
            return -1;
        /* If no parens, remainder after password check is the FP */
        if (!client_fp) {
            client_fp = pass;
            client_fp_len = pass_len;
        }
    } else {
        /* Normal user — exact password match */
        if (client_real_len != self->pass_len ||
            memcmp (client_real, self->pass, self->pass_len) != 0)
            return -1;
        /* Still allow FP override in parens */
    }

    /* Save dynamic FP for later parsing in session_bind */
    if (client_fp && client_fp_len > 0) {
        if (um->client_pass)
            free (um->client_pass);
        um->client_pass = malloc (client_fp_len + 1);
        if (um->client_pass) {
            memcpy (um->client_pass, client_fp, client_fp_len);
            um->client_pass[client_fp_len] = '\0';
            um->client_pass_len = client_fp_len;
        }
    }

    return 0;
}

static void
hev_socks5_user_mark_destruct (HevObject *base)
{
    HevSocks5UserMark *self = HEV_SOCKS5_USER_MARK (base);

    LOG_D ("%p socks5 user mark destruct", self);

    if (self->client_pass)
        free (self->client_pass);
    if (self->fingerprint)
        free (self->fingerprint);
    if (self->iface)
        free (self->iface);
    HEV_SOCKS5_USER_TYPE->destruct (base);
}

HevObjectClass *
hev_socks5_user_mark_class (void)
{
    static HevSocks5UserMarkClass klass;
    HevSocks5UserMarkClass *kptr = &klass;
    HevObjectClass *okptr = HEV_OBJECT_CLASS (kptr);

    if (!okptr->name) {
        HevSocks5UserClass *ukptr;

        memcpy (kptr, HEV_SOCKS5_USER_TYPE, sizeof (HevSocks5UserClass));

        okptr->name = "HevSocks5UserMark";
        okptr->destruct = hev_socks5_user_mark_destruct;

        ukptr = HEV_SOCKS5_USER_CLASS (kptr);
        ukptr->checker = hev_socks5_user_mark_checker;
    }

    return okptr;
}
