/*
 ============================================================================
 Name        : hev-p0f-parser.c
 Description : Parse p0f v3 signature strings into HevFingerprint.
               Supports two formats:
                 Standard: "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0"
                 Encoded:  "4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0"
               The encoded format can carry active TCP FP params after '~':
                 "4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0~rto=w,isn=t250k,ts=100"
 ============================================================================
 */

#include <stdlib.h>
#include <string.h>

#include "hev-logger.h"
#include "hev-p0f-parser.h"

/* ---- TCP option layout parser ---- */

static int
parse_olayout (HevFingerprint *fp, const char *str)
{
    char buf[256];
    char *p, *tok, *save;
    int count = 0;

    strncpy (buf, str, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';

    for (p = buf; (tok = strtok_r (p, ",", &save)) != NULL; p = NULL) {
        if (count >= HEV_FP_MAX_TCP_OPTIONS)
            break;

        if (0 == strcmp (tok, "mss"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_MSS;
        else if (0 == strcmp (tok, "ws"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_WSCALE;
        else if (0 == strcmp (tok, "sok"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_SACK_PERM;
        else if (0 == strcmp (tok, "sack"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_SACK;
        else if (0 == strcmp (tok, "ts"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_TIMESTAMPS;
        else if (0 == strcmp (tok, "nop"))
            fp->tcp_options_order[count++] = HEV_TCP_OPT_NOP;
        else if (0 == strncmp (tok, "eol", 3)) {
            fp->tcp_options_order[count++] = HEV_TCP_OPT_EOL;
            if (tok[3] == '+') {
                int pad = atoi (tok + 4);
                int i;
                for (i = 0; i < pad && count < HEV_FP_MAX_TCP_OPTIONS; i++)
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_NOP;
            }
        } else if (tok[0] == '?') {
            fp->tcp_options_order[count++] = atoi (tok + 1);
        }
    }

    fp->tcp_options_count = count;
    if (count > 0) {
        fp->flags |= HEV_FP_FLAG_TCP_OPTS;
        int i;
        for (i = 0; i < count; i++) {
            if (fp->tcp_options_order[i] == HEV_TCP_OPT_SACK_PERM) {
                fp->sack_perm = 1;
                fp->flags |= HEV_FP_FLAG_SACK_PERM;
            }
            if (fp->tcp_options_order[i] == HEV_TCP_OPT_TIMESTAMPS) {
                fp->timestamps = 1;
                fp->flags |= HEV_FP_FLAG_TIMESTAMPS;
            }
        }
    }
    return 0;
}

/* ---- Quirks parser ---- */

static int
parse_quirks (HevFingerprint *fp, const char *str)
{
    char buf[128];
    char *p, *tok, *save;

    if (!str || str[0] == '\0')
        return 0;

    strncpy (buf, str, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';
    fp->quirks = 0;

    for (p = buf; (tok = strtok_r (p, ",", &save)) != NULL; p = NULL) {
        if (0 == strcmp (tok, "df")) {
            fp->quirks |= HEV_FP_QUIRK_DF;
            fp->df = 1;
            fp->flags |= HEV_FP_FLAG_DF;
        } else if (0 == strcmp (tok, "id+"))
            fp->quirks |= HEV_FP_QUIRK_ID_PLUS;
        else if (0 == strcmp (tok, "id-"))
            fp->quirks |= HEV_FP_QUIRK_ID_MINUS;
        else if (0 == strcmp (tok, "ecn")) {
            fp->quirks |= HEV_FP_QUIRK_ECN;
            fp->ecn = 1;
            fp->flags |= HEV_FP_FLAG_ECN;
        } else if (0 == strcmp (tok, "0+"))
            fp->quirks |= HEV_FP_QUIRK_ZERO_PLUS;
        else if (0 == strcmp (tok, "flow"))
            fp->quirks |= HEV_FP_QUIRK_FLOW;
        else if (0 == strcmp (tok, "seq-"))
            fp->quirks |= HEV_FP_QUIRK_SEQ_MINUS;
        else if (0 == strcmp (tok, "ack+"))
            fp->quirks |= HEV_FP_QUIRK_ACK_PLUS;
        else if (0 == strcmp (tok, "ack-"))
            fp->quirks |= HEV_FP_QUIRK_ACK_MINUS;
        else if (0 == strcmp (tok, "uptr+"))
            fp->quirks |= HEV_FP_QUIRK_UPTR_PLUS;
        else if (0 == strcmp (tok, "urgf+"))
            fp->quirks |= HEV_FP_QUIRK_URGF_PLUS;
        else if (0 == strcmp (tok, "pushf+"))
            fp->quirks |= HEV_FP_QUIRK_PUSHF_PLUS;
        else if (0 == strcmp (tok, "ts1-"))
            fp->quirks |= HEV_FP_QUIRK_TS1_MINUS;
        else if (0 == strcmp (tok, "ts2+"))
            fp->quirks |= HEV_FP_QUIRK_TS2_PLUS;
        else if (0 == strcmp (tok, "opt+"))
            fp->quirks |= HEV_FP_QUIRK_OPT_PLUS;
        else if (0 == strcmp (tok, "exws"))
            fp->quirks |= HEV_FP_QUIRK_EXWS;
        else if (0 == strcmp (tok, "bad"))
            fp->quirks |= HEV_FP_QUIRK_BAD;
    }

    if (fp->quirks)
        fp->flags |= HEV_FP_FLAG_QUIRKS;
    return 0;
}

/* ---- Window size + scale parser ---- */

static int
parse_wsize_scale (HevFingerprint *fp, const char *str)
{
    char buf[64];
    char *comma;

    strncpy (buf, str, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';

    comma = strchr (buf, ',');
    if (!comma)
        return -1;
    *comma = '\0';

    const char *wsize_str = buf;
    const char *scale_str = comma + 1;

    if (wsize_str[0] != '*') {
        if (0 == strncmp (wsize_str, "mss*", 4)) {
            fp->win_type = HEV_FP_WIN_MSS_MULT;
            fp->win_multiplier = atoi (wsize_str + 4);
            fp->window =
                (fp->flags & HEV_FP_FLAG_MSS) ?
                    fp->mss * fp->win_multiplier :
                    1460 * fp->win_multiplier;
            fp->flags |= HEV_FP_FLAG_WIN_TYPE | HEV_FP_FLAG_WINDOW;
        } else if (0 == strncmp (wsize_str, "mtu*", 4)) {
            fp->win_type = HEV_FP_WIN_MTU_MULT;
            fp->win_multiplier = atoi (wsize_str + 4);
            fp->window = 1500 * fp->win_multiplier;
            fp->flags |= HEV_FP_FLAG_WIN_TYPE | HEV_FP_FLAG_WINDOW;
        } else if (wsize_str[0] == '%') {
            fp->win_type = HEV_FP_WIN_MOD;
            fp->win_multiplier = atoi (wsize_str + 1);
            fp->window = fp->win_multiplier;
            fp->flags |= HEV_FP_FLAG_WIN_TYPE | HEV_FP_FLAG_WINDOW;
        } else {
            fp->win_type = HEV_FP_WIN_NORMAL;
            fp->window = atoi (wsize_str);
            fp->flags |= HEV_FP_FLAG_WIN_TYPE | HEV_FP_FLAG_WINDOW;
        }
    }

    if (scale_str[0] != '*') {
        fp->wscale = atoi (scale_str);
        fp->flags |= HEV_FP_FLAG_WSCALE;
    }
    return 0;
}

/* ---- Active TCP FP extras parser (after '~') ---- */

static void
parse_active_params (HevFingerprint *fp, const char *str)
{
    char buf[256];
    char *p, *tok, *save;

    strncpy (buf, str, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';

    for (p = buf; (tok = strtok_r (p, ",", &save)) != NULL; p = NULL) {
        char *eq = strchr (tok, '=');
        if (!eq)
            continue;
        *eq = '\0';
        const char *key = tok;
        const char *val = eq + 1;

        if (0 == strcmp (key, "rto")) {
            if (val[0] == 'l') {
                fp->rto_pattern = HEV_FP_RTO_LINUX;
                fp->rto_initial_ms = 1000;
            } else if (val[0] == 'w') {
                fp->rto_pattern = HEV_FP_RTO_WINDOWS;
                fp->rto_initial_ms = 3000;
            } else if (val[0] == 'm') {
                fp->rto_pattern = HEV_FP_RTO_MACOS;
                fp->rto_initial_ms = 1000;
            } else if (strchr (val, '-')) {
                /* Custom pattern: rto=1000-1000-2000-4000-8000 */
                char rtobuf[128];
                char *rp, *rtok, *rsave;
                int rc = 0;
                fp->rto_pattern = HEV_FP_RTO_CUSTOM;
                strncpy (rtobuf, val, sizeof (rtobuf) - 1);
                rtobuf[sizeof (rtobuf) - 1] = '\0';
                for (rp = rtobuf;
                     rc < 16 &&
                     (rtok = strtok_r (rp, "-", &rsave)) != NULL;
                     rp = NULL)
                    fp->rto_values[rc++] = atoi (rtok);
                fp->rto_count = rc;
                if (rc > 0)
                    fp->rto_initial_ms = fp->rto_values[0];
            } else {
                fp->rto_initial_ms = atoi (val);
            }
            fp->flags2 |= HEV_FP_FLAG2_RTO;
        } else if (0 == strcmp (key, "isn")) {
            if (val[0] == 'r')
                fp->isn_pattern = HEV_FP_ISN_RANDOM;
            else if (val[0] == 'i')
                fp->isn_pattern = HEV_FP_ISN_INCR;
            else if (val[0] == 't') {
                fp->isn_pattern = HEV_FP_ISN_TIME_BASED;
                if (val[1])
                    fp->isn_incr_rate = atoi (val + 1);
            } else if (val[0] == 'c') {
                fp->isn_pattern = HEV_FP_ISN_CONST;
                if (val[1])
                    fp->isn_const = strtoul (val + 1, NULL, 0);
            }
            fp->flags2 |= HEV_FP_FLAG2_ISN;
        } else if (0 == strcmp (key, "ts")) {
            fp->ts_clock = atoi (val);
            fp->flags |= HEV_FP_FLAG_TS_CLOCK;
        } else if (0 == strcmp (key, "cc")) {
            strncpy (fp->congestion, val, sizeof (fp->congestion) - 1);
            fp->flags |= HEV_FP_FLAG_CONGESTION;
        } else if (0 == strcmp (key, "rst")) {
            /* rst=d (DF on RST), rst=a (ACK on RST), rst=da (both) */
            const char *c = val;
            while (*c) {
                if (*c == 'd') {
                    fp->rst_df = 1;
                    fp->flags |= HEV_FP_FLAG_RST_DF;
                } else if (*c == 'a') {
                    fp->rst_ack = 1;
                    fp->flags |= HEV_FP_FLAG_RST_ACK;
                }
                c++;
            }
        } else if (0 == strcmp (key, "tos")) {
            fp->tos = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_TOS;
        } else if (0 == strcmp (key, "ecn")) {
            fp->ecn = atoi (val);
            fp->flags |= HEV_FP_FLAG_ECN;
        } else if (0 == strcmp (key, "strip")) {
            fp->option_strip_after = atoi (val);
            fp->flags2 |= HEV_FP_FLAG2_OPT_STRIP;
        }
    }
}

/* ---- Core parser: handles both ':' and '.' separated formats ---- */

static HevFingerprint *
parse_p0f_fields (char *buf)
{
    HevFingerprint *fp;
    char *fields[8];
    char *active = NULL;
    char *p, *save;
    int n = 0;
    char sep;

    /* Detect separator: '.' (encoded) or ':' (standard) */
    if (strchr (buf, ':'))
        sep = ':';
    else
        sep = '.';

    /* Split off active params after '~' */
    active = strchr (buf, '~');
    if (active) {
        *active = '\0';
        active++;
    }

    /* Split into 8 fields */
    char sep_str[2] = { sep, '\0' };
    for (p = buf; n < 8 && (fields[n] = strtok_r (p, sep_str, &save)) != NULL;
         p = NULL)
        n++;

    if (n < 8)
        return NULL;

    fp = calloc (1, sizeof (HevFingerprint));
    if (!fp)
        return NULL;

    /* Field 0: ver — skip */

    /* Field 1: ittl */
    if (fields[1][0] != '*') {
        char *plus = strchr (fields[1], '+');
        if (plus)
            *plus = '\0';
        fp->ttl = atoi (fields[1]);
        fp->ttl_guess = fp->ttl;
        fp->flags |= HEV_FP_FLAG_TTL;
        fp->flags2 |= HEV_FP_FLAG2_IPTTL_GUESS;
    }

    /* Field 2: olen */
    if (fields[2][0] != '*') {
        fp->ip_opt_len = atoi (fields[2]);
        if (fp->ip_opt_len > 0)
            fp->flags |= HEV_FP_FLAG_IP_OPT_LEN;
    }

    /* Field 3: mss */
    if (fields[3][0] != '*') {
        fp->mss = atoi (fields[3]);
        fp->flags |= HEV_FP_FLAG_MSS;
    }

    /* Field 4: wsize,scale */
    parse_wsize_scale (fp, fields[4]);

    /* Field 5: olayout */
    parse_olayout (fp, fields[5]);

    /* Field 6: quirks */
    parse_quirks (fp, fields[6]);

    /* Field 7: pclass */
    if (fields[7][0] == '0')
        fp->pclass = HEV_FP_PCLASS_ZERO;
    else if (fields[7][0] == '+')
        fp->pclass = HEV_FP_PCLASS_NONZERO;
    else
        fp->pclass = HEV_FP_PCLASS_ANY;
    fp->flags |= HEV_FP_FLAG_PCLASS;

    /* Derive DF */
    if ((fp->quirks & HEV_FP_QUIRK_DF) && !(fp->flags & HEV_FP_FLAG_DF)) {
        fp->df = 1;
        fp->flags |= HEV_FP_FLAG_DF;
    }

    /* Derive IP ID from quirks */
    if (fp->quirks & HEV_FP_QUIRK_ID_PLUS) {
        fp->ip_id_behavior = HEV_FP_IPID_RANDOM;
        fp->flags |= HEV_FP_FLAG_IP_ID;
    } else if (fp->quirks & HEV_FP_QUIRK_ID_MINUS) {
        fp->ip_id_behavior = HEV_FP_IPID_ZERO;
        fp->flags |= HEV_FP_FLAG_IP_ID;
    } else if (fp->df) {
        fp->ip_id_behavior = HEV_FP_IPID_ZERO;
        fp->flags |= HEV_FP_FLAG_IP_ID;
    }

    /* Active TCP FP extras */
    if (active && active[0])
        parse_active_params (fp, active);

    LOG_D ("p0f: parsed TTL=%d MSS=%d WIN=%d WS=%d DF=%d opts=%d q=0x%x",
           fp->ttl, fp->mss, fp->window, fp->wscale, fp->df,
           fp->tcp_options_count, fp->quirks);

    return fp;
}

/* ---- JA4T parser ---- */

/*
 * JA4T format: window_options_mss_wscale[_rto]
 *
 * Fields separated by '_':
 *   a: TCP window size (e.g. 65535)
 *   b: TCP options as hyphen-separated kind numbers (e.g. 2-1-3-1-1-4)
 *   c: MSS value (e.g. 1460)
 *   d: Window scale (e.g. 8)
 *   e: (optional) RTO timings in seconds (e.g. 1-2-4-8 or 1-2-4-8-R6)
 *
 * Option kind numbers: 0=EOL 1=NOP 2=MSS 3=WS 4=SACK 8=TS
 */
static HevFingerprint *
parse_ja4t (char *buf)
{
    HevFingerprint *fp;
    char *fields[5] = { 0 };
    char *p, *save;
    int n = 0;

    for (p = buf; n < 5 && (fields[n] = strtok_r (p, "_", &save)) != NULL;
         p = NULL)
        n++;

    if (n < 4)
        return NULL;

    fp = calloc (1, sizeof (HevFingerprint));
    if (!fp)
        return NULL;

    /* Field a: window size */
    fp->window = atoi (fields[0]);
    fp->flags |= HEV_FP_FLAG_WINDOW;

    /* Field b: TCP options (hyphen-separated kind numbers) */
    {
        char optbuf[128];
        char *op, *osave;
        int oc = 0;
        strncpy (optbuf, fields[1], sizeof (optbuf) - 1);
        optbuf[sizeof (optbuf) - 1] = '\0';
        for (op = optbuf;
             oc < HEV_FP_MAX_TCP_OPTIONS &&
             (p = strtok_r (op, "-", &osave)) != NULL;
             op = NULL) {
            int kind = atoi (p);
            fp->tcp_options_order[oc++] = kind;
            /* Derive flags from presence */
            switch (kind) {
            case HEV_TCP_OPT_WSCALE:
                fp->flags |= HEV_FP_FLAG_WSCALE;
                break;
            case HEV_TCP_OPT_SACK_PERM:
                fp->sack_perm = 1;
                fp->flags |= HEV_FP_FLAG_SACK_PERM;
                break;
            case HEV_TCP_OPT_TIMESTAMPS:
                fp->timestamps = 1;
                fp->flags |= HEV_FP_FLAG_TIMESTAMPS;
                break;
            }
        }
        fp->tcp_options_count = oc;
        fp->flags |= HEV_FP_FLAG_TCP_OPTS;
    }

    /* Field c: MSS */
    fp->mss = atoi (fields[2]);
    fp->flags |= HEV_FP_FLAG_MSS;

    /* Field d: window scale */
    fp->wscale = atoi (fields[3]);
    fp->flags |= HEV_FP_FLAG_WSCALE;

    /* Default TTL: guess from window size (Windows=128, else 64) */
    if (fp->window == 65535 && !fp->timestamps) {
        fp->ttl = 128; /* Windows-like */
        fp->df = 1;
        fp->ip_id_behavior = HEV_FP_IPID_RANDOM;
        fp->flags |= HEV_FP_FLAG_IP_ID;
    } else {
        fp->ttl = 64; /* Unix-like */
        fp->df = 1;
    }
    fp->flags |= HEV_FP_FLAG_TTL | HEV_FP_FLAG_DF;

    /* Field e: RTO timings (optional) */
    if (n >= 5 && fields[4] && fields[4][0]) {
        char rtobuf[128];
        char *rp, *rtok, *rsave;
        int rc = 0;
        strncpy (rtobuf, fields[4], sizeof (rtobuf) - 1);
        rtobuf[sizeof (rtobuf) - 1] = '\0';

        /* Check for R<count> suffix (e.g. "1-2-4-8-R6") */
        char *rflag = strrchr (rtobuf, 'R');
        if (rflag) {
            fp->retransmit_count = atoi (rflag + 1);
            fp->flags2 |= HEV_FP_FLAG2_RETRANSMIT;
            *rflag = '\0'; /* trim R suffix */
            /* Remove trailing '-' if present */
            int rlen = strlen (rtobuf);
            if (rlen > 0 && rtobuf[rlen - 1] == '-')
                rtobuf[rlen - 1] = '\0';
        }

        fp->rto_pattern = HEV_FP_RTO_CUSTOM;
        for (rp = rtobuf;
             rc < 16 && (rtok = strtok_r (rp, "-", &rsave)) != NULL;
             rp = NULL) {
            /* JA4T uses seconds, convert to ms */
            fp->rto_values[rc++] = atoi (rtok) * 1000;
        }
        fp->rto_count = rc;
        if (rc > 0)
            fp->rto_initial_ms = fp->rto_values[0];
        fp->flags2 |= HEV_FP_FLAG2_RTO;
    }

    LOG_D ("ja4t: parsed WIN=%d MSS=%d WS=%d opts=%d rto_count=%d",
           fp->window, fp->mss, fp->wscale, fp->tcp_options_count,
           fp->rto_count);

    return fp;
}

/*
 * Detect format: JA4T uses '_' separator, p0f uses ':' or '.'
 */
static int
is_ja4t_format (const char *sig)
{
    /* JA4T starts with a number (window size) and contains '_' */
    if (!sig || !sig[0])
        return 0;
    if (sig[0] < '0' || sig[0] > '9')
        return 0;
    if (!strchr (sig, '_'))
        return 0;
    /* p0f starts with version (4 or 6) then ':' or '.'
     * JA4T window sizes are > 6, so if first field > 9 it's JA4T */
    char first[16];
    const char *us = strchr (sig, '_');
    int flen = us - sig;
    if (flen <= 0 || flen > 15)
        return 0;
    memcpy (first, sig, flen);
    first[flen] = '\0';
    int val = atoi (first);
    /* p0f version is 4 or 6. JA4T window is typically > 100 */
    return val > 6;
}

/* ---- Public API ---- */

HevFingerprint *
hev_p0f_parse (const char *sig)
{
    char buf[512];

    if (!sig || !sig[0])
        return NULL;

    strncpy (buf, sig, sizeof (buf) - 1);
    buf[sizeof (buf) - 1] = '\0';

    if (is_ja4t_format (buf))
        return parse_ja4t (buf);

    return parse_p0f_fields (buf);
}

/*
 * Try to parse a SOCKS5 username as an encoded fingerprint.
 * Returns heap-allocated HevFingerprint if the username matches
 * the encoding pattern, NULL otherwise (treat as normal username).
 *
 * Encoded format (dot-separated p0f):
 *   "4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0"
 *   "4.64.0.1460.mss*20,7.mss,sok,ts,nop,ws.df.0~rto=l,isn=r"
 *
 * Detection: starts with "4." or "6." or "*." and has exactly 7 dots
 * before any '~'.
 */
HevFingerprint *
hev_p0f_parse_username (const char *username, unsigned int len)
{
    char buf[256];
    const char *p;
    int dots = 0;

    if (!username || len < 5 || len > 250)
        return NULL;

    if (len >= sizeof (buf))
        return NULL;

    memcpy (buf, username, len);
    buf[len] = '\0';

    /* Try JA4T format first (starts with digits, has '_') */
    if (is_ja4t_format (buf))
        return parse_ja4t (buf);

    /* p0f format: must start with "4." or "6." or "*." */
    if (username[1] != '.')
        return NULL;
    if (username[0] != '4' && username[0] != '6' && username[0] != '*')
        return NULL;

    /* Count dots before '~' - need exactly 7 for 8 fields */
    for (p = username; p < username + len && *p != '~'; p++) {
        if (*p == '.')
            dots++;
    }
    if (dots != 7)
        return NULL;

    return parse_p0f_fields (buf);
}
