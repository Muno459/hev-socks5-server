/*
 ============================================================================
 Name        : hev-socks5-proxy.c
 Author      : Heiher <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2024 hev
 Description : Socks5 Proxy
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <yaml.h>

#include <hev-task.h>
#include <hev-task-system.h>
#include <hev-memory-allocator.h>
#include <hev-socks5-authenticator.h>

#include "hev-config.h"
#include "hev-logger.h"
#include "hev-socks5-worker.h"
#include "hev-socket-factory.h"
#include "hev-socks5-user-mark.h"
#include "hev-fingerprint.h"
#include "hev-p0f-parser.h"

#include "hev-socks5-proxy.h"

static int listen_fd = -1;
static unsigned int workers;

static HevTask *task;
static pthread_t *work_threads;
static HevSocketFactory *factory;
static HevSocks5Worker **worker_list;

static int
hev_socks5_proxy_parse_bool (const char *val)
{
    return (0 == strcmp (val, "true") || 0 == strcmp (val, "1") ||
            0 == strcmp (val, "yes"));
}

static HevFingerprint *
hev_socks5_proxy_parse_fingerprint (yaml_document_t *doc, yaml_node_t *node)
{
    HevFingerprint *fp;
    yaml_node_pair_t *pair;

    if (!node || node->type != YAML_MAPPING_NODE)
        return NULL;

    fp = calloc (1, sizeof (HevFingerprint));
    if (!fp)
        return NULL;

    for (pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *k = yaml_document_get_node (doc, pair->key);
        yaml_node_t *v = yaml_document_get_node (doc, pair->value);
        const char *key;
        const char *val;

        if (!k || k->type != YAML_SCALAR_NODE)
            continue;

        key = (const char *)k->data.scalar.value;

        /* tcp_options_order is a sequence */
        if (v && v->type == YAML_SEQUENCE_NODE &&
            0 == strcmp (key, "tcp_options_order")) {
            yaml_node_item_t *item;
            int count = 0;

            for (item = v->data.sequence.items.start;
                 item < v->data.sequence.items.top &&
                 count < HEV_FP_MAX_TCP_OPTIONS;
                 item++) {
                yaml_node_t *n = yaml_document_get_node (doc, *item);
                const char *opt;

                if (!n || n->type != YAML_SCALAR_NODE)
                    continue;

                opt = (const char *)n->data.scalar.value;
                if (0 == strcmp (opt, "mss"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_MSS;
                else if (0 == strcmp (opt, "wscale"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_WSCALE;
                else if (0 == strcmp (opt, "sack_perm"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_SACK_PERM;
                else if (0 == strcmp (opt, "timestamps"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_TIMESTAMPS;
                else if (0 == strcmp (opt, "nop"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_NOP;
                else if (0 == strcmp (opt, "eol"))
                    fp->tcp_options_order[count++] = HEV_TCP_OPT_EOL;
            }
            fp->tcp_options_count = count;
            fp->flags |= HEV_FP_FLAG_TCP_OPTS;
            continue;
        }

        if (!v || v->type != YAML_SCALAR_NODE)
            continue;

        val = (const char *)v->data.scalar.value;

        /* Phase 1: setsockopt fields */
        if (0 == strcmp (key, "ttl")) {
            fp->ttl = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_TTL;
        } else if (0 == strcmp (key, "mss")) {
            fp->mss = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_MSS;
        } else if (0 == strcmp (key, "window")) {
            fp->window = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_WINDOW;
        } else if (0 == strcmp (key, "df")) {
            fp->df = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_DF;
        } else if (0 == strcmp (key, "nodelay")) {
            fp->nodelay = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_NODELAY;
        } else if (0 == strcmp (key, "ecn")) {
            fp->ecn = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_ECN;
        } else if (0 == strcmp (key, "tos")) {
            fp->tos = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_TOS;
        } else if (0 == strcmp (key, "sndbuf")) {
            fp->sndbuf = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_SNDBUF;
        } else if (0 == strcmp (key, "rcvbuf")) {
            fp->rcvbuf = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_RCVBUF;
        } else if (0 == strcmp (key, "congestion")) {
            strncpy (fp->congestion, val, sizeof (fp->congestion) - 1);
            fp->flags |= HEV_FP_FLAG_CONGESTION;
        } else if (0 == strcmp (key, "keepalive")) {
            fp->keepalive = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_KEEPALIVE;
        } else if (0 == strcmp (key, "keepalive_idle")) {
            fp->keepalive_idle = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_KEEPALIVE;
        } else if (0 == strcmp (key, "keepalive_intvl")) {
            fp->keepalive_intvl = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_KEEPALIVE;
        } else if (0 == strcmp (key, "keepalive_cnt")) {
            fp->keepalive_cnt = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_KEEPALIVE;
        } else if (0 == strcmp (key, "urgent")) {
            fp->urgent = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_URGENT;
        /* Phase 2: deep fields (eBPF / DKMS) */
        } else if (0 == strcmp (key, "wscale")) {
            fp->wscale = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_WSCALE;
        } else if (0 == strcmp (key, "sack_perm")) {
            fp->sack_perm = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_SACK_PERM;
        } else if (0 == strcmp (key, "timestamps")) {
            fp->timestamps = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_TIMESTAMPS;
        } else if (0 == strcmp (key, "ts_clock")) {
            fp->ts_clock = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_TS_CLOCK;
        } else if (0 == strcmp (key, "init_window")) {
            fp->init_window = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_INIT_WINDOW;
        /* --- IP layer --- */
        } else if (0 == strcmp (key, "ip_id")) {
            if (0 == strcmp (val, "incr"))
                fp->ip_id_behavior = HEV_FP_IPID_INCR;
            else if (0 == strcmp (val, "random"))
                fp->ip_id_behavior = HEV_FP_IPID_RANDOM;
            else if (0 == strcmp (val, "zero"))
                fp->ip_id_behavior = HEV_FP_IPID_ZERO;
            else if (0 == strcmp (val, "const"))
                fp->ip_id_behavior = HEV_FP_IPID_CONST;
            fp->flags |= HEV_FP_FLAG_IP_ID;
        } else if (0 == strcmp (key, "ip_opt_len")) {
            fp->ip_opt_len = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_IP_OPT_LEN;
        } else if (0 == strcmp (key, "flow_label")) {
            fp->flow_label = strtoul (val, NULL, 0) & 0xFFFFF;
            fp->flags |= HEV_FP_FLAG_FLOW_LABEL;
        /* --- NOP padding --- */
        } else if (0 == strcmp (key, "nop_padding")) {
            if (0 == strcmp (val, "none"))
                fp->nop_padding = HEV_FP_PAD_NONE;
            else if (0 == strcmp (val, "front"))
                fp->nop_padding = HEV_FP_PAD_FRONT;
            else if (0 == strcmp (val, "back"))
                fp->nop_padding = HEV_FP_PAD_BACK;
            else if (0 == strcmp (val, "align4"))
                fp->nop_padding = HEV_FP_PAD_ALIGN4;
            fp->flags |= HEV_FP_FLAG_NOP_PADDING;
        /* --- Timing --- */
        } else if (0 == strcmp (key, "ts_initial")) {
            fp->ts_initial = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_TS_INITIAL;
        } else if (0 == strcmp (key, "rto_pattern")) {
            if (0 == strcmp (val, "linux"))
                fp->rto_pattern = HEV_FP_RTO_LINUX;
            else if (0 == strcmp (val, "windows"))
                fp->rto_pattern = HEV_FP_RTO_WINDOWS;
            else if (0 == strcmp (val, "macos"))
                fp->rto_pattern = HEV_FP_RTO_MACOS;
            else if (0 == strcmp (val, "custom"))
                fp->rto_pattern = HEV_FP_RTO_CUSTOM;
            fp->flags2 |= HEV_FP_FLAG2_RTO;
        } else if (0 == strcmp (key, "rto_initial_ms")) {
            fp->rto_initial_ms = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_RTO;
        } else if (0 == strcmp (key, "retransmit_count")) {
            fp->retransmit_count = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_RETRANSMIT;
        /* --- ISN --- */
        } else if (0 == strcmp (key, "isn_pattern")) {
            if (0 == strcmp (val, "random"))
                fp->isn_pattern = HEV_FP_ISN_RANDOM;
            else if (0 == strcmp (val, "incr"))
                fp->isn_pattern = HEV_FP_ISN_INCR;
            else if (0 == strcmp (val, "const"))
                fp->isn_pattern = HEV_FP_ISN_CONST;
            else if (0 == strcmp (val, "time_based"))
                fp->isn_pattern = HEV_FP_ISN_TIME_BASED;
            else if (0 == strcmp (val, "broken"))
                fp->isn_pattern = HEV_FP_ISN_BROKEN;
            fp->flags2 |= HEV_FP_FLAG2_ISN;
        } else if (0 == strcmp (key, "isn_const")) {
            fp->isn_const = strtoul (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_ISN;
        } else if (0 == strcmp (key, "isn_incr_rate")) {
            fp->isn_incr_rate = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_ISN;
        /* --- RST/FIN/ACK behavior --- */
        } else if (0 == strcmp (key, "rst_df")) {
            fp->rst_df = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_RST_DF;
        } else if (0 == strcmp (key, "rst_ack")) {
            fp->rst_ack = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_RST_ACK;
        } else if (0 == strcmp (key, "rst_ttl")) {
            fp->rst_ttl = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_RST_TTL;
        } else if (0 == strcmp (key, "rst_window")) {
            fp->rst_window = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_RST_WINDOW;
        } else if (0 == strcmp (key, "fin_df")) {
            fp->fin_df = hev_socks5_proxy_parse_bool (val);
            fp->flags |= HEV_FP_FLAG_FIN_DF;
        } else if (0 == strcmp (key, "ack_df")) {
            fp->ack_df = hev_socks5_proxy_parse_bool (val);
            fp->flags2 |= HEV_FP_FLAG2_ACK_DF;
        /* --- p0f signature fields --- */
        } else if (0 == strcmp (key, "win_type")) {
            if (0 == strcmp (val, "normal"))
                fp->win_type = HEV_FP_WIN_NORMAL;
            else if (0 == strcmp (val, "mss_mult"))
                fp->win_type = HEV_FP_WIN_MSS_MULT;
            else if (0 == strcmp (val, "mtu_mult"))
                fp->win_type = HEV_FP_WIN_MTU_MULT;
            else if (0 == strcmp (val, "mod"))
                fp->win_type = HEV_FP_WIN_MOD;
            fp->flags |= HEV_FP_FLAG_WIN_TYPE;
        } else if (0 == strcmp (key, "win_multiplier")) {
            fp->win_multiplier = strtol (val, NULL, 0);
            fp->flags |= HEV_FP_FLAG_WIN_TYPE;
        } else if (0 == strcmp (key, "pclass")) {
            if (0 == strcmp (val, "zero"))
                fp->pclass = HEV_FP_PCLASS_ZERO;
            else if (0 == strcmp (val, "nonzero"))
                fp->pclass = HEV_FP_PCLASS_NONZERO;
            else if (0 == strcmp (val, "any"))
                fp->pclass = HEV_FP_PCLASS_ANY;
            fp->flags |= HEV_FP_FLAG_PCLASS;
        } else if (0 == strcmp (key, "ttl_guess")) {
            fp->ttl_guess = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_IPTTL_GUESS;
        /* --- SYN packet --- */
        } else if (0 == strcmp (key, "syn_size")) {
            fp->syn_size = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_SYN_SIZE;
        } else if (0 == strcmp (key, "syn_urg_ptr")) {
            fp->syn_urg_ptr = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_TCP_FLAGS;
        } else if (0 == strcmp (key, "syn_flags_extra")) {
            fp->syn_flags_extra = strtol (val, NULL, 0);
            fp->flags2 |= HEV_FP_FLAG2_TCP_FLAGS;
        /* --- Window behavior --- */
        } else if (0 == strcmp (key, "win_behavior")) {
            if (0 == strcmp (val, "static"))
                fp->win_behavior = HEV_FP_WINB_STATIC;
            else if (0 == strcmp (val, "scale"))
                fp->win_behavior = HEV_FP_WINB_SCALE;
            else if (0 == strcmp (val, "noscale"))
                fp->win_behavior = HEV_FP_WINB_NOSCALE;
            fp->flags2 |= HEV_FP_FLAG2_WIN_BEHAVIOR;
        }
    }

    /* Parse quirks bitmask from sequence if present */
    for (pair = node->data.mapping.pairs.start;
         pair < node->data.mapping.pairs.top; pair++) {
        yaml_node_t *k = yaml_document_get_node (doc, pair->key);
        yaml_node_t *v = yaml_document_get_node (doc, pair->value);

        if (!k || k->type != YAML_SCALAR_NODE)
            continue;

        const char *key = (const char *)k->data.scalar.value;

        if (v && v->type == YAML_SEQUENCE_NODE &&
            0 == strcmp (key, "quirks")) {
            yaml_node_item_t *item;
            fp->quirks = 0;
            for (item = v->data.sequence.items.start;
                 item < v->data.sequence.items.top; item++) {
                yaml_node_t *n = yaml_document_get_node (doc, *item);
                const char *q;
                if (!n || n->type != YAML_SCALAR_NODE)
                    continue;
                q = (const char *)n->data.scalar.value;
                if (0 == strcmp (q, "df"))
                    fp->quirks |= HEV_FP_QUIRK_DF;
                else if (0 == strcmp (q, "id+"))
                    fp->quirks |= HEV_FP_QUIRK_ID_PLUS;
                else if (0 == strcmp (q, "id-"))
                    fp->quirks |= HEV_FP_QUIRK_ID_MINUS;
                else if (0 == strcmp (q, "ecn"))
                    fp->quirks |= HEV_FP_QUIRK_ECN;
                else if (0 == strcmp (q, "0+"))
                    fp->quirks |= HEV_FP_QUIRK_ZERO_PLUS;
                else if (0 == strcmp (q, "flow"))
                    fp->quirks |= HEV_FP_QUIRK_FLOW;
                else if (0 == strcmp (q, "seq-"))
                    fp->quirks |= HEV_FP_QUIRK_SEQ_MINUS;
                else if (0 == strcmp (q, "ack+"))
                    fp->quirks |= HEV_FP_QUIRK_ACK_PLUS;
                else if (0 == strcmp (q, "ack-"))
                    fp->quirks |= HEV_FP_QUIRK_ACK_MINUS;
                else if (0 == strcmp (q, "uptr+"))
                    fp->quirks |= HEV_FP_QUIRK_UPTR_PLUS;
                else if (0 == strcmp (q, "urgf+"))
                    fp->quirks |= HEV_FP_QUIRK_URGF_PLUS;
                else if (0 == strcmp (q, "pushf+"))
                    fp->quirks |= HEV_FP_QUIRK_PUSHF_PLUS;
                else if (0 == strcmp (q, "ts1-"))
                    fp->quirks |= HEV_FP_QUIRK_TS1_MINUS;
                else if (0 == strcmp (q, "ts2+"))
                    fp->quirks |= HEV_FP_QUIRK_TS2_PLUS;
                else if (0 == strcmp (q, "opt+"))
                    fp->quirks |= HEV_FP_QUIRK_OPT_PLUS;
                else if (0 == strcmp (q, "exws"))
                    fp->quirks |= HEV_FP_QUIRK_EXWS;
                else if (0 == strcmp (q, "bad"))
                    fp->quirks |= HEV_FP_QUIRK_BAD;
            }
            fp->flags |= HEV_FP_FLAG_QUIRKS;
        }

        /* rto_values sequence */
        if (v && v->type == YAML_SEQUENCE_NODE &&
            0 == strcmp (key, "rto_values")) {
            yaml_node_item_t *item;
            int count = 0;
            for (item = v->data.sequence.items.start;
                 item < v->data.sequence.items.top && count < 16;
                 item++) {
                yaml_node_t *n = yaml_document_get_node (doc, *item);
                if (!n || n->type != YAML_SCALAR_NODE)
                    continue;
                fp->rto_values[count++] =
                    strtol ((const char *)n->data.scalar.value, NULL, 0);
            }
            fp->rto_count = count;
            fp->flags2 |= HEV_FP_FLAG2_RTO;
        }

        /* win_response sequence */
        if (v && v->type == YAML_SEQUENCE_NODE &&
            0 == strcmp (key, "win_response")) {
            yaml_node_item_t *item;
            int count = 0;
            for (item = v->data.sequence.items.start;
                 item < v->data.sequence.items.top && count < 6;
                 item++) {
                yaml_node_t *n = yaml_document_get_node (doc, *item);
                if (!n || n->type != YAML_SCALAR_NODE)
                    continue;
                fp->win_response[count++] =
                    strtol ((const char *)n->data.scalar.value, NULL, 0);
            }
            fp->win_response_count = count;
            fp->flags2 |= HEV_FP_FLAG2_WIN_BEHAVIOR;
        }
    }

    if (!fp->flags && !fp->flags2) {
        free (fp);
        return NULL;
    }

    return fp;
}

static void
hev_socks5_proxy_load_file_yaml (HevSocks5Authenticator *auth,
                                 const char *file)
{
    yaml_parser_t parser;
    yaml_document_t doc;
    yaml_node_t *root;
    FILE *fp;

    fp = fopen (file, "r");
    if (!fp) {
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    if (!yaml_parser_initialize (&parser)) {
        fclose (fp);
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    yaml_parser_set_input_file (&parser, fp);
    if (!yaml_parser_load (&parser, &doc)) {
        yaml_parser_delete (&parser);
        fclose (fp);
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    root = yaml_document_get_root_node (&doc);
    if (root && root->type == YAML_SEQUENCE_NODE) {
        yaml_node_item_t *item;
        for (item = root->data.sequence.items.start;
             item < root->data.sequence.items.top; item++) {
            yaml_node_t *node = yaml_document_get_node (&doc, *item);
            if (!node || node->type != YAML_MAPPING_NODE)
                continue;

            char *username = NULL;
            char *password = NULL;
            char *iface = NULL;
            unsigned long mark = 0;
            HevFingerprint *fp = NULL;

            yaml_node_pair_t *pair;
            for (pair = node->data.mapping.pairs.start;
                 pair < node->data.mapping.pairs.top; pair++) {
                yaml_node_t *k = yaml_document_get_node (&doc, pair->key);
                yaml_node_t *v = yaml_document_get_node (&doc, pair->value);
                const char *key;

                if (!k || !v || k->type != YAML_SCALAR_NODE)
                    continue;

                key = (const char *)k->data.scalar.value;

                if (0 == strcmp (key, "fingerprint") &&
                    v->type == YAML_MAPPING_NODE) {
                    fp = hev_socks5_proxy_parse_fingerprint (&doc, v);
                    continue;
                }

                if (v->type != YAML_SCALAR_NODE)
                    continue;

                const char *val = (const char *)v->data.scalar.value;
                if (0 == strcmp (key, "username"))
                    username = (char *)val;
                else if (0 == strcmp (key, "password"))
                    password = (char *)val;
                else if (0 == strcmp (key, "mark"))
                    mark = strtoul (val, NULL, 0);
                else if (0 == strcmp (key, "iface"))
                    iface = (char *)val;
                else if ((0 == strcmp (key, "p0f") ||
                          0 == strcmp (key, "ja4t") ||
                          0 == strcmp (key, "preset")) && !fp)
                    fp = hev_p0f_parse (val);
            }

            if (username && password) {
                HevSocks5UserMark *user;
                user = hev_socks5_user_mark_new (username, strlen (username),
                                                 password, strlen (password),
                                                 (unsigned int)mark);
                if (!user) {
                    free (fp);
                    continue;
                }
                if (iface && iface[0] != '\0')
                    user->iface = strdup (iface);
                user->fingerprint = fp;
                if (hev_socks5_authenticator_add (auth,
                                                  HEV_SOCKS5_USER (user)) < 0) {
                    hev_object_unref (HEV_OBJECT (user));
                }
            } else {
                free (fp);
            }
        }
    } else if (root && root->type == YAML_MAPPING_NODE) {
        /* Support { "users": [ ... ] } */
        yaml_node_pair_t *pair;
        for (pair = root->data.mapping.pairs.start;
             pair < root->data.mapping.pairs.top; pair++) {
            yaml_node_t *k = yaml_document_get_node (&doc, pair->key);
            yaml_node_t *v = yaml_document_get_node (&doc, pair->value);
            if (!k || !v || k->type != YAML_SCALAR_NODE)
                continue;
            const char *key = (const char *)k->data.scalar.value;
            if (0 == strcmp (key, "users") && v->type == YAML_SEQUENCE_NODE) {
                yaml_node_item_t *item;
                for (item = v->data.sequence.items.start;
                     item < v->data.sequence.items.top; item++) {
                    yaml_node_t *node = yaml_document_get_node (&doc, *item);
                    if (!node || node->type != YAML_MAPPING_NODE)
                        continue;
                    char *username = NULL;
                    char *password = NULL;
                    char *iface = NULL;
                    unsigned long mark = 0;
                    HevFingerprint *fp = NULL;
                    yaml_node_pair_t *mpair;
                    for (mpair = node->data.mapping.pairs.start;
                         mpair < node->data.mapping.pairs.top; mpair++) {
                        yaml_node_t *mk =
                            yaml_document_get_node (&doc, mpair->key);
                        yaml_node_t *mv =
                            yaml_document_get_node (&doc, mpair->value);
                        const char *mkey;

                        if (!mk || !mv || mk->type != YAML_SCALAR_NODE)
                            continue;

                        mkey = (const char *)mk->data.scalar.value;

                        if (0 == strcmp (mkey, "fingerprint") &&
                            mv->type == YAML_MAPPING_NODE) {
                            fp = hev_socks5_proxy_parse_fingerprint (&doc, mv);
                            continue;
                        }

                        if (mv->type != YAML_SCALAR_NODE)
                            continue;

                        const char *mval =
                            (const char *)mv->data.scalar.value;
                        if (0 == strcmp (mkey, "username"))
                            username = (char *)mval;
                        else if (0 == strcmp (mkey, "password"))
                            password = (char *)mval;
                        else if (0 == strcmp (mkey, "mark"))
                            mark = strtoul (mval, NULL, 0);
                        else if (0 == strcmp (mkey, "iface"))
                            iface = (char *)mval;
                        else if ((0 == strcmp (mkey, "p0f") ||
                                  0 == strcmp (mkey, "ja4t") ||
                                  0 == strcmp (mkey, "preset")) && !fp)
                            fp = hev_p0f_parse (mval);
                    }
                    if (username && password) {
                        HevSocks5UserMark *user;
                        user = hev_socks5_user_mark_new (
                            username, strlen (username), password,
                            strlen (password), (unsigned int)mark);
                        if (!user) {
                            free (fp);
                            continue;
                        }
                        if (iface && iface[0] != '\0')
                            user->iface = strdup (iface);
                        user->fingerprint = fp;
                        if (hev_socks5_authenticator_add (
                                auth, HEV_SOCKS5_USER (user)) < 0)
                            hev_object_unref (HEV_OBJECT (user));
                    } else {
                        free (fp);
                    }
                }
            }
        }
    }

    yaml_document_delete (&doc);
    yaml_parser_delete (&parser);
    fclose (fp);
}

static void
hev_socks5_proxy_load_file (HevSocks5Authenticator *auth, const char *file)
{
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    FILE *fp;
    int c;

    fp = fopen (file, "r");
    if (!fp) {
        hev_object_unref (HEV_OBJECT (auth));
        return;
    }

    /* Detect JSON/YAML document and delegate */
    do {
        c = fgetc (fp);
        if (c == EOF)
            break;
    } while (c == ' ' || c == '\t' || c == '\r' || c == '\n');
    if (c == '{' || c == '[') {
        fclose (fp);
        hev_socks5_proxy_load_file_yaml (auth, file);
        return;
    }
    /* Not JSON/YAML sequence, rewind and parse legacy format */
    rewind (fp);

    while ((nread = getline (&line, &len, fp)) != -1) {
        HevSocks5UserMark *user;
        unsigned int nlen;
        unsigned int plen;
        char name[256];
        char pass[256];
        long mark = 0;
        char iface[256] = { 0 };
        int res;

        /* Format: USER PASS [MARK] [SRC_IP] [IFACE]
         * We keep backward compatibility. We parse up to 5 tokens, but only
         * the 1st two are mandatory. MARK remains hexadecimal; IFACE is
         * optional here to bind to device.
         */
        res = sscanf (line, "%255s %255s %lx %*255s %255s\n", name, pass, &mark, iface);
        if (res < 2) {
            /* Try legacy 3-field form */
            res = sscanf (line, "%255s %255s %lx\n", name, pass, &mark);
        }
        if (res < 2) {
            LOG_E ("socks5 proxy user/pass format");
            continue;
        }

        nlen = strlen (name);
        plen = strlen (pass);
        user = hev_socks5_user_mark_new (name, nlen, pass, plen, mark);
        if (!user) {
            LOG_E ("socks5 proxy user new");
            continue;
        }
        if (iface[0] != '\0') {
            user->iface = strdup (iface);
        }
        res = hev_socks5_authenticator_add (auth, HEV_SOCKS5_USER (user));
        if (res < 0) {
            LOG_E ("socks5 proxy user conflict");
            hev_object_unref (HEV_OBJECT (user));
        }
    }

    free (line);
    fclose (fp);
}

static void
hev_socks5_proxy_load (void)
{
    HevSocks5Authenticator *auth;
    const char *file, *name, *pass;
    int i;

    LOG_D ("socks5 proxy load");

    file = hev_config_get_auth_file ();
    name = hev_config_get_auth_username ();
    pass = hev_config_get_auth_password ();

    if (!file && !name && !pass)
        return;

    auth = hev_socks5_authenticator_new ();
    if (!auth)
        return;

    if (file) {
        hev_socks5_proxy_load_file (auth, file);
    } else {
        HevSocks5UserMark *user;

        user = hev_socks5_user_mark_new (name, strlen (name), pass,
                                         strlen (pass), 0);
        if (user)
            hev_socks5_authenticator_add (auth, HEV_SOCKS5_USER (user));
    }

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = worker_list[i];
        hev_socks5_worker_set_auth (worker, auth);
        hev_socks5_worker_reload (worker);
    }

    hev_object_unref (HEV_OBJECT (auth));
}

static void
sigint_handler (int signum)
{
    hev_socks5_proxy_load ();
}

int
hev_socks5_proxy_init (void)
{
    LOG_D ("socks5 proxy init");

    if (hev_task_system_init () < 0) {
        LOG_E ("socks5 proxy task system");
        goto exit;
    }

    task = hev_task_new (-1);
    if (!task) {
        LOG_E ("socks5 proxy task");
        goto exit;
    }

    workers = hev_config_get_workers ();
    work_threads = hev_malloc0 (sizeof (pthread_t) * workers);
    if (!work_threads) {
        LOG_E ("socks5 proxy work threads");
        goto exit;
    }

    worker_list = hev_malloc0 (sizeof (HevSocks5Worker *) * workers);
    if (!worker_list) {
        LOG_E ("socks5 proxy worker list");
        goto exit;
    }

    factory = hev_socket_factory_new (hev_config_get_listen_address (),
                                      hev_config_get_listen_port (),
                                      hev_config_get_listen_ipv6_only ());
    if (!factory) {
        LOG_E ("socks5 proxy socket factory");
        goto exit;
    }

    hev_fingerprint_detect_caps ();

    signal (SIGPIPE, SIG_IGN);
    signal (SIGUSR1, sigint_handler);

    return 0;

exit:
    hev_socks5_proxy_fini ();
    return -1;
}

void
hev_socks5_proxy_fini (void)
{
    LOG_D ("socks5 proxy fini");

    hev_fingerprint_backend_fini ();

    if (task)
        hev_task_unref (task);
    if (work_threads)
        hev_free (work_threads);
    if (worker_list)
        hev_free (worker_list);
    if (factory)
        hev_socket_factory_destroy (factory);
    hev_task_system_fini ();
}

static void *
work_thread_handler (void *data)
{
    HevSocks5Worker **worker = data;
    int res;
    int fd;

    if (hev_task_system_init () < 0) {
        LOG_E ("socks5 proxy worker task system");
        goto exit;
    }

    fd = hev_socket_factory_get (factory);
    if (fd < 0) {
        LOG_E ("socks5 proxy worker socket");
        goto free;
    }

    res = hev_socks5_worker_init (*worker, fd);
    if (res < 0) {
        LOG_E ("socks5 proxy worker init");
        goto free;
    }

    hev_socks5_worker_start (*worker);

    hev_task_system_run ();

    hev_socks5_worker_destroy (*worker);
    *worker = NULL;

free:
    if (fd >= 0)
        close (fd);
    hev_task_system_fini ();
exit:
    return NULL;
}

static void
hev_socks5_proxy_task_entry (void *data)
{
    int res;
    int i;

    LOG_D ("socks5 proxy task run");

    listen_fd = hev_socket_factory_get (factory);
    if (listen_fd < 0)
        return;

    worker_list[0] = hev_socks5_worker_new ();
    if (!worker_list[0]) {
        LOG_E ("socks5 proxy worker");
        return;
    }

    res = hev_socks5_worker_init (worker_list[0], listen_fd);
    if (res < 0) {
        LOG_E ("socks5 proxy worker init");
        return;
    }

    hev_socks5_worker_start (worker_list[0]);

    for (i = 1; i < workers; i++) {
        worker_list[i] = hev_socks5_worker_new ();
        if (!worker_list[i]) {
            LOG_E ("socks5 proxy worker");
            return;
        }

        pthread_create (&work_threads[i], NULL, work_thread_handler,
                        &worker_list[i]);
    }

    hev_socks5_proxy_load ();

    task = NULL;
}

void
hev_socks5_proxy_run (void)
{
    LOG_D ("socks5 proxy run");

    hev_task_run (task, hev_socks5_proxy_task_entry, NULL);

    hev_task_system_run ();

    if (listen_fd >= 0)
        close (listen_fd);

    if (worker_list[0]) {
        int i;

        for (i = 1; i < workers; i++)
            pthread_join (work_threads[i], NULL);

        hev_socks5_worker_destroy (worker_list[0]);
        worker_list[0] = NULL;
    }
}

void
hev_socks5_proxy_stop (void)
{
    int i;

    for (i = 0; i < workers; i++) {
        HevSocks5Worker *worker;

        worker = worker_list[i];
        if (!worker)
            continue;

        hev_socks5_worker_stop (worker);
    }
}
