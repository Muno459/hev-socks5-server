/*
 ============================================================================
 Name        : hev-fingerprint.h
 Author      : TCP/IP Fingerprint Spoofing
 Description : Full TCP/IP OS fingerprint definitions — covers p0f, Nmap,
               and active TCP fingerprinting resistance.
 ============================================================================
 */

#ifndef __HEV_FINGERPRINT_H__
#define __HEV_FINGERPRINT_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Flag bits — every configurable parameter has a flag so that unset
 * fields are never touched (partial fingerprints work).  Stored in
 * two 32-bit words (flags / flags2) giving room for 64 knobs.
 */

/* flags word 0 */
#define HEV_FP_FLAG_TTL            (1u << 0)
#define HEV_FP_FLAG_MSS            (1u << 1)
#define HEV_FP_FLAG_WINDOW         (1u << 2)
#define HEV_FP_FLAG_DF             (1u << 3)
#define HEV_FP_FLAG_NODELAY        (1u << 4)
#define HEV_FP_FLAG_WSCALE         (1u << 5)
#define HEV_FP_FLAG_SACK_PERM      (1u << 6)
#define HEV_FP_FLAG_TIMESTAMPS     (1u << 7)
#define HEV_FP_FLAG_TCP_OPTS       (1u << 8)
#define HEV_FP_FLAG_ECN            (1u << 9)
#define HEV_FP_FLAG_IP_ID          (1u << 10)
#define HEV_FP_FLAG_TOS            (1u << 11)
#define HEV_FP_FLAG_NOP_PADDING    (1u << 12)
#define HEV_FP_FLAG_TS_CLOCK       (1u << 13)
#define HEV_FP_FLAG_INIT_WINDOW    (1u << 14)
#define HEV_FP_FLAG_SNDBUF         (1u << 15)
#define HEV_FP_FLAG_RCVBUF         (1u << 16)
#define HEV_FP_FLAG_KEEPALIVE      (1u << 17)
#define HEV_FP_FLAG_URGENT         (1u << 18)
#define HEV_FP_FLAG_RST_DF         (1u << 19)
#define HEV_FP_FLAG_CONGESTION     (1u << 20)
/* p0f quirks & extra */
#define HEV_FP_FLAG_IP_OPT_LEN     (1u << 21)
#define HEV_FP_FLAG_QUIRKS         (1u << 22)
#define HEV_FP_FLAG_PCLASS         (1u << 23)
#define HEV_FP_FLAG_WIN_TYPE       (1u << 24)
#define HEV_FP_FLAG_SYN_PAYLOAD    (1u << 25)
#define HEV_FP_FLAG_RST_ACK        (1u << 26)
#define HEV_FP_FLAG_RST_TTL        (1u << 27)
#define HEV_FP_FLAG_RST_WINDOW     (1u << 28)
#define HEV_FP_FLAG_FIN_DF         (1u << 29)
#define HEV_FP_FLAG_FLOW_LABEL     (1u << 30)
#define HEV_FP_FLAG_IP_OPTIONS     (1u << 31)

/* flags2 word */
#define HEV_FP_FLAG2_RTO           (1u << 0)
#define HEV_FP_FLAG2_RETRANSMIT    (1u << 1)
#define HEV_FP_FLAG2_ISN           (1u << 2)
#define HEV_FP_FLAG2_TS_INITIAL    (1u << 3)
#define HEV_FP_FLAG2_SYN_SIZE      (1u << 4)
#define HEV_FP_FLAG2_SYN_PADDING   (1u << 5)
#define HEV_FP_FLAG2_ACK_DF        (1u << 6)
#define HEV_FP_FLAG2_IPTTL_GUESS   (1u << 7)
#define HEV_FP_FLAG2_WIN_BEHAVIOR  (1u << 8)
#define HEV_FP_FLAG2_TCP_FLAGS     (1u << 9)
#define HEV_FP_FLAG2_OPT_STRIP    (1u << 10)

#define HEV_FP_MAX_TCP_OPTIONS 16
#define HEV_FP_MAX_IP_OPTIONS  40
#define HEV_FP_MAX_SYN_PADDING 64

/* TCP option kind numbers (IANA) */
#define HEV_TCP_OPT_EOL        0
#define HEV_TCP_OPT_NOP        1
#define HEV_TCP_OPT_MSS        2
#define HEV_TCP_OPT_WSCALE     3
#define HEV_TCP_OPT_SACK_PERM  4
#define HEV_TCP_OPT_SACK       5
#define HEV_TCP_OPT_TIMESTAMPS 8

/* IP ID behavior modes */
#define HEV_FP_IPID_INCR      0   /* incrementing (Linux default) */
#define HEV_FP_IPID_RANDOM    1   /* random (Windows) */
#define HEV_FP_IPID_ZERO      2   /* zero (some BSD, DF=1 Linux) */
#define HEV_FP_IPID_CONST     3   /* constant (rare, some embedded) */

/* NOP padding strategies */
#define HEV_FP_PAD_NONE       0
#define HEV_FP_PAD_FRONT      1   /* NOPs before option */
#define HEV_FP_PAD_BACK       2   /* NOPs after option */
#define HEV_FP_PAD_ALIGN4     3   /* align to 4-byte boundaries */

/* Window size mode (p0f wsize field) */
#define HEV_FP_WIN_NORMAL     0   /* absolute value */
#define HEV_FP_WIN_MSS_MULT   1   /* window = N * MSS */
#define HEV_FP_WIN_MTU_MULT   2   /* window = N * MTU */
#define HEV_FP_WIN_MOD        3   /* window % N == 0 */

/* ISN generation patterns */
#define HEV_FP_ISN_RANDOM     0   /* fully random (Linux default) */
#define HEV_FP_ISN_INCR       1   /* incrementing */
#define HEV_FP_ISN_CONST      2   /* constant value */
#define HEV_FP_ISN_TIME_BASED 3   /* time-based increment (Windows) */
#define HEV_FP_ISN_BROKEN     4   /* broken: ISN == 0 */

/* Retransmit timing patterns */
#define HEV_FP_RTO_LINUX      0   /* 1s, 2s, 4s, 8s, 16s, 32s */
#define HEV_FP_RTO_WINDOWS    1   /* 3s, 6s, 12s, 24s, 48s */
#define HEV_FP_RTO_MACOS      2   /* 1s, 1s, 1s, 1s, 2s, 4s */
#define HEV_FP_RTO_CUSTOM     3   /* use rto_values[] */

/* Payload class (p0f pclass) */
#define HEV_FP_PCLASS_ZERO    0   /* no payload in SYN */
#define HEV_FP_PCLASS_NONZERO 1   /* SYN carries payload */
#define HEV_FP_PCLASS_ANY     2   /* either */

/* Window behavior across segments (Nmap OPS/WIN probes) */
#define HEV_FP_WINB_STATIC    0   /* window stays constant */
#define HEV_FP_WINB_SCALE     1   /* window grows/shrinks (normal) */
#define HEV_FP_WINB_NOSCALE   2   /* window = initial always */

/*
 * p0f quirks bitmask — these match the p0f quirk labels.
 * Each bit represents a specific TCP/IP stack behavior quirk.
 */
#define HEV_FP_QUIRK_DF        (1u << 0)  /* DF bit set */
#define HEV_FP_QUIRK_ID_PLUS   (1u << 1)  /* non-zero IP ID when DF set */
#define HEV_FP_QUIRK_ID_MINUS  (1u << 2)  /* zero IP ID when DF not set */
#define HEV_FP_QUIRK_ECN       (1u << 3)  /* ECN support */
#define HEV_FP_QUIRK_ZERO_PLUS (1u << 4)  /* "must be zero" field != 0 */
#define HEV_FP_QUIRK_FLOW      (1u << 5)  /* non-zero IPv6 flow label */
#define HEV_FP_QUIRK_SEQ_MINUS (1u << 6)  /* seq == 0 in SYN */
#define HEV_FP_QUIRK_ACK_PLUS  (1u << 7)  /* ACK num != 0 in SYN */
#define HEV_FP_QUIRK_ACK_MINUS (1u << 8)  /* ACK num == 0 in SYN+ACK */
#define HEV_FP_QUIRK_UPTR_PLUS (1u << 9)  /* urgptr != 0 in non-URG */
#define HEV_FP_QUIRK_URGF_PLUS (1u << 10) /* URG flag in SYN */
#define HEV_FP_QUIRK_PUSHF_PLUS (1u << 11) /* PUSH flag in SYN */
#define HEV_FP_QUIRK_TS1_MINUS (1u << 12) /* own timestamp == 0 */
#define HEV_FP_QUIRK_TS2_PLUS  (1u << 13) /* peer timestamp != 0 in SYN */
#define HEV_FP_QUIRK_OPT_PLUS  (1u << 14) /* non-zero trailing data past opts */
#define HEV_FP_QUIRK_EXWS      (1u << 15) /* excessive window scaling (>14) */
#define HEV_FP_QUIRK_BAD       (1u << 16) /* malformed TCP options */

typedef struct _HevFingerprint HevFingerprint;

struct _HevFingerprint
{
    unsigned int flags;
    unsigned int flags2;

    /* ========== Phase 1: setsockopt fields ========== */

    int ttl;                   /* IP_TTL / IPV6_UNICAST_HOPS */
    int mss;                   /* TCP_MAXSEG */
    int window;                /* TCP_WINDOW_CLAMP */
    int df;                    /* IP_MTU_DISCOVER: 1=set, 0=clear */
    int nodelay;               /* TCP_NODELAY */
    int ecn;                   /* TCP_ECN: 0=off, 1=on, 2=server */
    int tos;                   /* IP_TOS / IPV6_TCLASS (DSCP+ECN byte) */
    int sndbuf;                /* SO_SNDBUF */
    int rcvbuf;                /* SO_RCVBUF */
    int keepalive;             /* SO_KEEPALIVE */
    int keepalive_idle;        /* TCP_KEEPIDLE (seconds) */
    int keepalive_intvl;       /* TCP_KEEPINTVL (seconds) */
    int keepalive_cnt;         /* TCP_KEEPCNT */
    int urgent;                /* SO_OOBINLINE (urgent pointer behavior) */
    char congestion[16];       /* TCP_CONGESTION algorithm name */

    /* ========== Phase 2: eBPF / DKMS deep fields ========== */

    /* --- TCP options --- */
    int wscale;                /* window scaling factor (0-14) */
    int sack_perm;             /* SACK permitted option */
    int timestamps;            /* TCP timestamps enable */
    unsigned char tcp_options_order[HEV_FP_MAX_TCP_OPTIONS];
    int tcp_options_count;
    int nop_padding;           /* HEV_FP_PAD_* strategy */

    /* --- IP layer --- */
    int ip_id_behavior;        /* HEV_FP_IPID_* */
    int ip_opt_len;            /* IP options length (bytes, p0f 'olen') */
    unsigned char ip_options[HEV_FP_MAX_IP_OPTIONS];
    int ip_options_len;        /* actual bytes in ip_options[] */
    unsigned int flow_label;   /* IPv6 flow label (20 bits) */

    /* --- Timing & clocks --- */
    int ts_clock;              /* timestamp clock rate (Hz, e.g. 1000, 250) */
    int ts_initial;            /* initial timestamp value (0 = random) */
    int init_window;           /* initial congestion window (segments) */
    int rto_pattern;           /* HEV_FP_RTO_* */
    int rto_initial_ms;        /* initial RTO in milliseconds */
    int rto_values[16];        /* custom RTO sequence (ms) for RTO_CUSTOM */
    int rto_count;             /* number of entries in rto_values */
    int retransmit_count;      /* max SYN retransmits before giving up */
    int option_strip_after;    /* strip options after N retransmits (Darwin: 10) */

    /* --- ISN (Initial Sequence Number) --- */
    int isn_pattern;           /* HEV_FP_ISN_* */
    unsigned int isn_const;    /* constant ISN value (for ISN_CONST) */
    int isn_incr_rate;         /* increment rate per second (for ISN_TIME_BASED) */

    /* --- RST/FIN/ACK behavior --- */
    int rst_df;                /* DF bit on RST packets */
    int rst_ack;               /* ACK flag on RST packets: 0/1 */
    int rst_ttl;               /* TTL override for RST packets (0=same) */
    int rst_window;            /* window value in RST packets */
    int fin_df;                /* DF bit on FIN packets */
    int ack_df;                /* DF bit on pure ACK packets */

    /* --- p0f signature fields --- */
    int win_type;              /* HEV_FP_WIN_* mode */
    int win_multiplier;        /* for MSS_MULT/MTU_MULT/MOD modes */
    int pclass;                /* HEV_FP_PCLASS_* */
    unsigned int quirks;       /* HEV_FP_QUIRK_* bitmask */

    /* --- SYN packet construction --- */
    int syn_size;              /* total SYN packet size (0=auto) */
    unsigned char syn_payload[HEV_FP_MAX_SYN_PADDING];
    int syn_payload_len;       /* payload attached to SYN (pclass=nonzero) */
    unsigned char syn_padding[HEV_FP_MAX_SYN_PADDING];
    int syn_padding_len;       /* raw option area padding bytes */

    /* --- Window behavior --- */
    int win_behavior;          /* HEV_FP_WINB_* */
    int win_response[6];       /* window values for Nmap OPS/WIN probes */
    int win_response_count;

    /* --- Extra TCP flags quirks --- */
    int syn_urg_ptr;           /* urgent pointer value in SYN */
    int syn_flags_extra;       /* extra flags to OR into SYN (URG,PSH bits) */

    /* --- p0f initial TTL guess --- */
    int ttl_guess;             /* initial TTL before decrement (p0f ittl) */
};

/* Detect which setsockopt capabilities the kernel supports */
void hev_fingerprint_detect_caps (void);

/* Apply setsockopt-level fingerprint options (best effort, logs skipped) */
int hev_fingerprint_apply_sockopt (int fd, int family,
                                   const HevFingerprint *fp);

/* Backend initialization for eBPF or DKMS (call once at startup) */
int hev_fingerprint_backend_init (void);

/* Apply deep fingerprint via eBPF or DKMS (call per-socket before connect) */
int hev_fingerprint_backend_apply (int fd, const HevFingerprint *fp);

/* Backend cleanup (call at shutdown) */
void hev_fingerprint_backend_fini (void);

#ifdef __cplusplus
}
#endif

#endif /* __HEV_FINGERPRINT_H__ */
