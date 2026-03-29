/*
 ============================================================================
 Name        : hev-fingerprint.c
 Author      : TCP/IP Fingerprint Spoofing
 Description : TCP/IP OS Fingerprint application via setsockopt (best effort)
 ============================================================================
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "hev-logger.h"

#include "hev-fingerprint.h"

static int caps_detected;
static int cap_ip_ttl;
static int cap_tcp_maxseg;
static int cap_tcp_window_clamp;
static int cap_ip_mtu_discover;
static int cap_tcp_nodelay;
static int cap_ip_tos;
static int cap_tcp_ecn;
static int cap_tcp_congestion;
static int cap_tcp_keepidle;

static int backend_available;

void
hev_fingerprint_detect_caps (void)
{
    int fd;
    int val;
    int res;

    fd = socket (AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_W ("fingerprint: cannot create probe socket");
        caps_detected = 1;
        return;
    }

    val = 64;
    res = setsockopt (fd, IPPROTO_IP, IP_TTL, &val, sizeof (val));
    cap_ip_ttl = (res == 0);

    val = 1460;
    res = setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &val, sizeof (val));
    cap_tcp_maxseg = (res == 0);

#ifdef TCP_WINDOW_CLAMP
    val = 65535;
    res = setsockopt (fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &val, sizeof (val));
    cap_tcp_window_clamp = (res == 0);
#endif

#ifdef IP_MTU_DISCOVER
    val = IP_PMTUDISC_DO;
    res = setsockopt (fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof (val));
    cap_ip_mtu_discover = (res == 0);
#endif

    val = 1;
    res = setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof (val));
    cap_tcp_nodelay = (res == 0);

    val = 0;
    res = setsockopt (fd, IPPROTO_IP, IP_TOS, &val, sizeof (val));
    cap_ip_tos = (res == 0);

#ifdef TCP_CONGESTION
    {
        char cc[16] = "cubic";
        res = setsockopt (fd, IPPROTO_TCP, TCP_CONGESTION, cc, strlen (cc));
        cap_tcp_congestion = (res == 0);
    }
#endif

#ifdef TCP_KEEPIDLE
    val = 60;
    res = setsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE, &val, sizeof (val));
    cap_tcp_keepidle = (res == 0);
#endif

#ifdef TCP_ECN
    val = 0;
    res = setsockopt (fd, IPPROTO_TCP, TCP_ECN, &val, sizeof (val));
    cap_tcp_ecn = (res == 0);
#endif

    close (fd);
    caps_detected = 1;

    LOG_I ("fingerprint caps: ttl=%d mss=%d wclamp=%d df=%d nodelay=%d "
           "tos=%d cc=%d keepalive=%d ecn=%d",
           cap_ip_ttl, cap_tcp_maxseg, cap_tcp_window_clamp,
           cap_ip_mtu_discover, cap_tcp_nodelay, cap_ip_tos,
           cap_tcp_congestion, cap_tcp_keepidle, cap_tcp_ecn);

    /* Try to initialize eBPF or DKMS backend */
    res = hev_fingerprint_backend_init ();
    if (res == 0)
        backend_available = 1;
    else
        LOG_I ("fingerprint: deep backend not available, setsockopt only");
}

static int
try_setsockopt (int fd, int level, int optname, const void *optval,
                unsigned int optlen, const char *name)
{
    int res;

    res = setsockopt (fd, level, optname, optval, optlen);
    if (res < 0) {
        LOG_I ("fingerprint: %s failed (errno=%d), best effort skip", name,
               errno);
    }
    return res;
}

int
hev_fingerprint_apply_sockopt (int fd, int family, const HevFingerprint *fp)
{
    if (!fp || !caps_detected)
        return 0;

    /* TTL */
    if (fp->flags & HEV_FP_FLAG_TTL) {
        if (cap_ip_ttl) {
            if (family == AF_INET)
                try_setsockopt (fd, IPPROTO_IP, IP_TTL, &fp->ttl,
                                sizeof (fp->ttl), "ttl");
            else
                try_setsockopt (fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &fp->ttl,
                                sizeof (fp->ttl), "ttl/hoplimit");
        } else {
            LOG_I ("fingerprint: ttl not supported, best effort skip");
        }
    }

    /* MSS */
    if (fp->flags & HEV_FP_FLAG_MSS) {
        if (cap_tcp_maxseg)
            try_setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &fp->mss,
                            sizeof (fp->mss), "mss");
        else
            LOG_I ("fingerprint: mss not supported, best effort skip");
    }

    /* Window size (SO_RCVBUF + TCP_WINDOW_CLAMP) */
    if (fp->flags & HEV_FP_FLAG_WINDOW) {
        if (cap_tcp_window_clamp) {
            int rcvbuf = fp->window;
            try_setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
                            sizeof (rcvbuf), "rcvbuf/window");
#ifdef TCP_WINDOW_CLAMP
            try_setsockopt (fd, IPPROTO_TCP, TCP_WINDOW_CLAMP, &fp->window,
                            sizeof (fp->window), "window_clamp");
#endif
        } else {
            LOG_I ("fingerprint: window_clamp not supported, best effort skip");
        }
    }

    /* Explicit SO_RCVBUF override */
    if (fp->flags & HEV_FP_FLAG_RCVBUF) {
        try_setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &fp->rcvbuf,
                        sizeof (fp->rcvbuf), "rcvbuf");
    }

    /* Explicit SO_SNDBUF override */
    if (fp->flags & HEV_FP_FLAG_SNDBUF) {
        try_setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &fp->sndbuf,
                        sizeof (fp->sndbuf), "sndbuf");
    }

    /* DF bit */
    if (fp->flags & HEV_FP_FLAG_DF) {
        if (cap_ip_mtu_discover) {
#ifdef IP_MTU_DISCOVER
            if (family == AF_INET) {
                int val = fp->df ? IP_PMTUDISC_DO : IP_PMTUDISC_DONT;
                try_setsockopt (fd, IPPROTO_IP, IP_MTU_DISCOVER, &val,
                                sizeof (val), "df");
            } else {
                int val = fp->df ? IPV6_PMTUDISC_DO : IPV6_PMTUDISC_DONT;
                try_setsockopt (fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val,
                                sizeof (val), "df/v6");
            }
#endif
        } else {
            LOG_I ("fingerprint: df not supported, best effort skip");
        }
    }

    /* TCP_NODELAY */
    if (fp->flags & HEV_FP_FLAG_NODELAY) {
        if (cap_tcp_nodelay)
            try_setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &fp->nodelay,
                            sizeof (fp->nodelay), "nodelay");
        else
            LOG_I ("fingerprint: nodelay not supported, best effort skip");
    }

    /* IP TOS / traffic class */
    if (fp->flags & HEV_FP_FLAG_TOS) {
        if (cap_ip_tos) {
            if (family == AF_INET)
                try_setsockopt (fd, IPPROTO_IP, IP_TOS, &fp->tos,
                                sizeof (fp->tos), "tos");
            else
                try_setsockopt (fd, IPPROTO_IPV6, IPV6_TCLASS, &fp->tos,
                                sizeof (fp->tos), "tclass");
        } else {
            LOG_I ("fingerprint: tos not supported, best effort skip");
        }
    }

    /* ECN */
#ifdef TCP_ECN
    if (fp->flags & HEV_FP_FLAG_ECN) {
        if (cap_tcp_ecn)
            try_setsockopt (fd, IPPROTO_TCP, TCP_ECN, &fp->ecn,
                            sizeof (fp->ecn), "ecn");
        else
            LOG_I ("fingerprint: ecn not supported, best effort skip");
    }
#endif

    /* Congestion control algorithm */
#ifdef TCP_CONGESTION
    if ((fp->flags & HEV_FP_FLAG_CONGESTION) && fp->congestion[0]) {
        if (cap_tcp_congestion)
            try_setsockopt (fd, IPPROTO_TCP, TCP_CONGESTION, fp->congestion,
                            strlen (fp->congestion), "congestion");
        else
            LOG_I ("fingerprint: congestion not supported, best effort skip");
    }
#endif

    /* Keepalive */
    if (fp->flags & HEV_FP_FLAG_KEEPALIVE) {
        int ka = fp->keepalive;
        try_setsockopt (fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof (ka),
                        "keepalive");
#ifdef TCP_KEEPIDLE
        if (cap_tcp_keepidle && fp->keepalive_idle > 0)
            try_setsockopt (fd, IPPROTO_TCP, TCP_KEEPIDLE,
                            &fp->keepalive_idle, sizeof (fp->keepalive_idle),
                            "keepidle");
        if (cap_tcp_keepidle && fp->keepalive_intvl > 0)
            try_setsockopt (fd, IPPROTO_TCP, TCP_KEEPINTVL,
                            &fp->keepalive_intvl, sizeof (fp->keepalive_intvl),
                            "keepintvl");
        if (cap_tcp_keepidle && fp->keepalive_cnt > 0)
            try_setsockopt (fd, IPPROTO_TCP, TCP_KEEPCNT,
                            &fp->keepalive_cnt, sizeof (fp->keepalive_cnt),
                            "keepcnt");
#endif
    }

    /* Urgent pointer / OOB inline */
    if (fp->flags & HEV_FP_FLAG_URGENT) {
        try_setsockopt (fd, SOL_SOCKET, SO_OOBINLINE, &fp->urgent,
                        sizeof (fp->urgent), "urgent/oobinline");
    }

    /* SYN retransmit count */
#ifdef TCP_SYNCNT
    if (fp->flags2 & HEV_FP_FLAG2_RETRANSMIT) {
        try_setsockopt (fd, IPPROTO_TCP, TCP_SYNCNT,
                        &fp->retransmit_count,
                        sizeof (fp->retransmit_count), "syncnt");
    }
#endif

    /* RTO: TCP_USER_TIMEOUT controls how long to wait for ACK.
     * Must cover the entire retransmit pattern duration. */
#ifdef TCP_USER_TIMEOUT
    if (fp->flags2 & HEV_FP_FLAG2_RTO) {
        int timeout_ms = 0;
        if (fp->rto_count > 0) {
            /* Sum all custom RTO values to get total duration */
            int i;
            for (i = 0; i < fp->rto_count; i++)
                timeout_ms += fp->rto_values[i];
            timeout_ms += timeout_ms / 4; /* 25% margin */
        } else if (fp->rto_initial_ms > 0) {
            timeout_ms = fp->rto_initial_ms * 60; /* generous for preset */
        } else {
            timeout_ms = 120000; /* 2 min default */
        }
        if (timeout_ms < 10000)
            timeout_ms = 10000; /* minimum 10s */
        try_setsockopt (fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
                        &timeout_ms, sizeof (timeout_ms), "user_timeout");
    }
#endif

    /* Deep fingerprint via backend (DKMS) */
    {
        unsigned int deep_flags =
            HEV_FP_FLAG_WSCALE | HEV_FP_FLAG_SACK_PERM |
            HEV_FP_FLAG_TIMESTAMPS | HEV_FP_FLAG_TCP_OPTS |
            HEV_FP_FLAG_IP_ID | HEV_FP_FLAG_NOP_PADDING |
            HEV_FP_FLAG_TS_CLOCK | HEV_FP_FLAG_INIT_WINDOW |
            HEV_FP_FLAG_RST_DF | HEV_FP_FLAG_IP_OPT_LEN |
            HEV_FP_FLAG_QUIRKS | HEV_FP_FLAG_PCLASS |
            HEV_FP_FLAG_WIN_TYPE | HEV_FP_FLAG_SYN_PAYLOAD |
            HEV_FP_FLAG_RST_ACK | HEV_FP_FLAG_RST_TTL |
            HEV_FP_FLAG_RST_WINDOW | HEV_FP_FLAG_FIN_DF |
            HEV_FP_FLAG_FLOW_LABEL | HEV_FP_FLAG_IP_OPTIONS;

        unsigned int deep_flags2 =
            HEV_FP_FLAG2_RTO | HEV_FP_FLAG2_RETRANSMIT |
            HEV_FP_FLAG2_ISN | HEV_FP_FLAG2_TS_INITIAL |
            HEV_FP_FLAG2_SYN_SIZE | HEV_FP_FLAG2_SYN_PADDING |
            HEV_FP_FLAG2_ACK_DF | HEV_FP_FLAG2_IPTTL_GUESS |
            HEV_FP_FLAG2_WIN_BEHAVIOR | HEV_FP_FLAG2_TCP_FLAGS;

        int need_deep = (fp->flags & deep_flags) ||
                        (fp->flags2 & deep_flags2);

        if (need_deep && backend_available) {
            hev_fingerprint_backend_apply (fd, fp);
        } else if (need_deep) {
            LOG_I ("fingerprint: deep parameters set but no eBPF/DKMS "
                   "backend, best effort skip (flags=0x%x flags2=0x%x)",
                   fp->flags & deep_flags, fp->flags2 & deep_flags2);
        }
    }

    return 0;
}

/*
 * Default backend stubs -- overridden when ENABLE_EBPF or ENABLE_DKMS is set.
 * Weak symbols allow the eBPF/DKMS .c files to provide real implementations.
 */
__attribute__ ((weak)) int
hev_fingerprint_backend_init (void)
{
    return -1;
}

__attribute__ ((weak)) int
hev_fingerprint_backend_apply (int fd, const HevFingerprint *fp)
{
    (void)fd;
    (void)fp;
    return -1;
}

__attribute__ ((weak)) void
hev_fingerprint_backend_fini (void)
{
}
