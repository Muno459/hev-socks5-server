/*
 ============================================================================
 Name        : hev-dkms-fingerprint.c
 Description : Userspace interface to the DKMS kernel module for deep TCP/IP
               fingerprint spoofing. Communicates with the kernel module via
               a character device (/dev/hev-tcpfp) or netlink.
 ============================================================================
 */

#ifdef ENABLE_DKMS

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "hev-logger.h"
#include "hev-fingerprint.h"
#include "hev-dkms-fingerprint.h"

/* ioctl commands for /dev/hev-tcpfp */
#define HEV_TCPFP_IOC_MAGIC 'T'
#define HEV_TCPFP_IOC_SET   _IOW(HEV_TCPFP_IOC_MAGIC, 1, struct hev_tcpfp_req)
#define HEV_TCPFP_IOC_DEL   _IOW(HEV_TCPFP_IOC_MAGIC, 2, uint64_t)

/*
 * Request structure passed to kernel module via ioctl.
 * Must match the kernel module's definition (using userspace types).
 */
struct hev_tcpfp_req
{
    uint64_t sock_cookie;

    /* TCP SYN construction */
    uint16_t tcp_window;
    uint8_t wscale;
    uint8_t sack_perm;
    uint8_t timestamps;
    uint8_t tcp_options_order[16];
    uint8_t tcp_options_count;
    uint8_t nop_padding;

    /* IP layer */
    uint8_t ip_id_behavior;
    uint8_t rst_df;
    uint8_t ip_opt_len;
    uint8_t ip_options[40];
    uint8_t ip_options_len;

    /* Timing */
    uint32_t ts_clock;
    uint32_t ts_initial;
    uint32_t init_window;
    uint32_t rto_initial_ms;
    uint8_t rto_pattern;
    uint16_t rto_values[16];
    uint8_t rto_count;
    uint8_t retransmit_count;

    /* ISN */
    uint8_t isn_pattern;
    uint32_t isn_const;
    uint32_t isn_incr_rate;

    /* RST/FIN/ACK */
    uint8_t rst_ack;
    uint8_t rst_ttl;
    uint16_t rst_window;
    uint8_t fin_df;
    uint8_t ack_df;

    /* p0f quirks */
    uint32_t quirks;
    uint8_t pclass;
    uint8_t win_type;
    uint16_t win_multiplier;
    uint32_t flow_label;

    /* SYN packet */
    uint16_t syn_size;
    uint16_t syn_urg_ptr;
    uint8_t syn_flags_extra;
    uint8_t syn_payload[64];
    uint8_t syn_payload_len;
    uint8_t syn_padding[64];
    uint8_t syn_padding_len;

    /* Window behavior */
    uint8_t win_behavior;
    uint16_t win_response[6];
    uint8_t win_response_count;

    /* Option stripping (Darwin: strip after 10 retransmits) */
    uint8_t option_strip_after;
};

static int dev_fd = -1;

int
hev_fingerprint_backend_init (void)
{
    dev_fd = open ("/dev/hev-tcpfp", O_RDWR);
    if (dev_fd < 0) {
        LOG_D ("dkms: cannot open /dev/hev-tcpfp (errno=%d)", errno);
        return -1;
    }

    LOG_I ("dkms: fingerprint backend initialized via /dev/hev-tcpfp");
    return 0;
}

int
hev_fingerprint_backend_apply (int fd, const HevFingerprint *fp)
{
    struct hev_tcpfp_req req = { 0 };
    uint64_t cookie = 0;
    socklen_t clen = sizeof (cookie);
    int res;
    int i;

    if (dev_fd < 0 || !fp)
        return -1;

    res = getsockopt (fd, SOL_SOCKET, SO_COOKIE, &cookie, &clen);
    if (res < 0) {
        LOG_I ("dkms: cannot get socket cookie (errno=%d)", errno);
        return -1;
    }

    req.sock_cookie = cookie;

    /* Window — pass the exact value to be written into th->window */
    if (fp->flags & HEV_FP_FLAG_WINDOW)
        req.tcp_window = fp->window;

    /* TCP options */
    if (fp->flags & HEV_FP_FLAG_WSCALE)
        req.wscale = fp->wscale;
    if (fp->flags & HEV_FP_FLAG_SACK_PERM)
        req.sack_perm = fp->sack_perm;
    if (fp->flags & HEV_FP_FLAG_TIMESTAMPS)
        req.timestamps = fp->timestamps;
    if (fp->flags & HEV_FP_FLAG_NOP_PADDING)
        req.nop_padding = fp->nop_padding;
    if (fp->flags & HEV_FP_FLAG_TCP_OPTS) {
        req.tcp_options_count = fp->tcp_options_count;
        for (i = 0; i < fp->tcp_options_count && i < 16; i++)
            req.tcp_options_order[i] = fp->tcp_options_order[i];
    }

    /* IP layer */
    if (fp->flags & HEV_FP_FLAG_IP_ID)
        req.ip_id_behavior = fp->ip_id_behavior;
    if (fp->flags & HEV_FP_FLAG_RST_DF)
        req.rst_df = fp->rst_df;
    if (fp->flags & HEV_FP_FLAG_IP_OPT_LEN)
        req.ip_opt_len = fp->ip_opt_len;
    if (fp->flags & HEV_FP_FLAG_IP_OPTIONS) {
        req.ip_options_len = fp->ip_options_len;
        memcpy (req.ip_options, fp->ip_options, fp->ip_options_len);
    }
    if (fp->flags & HEV_FP_FLAG_FLOW_LABEL)
        req.flow_label = fp->flow_label;

    /* Timing */
    if (fp->flags & HEV_FP_FLAG_TS_CLOCK)
        req.ts_clock = fp->ts_clock;
    if (fp->flags2 & HEV_FP_FLAG2_TS_INITIAL)
        req.ts_initial = fp->ts_initial;
    if (fp->flags & HEV_FP_FLAG_INIT_WINDOW)
        req.init_window = fp->init_window;
    if (fp->flags2 & HEV_FP_FLAG2_RTO) {
        req.rto_pattern = fp->rto_pattern;
        req.rto_initial_ms = fp->rto_initial_ms;
        req.rto_count = fp->rto_count;
        for (i = 0; i < fp->rto_count && i < 16; i++)
            req.rto_values[i] = fp->rto_values[i];
    }
    if (fp->flags2 & HEV_FP_FLAG2_RETRANSMIT)
        req.retransmit_count = fp->retransmit_count;

    /* ISN */
    if (fp->flags2 & HEV_FP_FLAG2_ISN) {
        req.isn_pattern = fp->isn_pattern;
        req.isn_const = fp->isn_const;
        req.isn_incr_rate = fp->isn_incr_rate;
    }

    /* RST/FIN/ACK */
    if (fp->flags & HEV_FP_FLAG_RST_ACK)
        req.rst_ack = fp->rst_ack;
    if (fp->flags & HEV_FP_FLAG_RST_TTL)
        req.rst_ttl = fp->rst_ttl;
    if (fp->flags & HEV_FP_FLAG_RST_WINDOW)
        req.rst_window = fp->rst_window;
    if (fp->flags & HEV_FP_FLAG_FIN_DF)
        req.fin_df = fp->fin_df;
    if (fp->flags2 & HEV_FP_FLAG2_ACK_DF)
        req.ack_df = fp->ack_df;

    /* p0f */
    if (fp->flags & HEV_FP_FLAG_QUIRKS)
        req.quirks = fp->quirks;
    if (fp->flags & HEV_FP_FLAG_PCLASS)
        req.pclass = fp->pclass;
    if (fp->flags & HEV_FP_FLAG_WIN_TYPE) {
        req.win_type = fp->win_type;
        req.win_multiplier = fp->win_multiplier;
    }

    /* SYN packet */
    if (fp->flags2 & HEV_FP_FLAG2_SYN_SIZE)
        req.syn_size = fp->syn_size;
    if (fp->flags2 & HEV_FP_FLAG2_TCP_FLAGS) {
        req.syn_urg_ptr = fp->syn_urg_ptr;
        req.syn_flags_extra = fp->syn_flags_extra;
    }
    if (fp->flags & HEV_FP_FLAG_SYN_PAYLOAD) {
        req.syn_payload_len = fp->syn_payload_len;
        memcpy (req.syn_payload, fp->syn_payload, fp->syn_payload_len);
    }
    if (fp->flags2 & HEV_FP_FLAG2_SYN_PADDING) {
        req.syn_padding_len = fp->syn_padding_len;
        memcpy (req.syn_padding, fp->syn_padding, fp->syn_padding_len);
    }

    /* Window behavior */
    if (fp->flags2 & HEV_FP_FLAG2_WIN_BEHAVIOR) {
        req.win_behavior = fp->win_behavior;
        req.win_response_count = fp->win_response_count;
        for (i = 0; i < fp->win_response_count && i < 6; i++)
            req.win_response[i] = fp->win_response[i];
    }

    /* Option stripping */
    if (fp->flags2 & HEV_FP_FLAG2_OPT_STRIP)
        req.option_strip_after = fp->option_strip_after;

    res = ioctl (dev_fd, HEV_TCPFP_IOC_SET, &req);
    if (res < 0) {
        LOG_I ("dkms: ioctl SET failed (errno=%d)", errno);
        return -1;
    }

    return 0;
}

void
hev_fingerprint_backend_fini (void)
{
    if (dev_fd >= 0) {
        close (dev_fd);
        dev_fd = -1;
    }
}

#endif /* ENABLE_DKMS */
