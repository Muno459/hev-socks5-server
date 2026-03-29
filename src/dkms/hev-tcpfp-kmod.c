// SPDX-License-Identifier: GPL-2.0
/*
 * hev-tcpfp-kmod.c — TCP/IP fingerprint spoofing kernel module v6.
 *
 * FULLY NATIVE TCP emission via kprobes — the kernel TCP stack builds
 * correct packets. Netfilter only handles IP-layer fields.
 *
 * Native kprobes (TCP layer):
 *   - ISN: kprobe tcp_connect → tp->write_seq
 *   - RTO: kretprobe tcp_connect_init → icsk->icsk_rto (initial)
 *          kprobe tcp_retransmit_timer → icsk->icsk_rto (subsequent)
 *   - Window: kretprobe tcp_connect_init → tp->rcv_wnd
 *   - WScale: kretprobe tcp_connect_init → tp->rx_opt.rcv_wscale
 *   - SACK/TS/MSS/WS values: kretprobe tcp_syn_options → opts struct
 *   - TCP option ORDER: kretprobe tcp_options_write → in-place reorder
 *   - TS clock scaling: kretprobe tcp_options_write → per-packet
 *
 * Netfilter LOCAL_OUT (IP-layer only, no TCP modifications):
 *   - IP ID behavior (zero/random/incremental)
 *   - RST/FIN/ACK DF flags
 *   - RST TTL/window
 *
 * Checksum: TCP checksum is computed by kernel AFTER our tcp_options_write
 * kretprobe, so it's naturally correct. We only recalculate IP header
 * checksum when modifying IP fields.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <net/inet_connection_sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("hev-socks5-server");
MODULE_DESCRIPTION("TCP/IP fingerprint spoofing v6 (fully native TCP via kprobes)");
MODULE_VERSION("6.0");

#define DEVICE_NAME    "hev-tcpfp"
#define CLASS_NAME     "hev-tcpfp"
#define FP_HASH_BITS   14

#define HEV_TCPFP_IOC_MAGIC 'T'
#define HEV_TCPFP_IOC_SET   _IOW(HEV_TCPFP_IOC_MAGIC, 1, struct hev_tcpfp_req)
#define HEV_TCPFP_IOC_DEL   _IOW(HEV_TCPFP_IOC_MAGIC, 2, u64)

#define OPT_EOL   0
#define OPT_NOP   1
#define OPT_MSS   2
#define OPT_WS    3
#define OPT_SACK  4
#define OPT_TS    8

#define IPID_INCR   0
#define IPID_RANDOM 1
#define IPID_ZERO   2

#define ISN_RANDOM     0
#define ISN_INCR       1
#define ISN_CONST      2
#define ISN_TIME_BASED 3

#define RTO_LINUX   0
#define RTO_WINDOWS 1
#define RTO_MACOS   2
#define RTO_CUSTOM  3

/* Kernel tcp_out_options flag bits (from tcp_output.c) */
#define KERN_OPT_SACK_ADVERTISE (1 << 0)  /* BIT(0) */
#define KERN_OPT_TS             (1 << 1)  /* BIT(1) */
#define KERN_OPT_WSCALE         (1 << 3)  /* BIT(3) */

/* Must match userspace struct in hev-dkms-fingerprint.c */
struct hev_tcpfp_req {
    u64 sock_cookie;
    u16 tcp_window;
    u8 wscale;
    u8 sack_perm;
    u8 timestamps;
    u8 tcp_options_order[16];
    u8 tcp_options_count;
    u8 nop_padding;
    u8 ip_id_behavior;
    u8 rst_df;
    u8 ip_opt_len;
    u8 ip_options[40];
    u8 ip_options_len;
    u32 ts_clock;
    u32 ts_initial;
    u32 init_window;
    u32 rto_initial_ms;
    u8 rto_pattern;
    u16 rto_values[16];
    u8 rto_count;
    u8 retransmit_count;
    u8 isn_pattern;
    u32 isn_const;
    u32 isn_incr_rate;
    u8 rst_ack;
    u8 rst_ttl;
    u16 rst_window;
    u8 fin_df;
    u8 ack_df;
    u32 quirks;
    u8 pclass;
    u8 win_type;
    u16 win_multiplier;
    u32 flow_label;
    u16 syn_size;
    u16 syn_urg_ptr;
    u8 syn_flags_extra;
    u8 syn_payload[64];
    u8 syn_payload_len;
    u8 syn_padding[64];
    u8 syn_padding_len;
    u8 win_behavior;
    u16 win_response[6];
    u8 win_response_count;
};

struct fp_entry {
    struct hlist_node node;
    u64 cookie;
    struct hev_tcpfp_req req;
    int syn_retransmits;
    struct rcu_head rcu;
};

static DEFINE_HASHTABLE(fp_table, FP_HASH_BITS);
static DEFINE_SPINLOCK(fp_lock);
static dev_t dev_num;
static struct class *dev_class;
static struct cdev dev_cdev;

static u32 isn_time_counter;
static unsigned long isn_time_last_jiffies;

/* --- Hash table --- */

static struct fp_entry *fp_find(u64 cookie)
{
    struct fp_entry *e;
    hash_for_each_possible_rcu(fp_table, e, node, cookie)
        if (e->cookie == cookie)
            return e;
    return NULL;
}

static int fp_set(struct hev_tcpfp_req *req)
{
    struct fp_entry *e, *old;
    e = kmalloc(sizeof(*e), GFP_KERNEL);
    if (!e) return -ENOMEM;
    e->cookie = req->sock_cookie;
    memcpy(&e->req, req, sizeof(*req));
    e->syn_retransmits = 0;
    spin_lock(&fp_lock);
    old = fp_find(req->sock_cookie);
    if (old) { hash_del_rcu(&old->node); kfree_rcu(old, rcu); }
    hash_add_rcu(fp_table, &e->node, e->cookie);
    spin_unlock(&fp_lock);
    return 0;
}

static void fp_del(u64 cookie)
{
    struct fp_entry *e;
    spin_lock(&fp_lock);
    e = fp_find(cookie);
    if (e) { hash_del_rcu(&e->node); kfree_rcu(e, rcu); }
    spin_unlock(&fp_lock);
}

/* --- ioctl --- */

static long fp_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    if (cmd == HEV_TCPFP_IOC_SET) {
        struct hev_tcpfp_req req;
        if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
            return -EFAULT;
        return fp_set(&req);
    }
    if (cmd == HEV_TCPFP_IOC_DEL) {
        u64 cookie;
        if (copy_from_user(&cookie, (void __user *)arg, sizeof(cookie)))
            return -EFAULT;
        fp_del(cookie);
        return 0;
    }
    return -EINVAL;
}

static const struct file_operations dev_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = fp_ioctl,
    .compat_ioctl = fp_ioctl,
};

/* --- RTO patterns --- */

static const int rto_linux[]   = {1000, 2000, 4000, 8000, 16000, 32000};
static const int rto_windows[] = {3000, 6000, 12000, 24000, 48000};
static const int rto_macos[]   = {1000, 1000, 1000, 1000, 2000, 4000, 8000, 16000};

static unsigned long get_rto_jiffies(struct fp_entry *fp, int retransmit)
{
    struct hev_tcpfp_req *req = &fp->req;
    int ms = 1000;

    switch (req->rto_pattern) {
    case RTO_LINUX:
        if (retransmit < ARRAY_SIZE(rto_linux))
            ms = rto_linux[retransmit];
        else ms = 64000;
        break;
    case RTO_WINDOWS:
        if (retransmit < ARRAY_SIZE(rto_windows))
            ms = rto_windows[retransmit];
        else ms = 48000;
        break;
    case RTO_MACOS:
        if (retransmit < ARRAY_SIZE(rto_macos))
            ms = rto_macos[retransmit];
        else ms = 32000;
        break;
    case RTO_CUSTOM:
        if (retransmit < req->rto_count)
            ms = req->rto_values[retransmit];
        else if (req->rto_count > 0)
            ms = req->rto_values[req->rto_count - 1];
        break;
    default:
        if (req->rto_initial_ms > 0)
            ms = req->rto_initial_ms << retransmit;
        break;
    }
    return msecs_to_jiffies(ms);
}

/* --- ISN generation --- */

static u32 generate_isn(struct fp_entry *fp)
{
    struct hev_tcpfp_req *req = &fp->req;
    unsigned long now = jiffies;

    switch (req->isn_pattern) {
    case ISN_CONST:
        return req->isn_const;
    case ISN_INCR: {
        static u32 counter;
        return counter++;
    }
    case ISN_TIME_BASED: {
        u32 rate = req->isn_incr_rate ? req->isn_incr_rate : 250000;
        unsigned long elapsed = now - isn_time_last_jiffies;
        u32 inc = (u32)((u64)elapsed * rate / HZ);
        isn_time_counter += inc;
        isn_time_last_jiffies = now;
        return isn_time_counter;
    }
    default:
        return get_random_u32();
    }
}

/* ================================================================
 * NATIVE KPROBES — TCP layer, kernel builds correct packets
 * ================================================================ */

/* --- kprobe: tcp_connect --- ISN */

static int kp_tcp_connect_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    struct tcp_sock *tp;
    struct fp_entry *fp;
    u64 cookie;

    if (!sk) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    if (fp->req.isn_pattern != ISN_RANDOM) {
        tp = tcp_sk(sk);
        tp->write_seq = generate_isn(fp);
    }
    return 0;
}

static struct kprobe kp_tcp_connect = {
    .symbol_name = "tcp_connect",
    .pre_handler = kp_tcp_connect_pre,
};

/* --- kretprobe: tcp_connect_init --- RTO, window, wscale, ISN fixup */

struct connect_init_data { struct sock *sk; };

static int krp_connect_init_entry(struct kretprobe_instance *ri,
                                   struct pt_regs *regs)
{
    struct connect_init_data *d = (struct connect_init_data *)ri->data;
    d->sk = (struct sock *)regs->di;
    return 0;
}

static int krp_connect_init_ret(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct connect_init_data *d = (struct connect_init_data *)ri->data;
    struct sock *sk = d->sk;
    struct tcp_sock *tp;
    struct inet_connection_sock *icsk;
    struct fp_entry *fp;
    struct hev_tcpfp_req *req;
    u64 cookie;

    if (!sk) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    req = &fp->req;
    tp = tcp_sk(sk);
    icsk = inet_csk(sk);

    /* ISN: tcp_connect_init copied write_seq → snd_una/snd_nxt.
     * Re-set all copies so tcp_connect uses our ISN. */
    if (req->isn_pattern != ISN_RANDOM) {
        u32 isn = generate_isn(fp);
        tp->write_seq = isn;
        tp->snd_una = isn;
        tp->snd_sml = isn;
        tp->snd_up = isn;
        tp->snd_nxt = isn;
    }

    /* Initial RTO: override kernel's 1s default.
     * tcp_connect() arms the retransmit timer with icsk->icsk_rto. */
    if (req->rto_pattern != 0 || req->rto_initial_ms != 0) {
        icsk->icsk_rto = get_rto_jiffies(fp, 0);
        fp->syn_retransmits = 1;
    }

    /* Window: __tcp_transmit_skb uses min(tp->rcv_wnd, 65535) for SYN. */
    if (req->tcp_window > 0)
        tp->rcv_wnd = req->tcp_window;

    /* Window scale: tcp_syn_options reads tp->rx_opt.rcv_wscale. */
    if (req->wscale > 0) {
        tp->rx_opt.rcv_wscale = req->wscale;
        tp->rcv_ssthresh = tp->rcv_wnd;
    }

    return 0;
}

static struct kretprobe krp_connect_init = {
    .handler = krp_connect_init_ret,
    .entry_handler = krp_connect_init_entry,
    .data_size = sizeof(struct connect_init_data),
    .maxactive = 20,
    .kp.symbol_name = "tcp_connect_init",
};

/* --- kretprobe: tcp_syn_options --- SACK/TS/WS flags + size calc */

struct syn_opts_data {
    struct sock *sk;
    void *opts;
};

static int krp_syn_options_entry(struct kretprobe_instance *ri,
                                  struct pt_regs *regs)
{
    struct syn_opts_data *d = (struct syn_opts_data *)ri->data;
    d->sk = (struct sock *)regs->di;
    d->opts = (void *)regs->dx;
    return 0;
}

static int krp_syn_options_ret(struct kretprobe_instance *ri,
                                struct pt_regs *regs)
{
    struct syn_opts_data *d = (struct syn_opts_data *)ri->data;
    struct sock *sk = d->sk;
    void *opts = d->opts;
    struct fp_entry *fp;
    struct hev_tcpfp_req *req;
    u64 cookie;
    u16 *options_p, *mss_p;
    u8 *ws_p;
    u32 *tsval_p;
    u16 options;
    unsigned int new_size;

    if (!sk || !opts) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    req = &fp->req;

    /* tcp_out_options layout (kernel 6.8):
     *   offset 0:  u16 options    (bitmask)
     *   offset 2:  u16 mss
     *   offset 4:  u8  ws
     *   offset 16: u32 tsval
     *   offset 20: u32 tsecr */
    options_p = (u16 *)opts;
    mss_p     = (u16 *)(opts + 2);
    ws_p      = (u8 *)(opts + 4);
    tsval_p   = (u32 *)(opts + 16);
    options   = *options_p;

    /* Window scale: override value, or remove entirely if wscale=0 */
    if (req->wscale > 0 && (options & KERN_OPT_WSCALE))
        *ws_p = req->wscale;
    else if (req->tcp_options_count > 0) {
        /* Check if target fingerprint includes WS. If not, remove it. */
        int has_ws = 0, k;
        for (k = 0; k < req->tcp_options_count; k++)
            if (req->tcp_options_order[k] == OPT_WS) { has_ws = 1; break; }
        if (!has_ws)
            *options_p &= ~KERN_OPT_WSCALE;
    }

    /* SACK permit: check target option layout, not just sack_perm flag */
    if (req->tcp_options_count > 0) {
        int has_sack = 0, k;
        for (k = 0; k < req->tcp_options_count; k++)
            if (req->tcp_options_order[k] == OPT_SACK) { has_sack = 1; break; }
        if (!has_sack)
            *options_p &= ~KERN_OPT_SACK_ADVERTISE;
        else
            *options_p |= KERN_OPT_SACK_ADVERTISE;
    } else {
        if (req->sack_perm == 0)
            *options_p &= ~KERN_OPT_SACK_ADVERTISE;
        else if (req->sack_perm == 1)
            *options_p |= KERN_OPT_SACK_ADVERTISE;
    }

    /* Timestamps: check target option layout */
    if (req->tcp_options_count > 0) {
        int has_ts = 0, k;
        for (k = 0; k < req->tcp_options_count; k++)
            if (req->tcp_options_order[k] == OPT_TS) { has_ts = 1; break; }
        if (!has_ts)
            *options_p &= ~KERN_OPT_TS;
    } else if (req->timestamps == 0)
        *options_p &= ~KERN_OPT_TS;

    /* Timestamp initial value */
    if (req->ts_initial > 0 && ((*options_p) & KERN_OPT_TS))
        *tsval_p = req->ts_initial;

    /* Recompute exact size that tcp_options_write will emit. */
    new_size = 0;
    {
        u16 final_opts = *options_p;
        if (*mss_p)
            new_size += 4;  /* TCPOLEN_MSS_ALIGNED */
        if (final_opts & KERN_OPT_TS)
            new_size += 12; /* TCPOLEN_TSTAMP_ALIGNED (SACK combined if both) */
        if ((final_opts & KERN_OPT_SACK_ADVERTISE) &&
            !(final_opts & KERN_OPT_TS))
            new_size += 4;  /* TCPOLEN_SACKPERM_ALIGNED (standalone) */
        if (final_opts & KERN_OPT_WSCALE)
            new_size += 4;  /* TCPOLEN_WSCALE_ALIGNED */
    }
    regs->ax = new_size;

    return 0;
}

static struct kretprobe krp_syn_options = {
    .handler = krp_syn_options_ret,
    .entry_handler = krp_syn_options_entry,
    .data_size = sizeof(struct syn_opts_data),
    .maxactive = 20,
    .kp.symbol_name = "tcp_syn_options",
};

/* --- kretprobe: tcp_options_write --- option ORDER + TS clock scaling
 *
 * This is the KEY native hook. tcp_options_write() writes TCP options in
 * a hardcoded order (MSS, TS+SACK, WS). We rewrite them in-place in the
 * target order immediately after. This happens BEFORE the kernel computes
 * the TCP checksum, so the checksum naturally covers our reordered options.
 *
 * tcp_options_write signature:
 *   void tcp_options_write(struct tcphdr *th, struct tcp_sock *tp,
 *                          const struct tcp_request_sock *tcprsk,
 *                          struct tcp_out_options *opts,
 *                          struct tcp_key *key)
 * x86_64: rdi=th, rsi=tp
 */

struct opts_write_data {
    struct tcphdr *th;
    struct tcp_sock *tp;
};

static int krp_opts_write_entry(struct kretprobe_instance *ri,
                                 struct pt_regs *regs)
{
    struct opts_write_data *d = (struct opts_write_data *)ri->data;
    d->th = (struct tcphdr *)regs->di;
    d->tp = (struct tcp_sock *)regs->si;
    return 0;
}

static int krp_opts_write_ret(struct kretprobe_instance *ri,
                               struct pt_regs *regs)
{
    struct opts_write_data *d = (struct opts_write_data *)ri->data;
    struct tcphdr *th = d->th;
    struct tcp_sock *tp = d->tp;
    struct sock *sk;
    struct fp_entry *fp;
    struct hev_tcpfp_req *req;
    u64 cookie;
    unsigned int hdrlen, opts_len;
    u8 *opts, *p;

    if (!th || !tp) return 0;

    sk = (struct sock *)tp;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    req = &fp->req;
    hdrlen = th->doff * 4;
    if (hdrlen <= sizeof(struct tcphdr))
        return 0;
    opts = (u8 *)th + sizeof(struct tcphdr);
    opts_len = hdrlen - sizeof(struct tcphdr);

    /* --- SYN: reorder options to match target fingerprint --- */
    if (th->syn && !th->ack && req->tcp_options_count > 0) {
        u16 mss_val = 0;
        u8 ws_val = 0;
        u32 tsval = 0, tsecr = 0;
        int has_ts = 0;
        int i, wrote;

        /* Parse what kernel wrote (fixed order: MSS, TS+SACK, WS) */
        p = opts;
        while (p < opts + opts_len) {
            u8 kind = *p, len;
            if (kind == OPT_EOL) break;
            if (kind == OPT_NOP) { p++; continue; }
            if (p + 1 >= opts + opts_len) break;
            len = *(p + 1);
            if (len < 2 || p + len > opts + opts_len) break;
            switch (kind) {
            case OPT_MSS:
                if (len >= 4) mss_val = ntohs(*(u16 *)(p + 2));
                break;
            case OPT_WS:
                if (len >= 3) ws_val = *(p + 2);
                break;
            case OPT_TS:
                if (len >= 10) {
                    tsval = ntohl(*(u32 *)(p + 2));
                    tsecr = ntohl(*(u32 *)(p + 6));
                    has_ts = 1;
                }
                break;
            }
            p += len;
        }

        /* Override values */
        if (req->wscale > 0) ws_val = req->wscale;

        /* Rewrite in target order */
        memset(opts, 0, opts_len);
        p = opts;
        wrote = 0;

        for (i = 0; i < req->tcp_options_count && i < 16; i++) {
            u8 kind = req->tcp_options_order[i];
            int need;
            switch (kind) {
            case OPT_NOP: case OPT_EOL: need = 1; break;
            case OPT_MSS:  need = 4; break;
            case OPT_WS:   need = 3; break;
            case OPT_SACK: need = 2; break;
            case OPT_TS:   need = 10; break;
            default: need = 0;
            }
            if (need == 0 || wrote + need > (int)opts_len) break;

            switch (kind) {
            case OPT_NOP: *p++ = OPT_NOP; break;
            case OPT_EOL: *p++ = OPT_EOL; break;
            case OPT_MSS:
                *p++ = OPT_MSS; *p++ = 4;
                *(u16 *)p = htons(mss_val); p += 2; break;
            case OPT_WS:
                *p++ = OPT_WS; *p++ = 3; *p++ = ws_val; break;
            case OPT_SACK:
                *p++ = OPT_SACK; *p++ = 2; break;
            case OPT_TS:
                if (!has_ts) break;
                *p++ = OPT_TS; *p++ = 10;
                *(u32 *)p = htonl(tsval); p += 4;
                *(u32 *)p = htonl(tsecr); p += 4; break;
            }
            wrote = p - opts;
        }
        /* Remaining bytes are already zeroed (EOL padding) */
        return 0;
    }

    /* --- All packets: timestamp clock scaling --- */
    if (req->ts_clock > 0 && req->ts_clock != 1000) {
        p = opts;
        while (p < opts + opts_len) {
            u8 kind = *p, len;
            if (kind == OPT_EOL) break;
            if (kind == OPT_NOP) { p++; continue; }
            if (p + 1 >= opts + opts_len) break;
            len = *(p + 1);
            if (len < 2 || p + len > opts + opts_len) break;
            if (kind == OPT_TS && len >= 10) {
                u32 ts = ntohl(*(u32 *)(p + 2));
                if (req->ts_clock < 1000)
                    ts = ts / (1000 / req->ts_clock);
                else
                    ts = ts * (req->ts_clock / 1000);
                *(u32 *)(p + 2) = htonl(ts);
            }
            p += len;
        }
    }

    return 0;
}

static struct kretprobe krp_opts_write = {
    .handler = krp_opts_write_ret,
    .entry_handler = krp_opts_write_entry,
    .data_size = sizeof(struct opts_write_data),
    .maxactive = 40,
    .kp.symbol_name = "tcp_options_write",
};

/* --- kprobe: tcp_retransmit_timer --- RTO for retransmits */

static int kp_retransmit_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    struct tcp_sock *tp;
    struct inet_connection_sock *icsk;
    struct fp_entry *fp;
    u64 cookie;
    unsigned long rto;
    int idx, linear;

    if (!sk) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;
    if (fp->req.rto_pattern == 0 && fp->req.rto_initial_ms == 0)
        return 0;

    tp = tcp_sk(sk);
    icsk = inet_csk(sk);
    idx = fp->syn_retransmits;
    rto = get_rto_jiffies(fp, idx);
    fp->syn_retransmits = idx + 1;

    /* SYN_SENT uses linear timeouts (no doubling) for first N retransmits.
     * For linear: set target directly. For exponential: halve (kernel doubles). */
    linear = (sk->sk_state == TCP_SYN_SENT &&
              tp->total_rto <=
              READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_syn_linear_timeouts));

    if (linear)
        icsk->icsk_rto = rto;
    else {
        icsk->icsk_rto = rto / 2;
        if (icsk->icsk_rto < 1)
            icsk->icsk_rto = 1;
    }
    return 0;
}

static struct kprobe kp_retransmit = {
    .symbol_name = "tcp_retransmit_timer",
    .pre_handler = kp_retransmit_pre,
};

/* ================================================================
 * NETFILTER — IP-layer modifications ONLY (no TCP header changes)
 * ================================================================ */

static unsigned int
nf_out_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct sock *sk;
    struct fp_entry *fp;
    u64 cookie;
    int modified = 0;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    sk = skb->sk;
    if (!sk) return NF_ACCEPT;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return NF_ACCEPT;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return NF_ACCEPT;

    /* IP ID behavior */
    if (fp->req.ip_id_behavior == IPID_RANDOM) {
        iph->id = htons(get_random_u16());
        modified = 1;
    } else if (fp->req.ip_id_behavior == IPID_ZERO) {
        iph->id = 0;
        modified = 1;
    }

    /* Need TCP header for RST/FIN/ACK checks */
    if (skb_ensure_writable(skb, skb_transport_offset(skb) +
                            sizeof(struct tcphdr)))
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    th = tcp_hdr(skb);
    if (!th) return NF_ACCEPT;

    /* RST behavior */
    if (th->rst) {
        if (fp->req.rst_df) {
            iph->frag_off |= htons(IP_DF);
            modified = 1;
        }
        if (fp->req.rst_window)
            th->window = htons(fp->req.rst_window);
        if (fp->req.rst_ttl) {
            iph->ttl = fp->req.rst_ttl;
            modified = 1;
        }
    }

    /* FIN DF */
    if (th->fin && fp->req.fin_df) {
        iph->frag_off |= htons(IP_DF);
        modified = 1;
    }

    /* ACK DF */
    if (th->ack && !th->syn && !th->fin && !th->rst && fp->req.ack_df) {
        iph->frag_off |= htons(IP_DF);
        modified = 1;
    }

    /* Only recalculate IP header checksum if we modified IP fields.
     * TCP checksum is NOT recalculated — we don't modify TCP headers here.
     * TCP option reordering + TS scaling happen in the tcp_options_write
     * kretprobe, BEFORE the kernel computes the TCP checksum. */
    if (modified) {
        iph->check = 0;
        iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    }

    /* RST window is a TCP field — recalc TCP checksum only if modified */
    if (th->rst && fp->req.rst_window) {
        int tcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
        th->check = 0;
        th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       tcp_len, IPPROTO_TCP,
                                       csum_partial((u8 *)th, tcp_len, 0));
        skb->ip_summed = CHECKSUM_NONE;
    }

    return NF_ACCEPT;
}

static unsigned int
nf_out_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h;
    struct tcphdr *th;
    struct sock *sk;
    struct fp_entry *fp;
    u64 cookie;

    if (!skb) return NF_ACCEPT;
    ip6h = ipv6_hdr(skb);
    if (!ip6h || ip6h->nexthdr != IPPROTO_TCP) return NF_ACCEPT;
    sk = skb->sk;
    if (!sk) return NF_ACCEPT;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return NF_ACCEPT;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return NF_ACCEPT;

    if (skb_ensure_writable(skb, skb_transport_offset(skb) +
                            sizeof(struct tcphdr)))
        return NF_ACCEPT;
    ip6h = ipv6_hdr(skb);
    th = tcp_hdr(skb);
    if (!th) return NF_ACCEPT;

    /* IPv6 flow label */
    if (fp->req.flow_label) {
        ip6h->flow_lbl[0] = (ip6h->flow_lbl[0] & 0xF0) |
                             ((fp->req.flow_label >> 16) & 0x0F);
    }

    /* RST */
    if (th->rst) {
        if (fp->req.rst_window) {
            th->window = htons(fp->req.rst_window);
            int tcp_len = ntohs(ip6h->payload_len);
            th->check = 0;
            th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
                                         tcp_len, IPPROTO_TCP,
                                         csum_partial((u8 *)th, tcp_len, 0));
            skb->ip_summed = CHECKSUM_NONE;
        }
        if (fp->req.rst_ttl)
            ip6h->hop_limit = fp->req.rst_ttl;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_hooks[] = {
    { .hook = nf_out_v4, .pf = NFPROTO_IPV4,
      .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP_PRI_LAST },
    { .hook = nf_out_v6, .pf = NFPROTO_IPV6,
      .hooknum = NF_INET_LOCAL_OUT, .priority = NF_IP6_PRI_LAST },
};

/* --- init/exit --- */

static int __init hev_tcpfp_init(void)
{
    int ret, i;

    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) return ret;

    dev_class = class_create(CLASS_NAME);
    if (IS_ERR(dev_class)) {
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(dev_class);
    }

    cdev_init(&dev_cdev, &dev_fops);
    ret = cdev_add(&dev_cdev, dev_num, 1);
    if (ret < 0) {
        class_destroy(dev_class);
        unregister_chrdev_region(dev_num, 1);
        return ret;
    }
    device_create(dev_class, NULL, dev_num, NULL, DEVICE_NAME);

    for (i = 0; i < ARRAY_SIZE(nf_hooks); i++) {
        ret = nf_register_net_hook(&init_net, &nf_hooks[i]);
        if (ret < 0) {
            pr_err("hev-tcpfp: hook %d failed\n", i);
            while (--i >= 0)
                nf_unregister_net_hook(&init_net, &nf_hooks[i]);
            device_destroy(dev_class, dev_num);
            cdev_del(&dev_cdev);
            class_destroy(dev_class);
            unregister_chrdev_region(dev_num, 1);
            return ret;
        }
    }

    /* Native kprobes */
    ret = register_kprobe(&kp_tcp_connect);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_connect failed (%d)\n", ret);

    ret = register_kretprobe(&krp_connect_init);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_connect_init failed (%d)\n", ret);

    ret = register_kretprobe(&krp_syn_options);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_syn_options failed (%d)\n", ret);

    ret = register_kretprobe(&krp_opts_write);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_options_write failed (%d)\n", ret);

    ret = register_kprobe(&kp_retransmit);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_retransmit_timer failed (%d)\n", ret);

    hash_init(fp_table);
    isn_time_last_jiffies = jiffies;
    isn_time_counter = get_random_u32();

    pr_info("hev-tcpfp: v6 loaded (fully native TCP: ISN+RTO+WIN+WS+SACK+TS+option-order+TS-clock, NF: IP-layer only)\n");
    return 0;
}

static void __exit hev_tcpfp_exit(void)
{
    struct fp_entry *e;
    struct hlist_node *tmp;
    int bkt, i;

    unregister_kprobe(&kp_retransmit);
    unregister_kretprobe(&krp_opts_write);
    unregister_kretprobe(&krp_syn_options);
    unregister_kretprobe(&krp_connect_init);
    unregister_kprobe(&kp_tcp_connect);

    for (i = 0; i < ARRAY_SIZE(nf_hooks); i++)
        nf_unregister_net_hook(&init_net, &nf_hooks[i]);

    spin_lock(&fp_lock);
    hash_for_each_safe(fp_table, bkt, tmp, e, node) {
        hash_del(&e->node);
        kfree(e);
    }
    spin_unlock(&fp_lock);

    device_destroy(dev_class, dev_num);
    cdev_del(&dev_cdev);
    class_destroy(dev_class);
    unregister_chrdev_region(dev_num, 1);
    pr_info("hev-tcpfp: v6 unloaded\n");
}

module_init(hev_tcpfp_init);
module_exit(hev_tcpfp_exit);
