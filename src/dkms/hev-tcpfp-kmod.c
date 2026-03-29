// SPDX-License-Identifier: GPL-2.0
/*
 * hev-tcpfp-kmod.c — TCP/IP fingerprint spoofing kernel module v4.
 *
 * ISN: kprobe on tcp_connect sets tp->write_seq directly (no delta tracking).
 * RTO: kprobe on tcp_connect sets icsk->icsk_rto before first SYN (exact timing).
 * Options/Window/IP ID/TS clock: netfilter LOCAL_OUT (in-place rewrite).
 * IPv4 + IPv6 supported.
 *
 * SAFETY: never modifies skb length/tail. In-place rewrite only.
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
MODULE_DESCRIPTION("TCP/IP fingerprint spoofing v4 (kprobe ISN+RTO, NF options)");
MODULE_VERSION("4.0");

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
    u16 rto_values[16];     /* custom RTO sequence in ms (up to 16 retransmits) */
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
    int syn_retransmits;   /* count of SYNs seen (for RTO pattern) */
    struct rcu_head rcu;
};

static DEFINE_HASHTABLE(fp_table, FP_HASH_BITS);
static DEFINE_SPINLOCK(fp_lock);
static dev_t dev_num;
static struct class *dev_class;
static struct cdev dev_cdev;

/* Global counter for time-based ISN */
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

/* --- RTO pattern: returns the RTO in jiffies for a given retransmit --- */

/* Linux:   1s, 2s, 4s, 8s, 16s, 32s */
static const int rto_linux[]  = {1000, 2000, 4000, 8000, 16000, 32000};
/* Windows: 3s, 6s, 12s, 24s, 48s */
static const int rto_windows[] = {3000, 6000, 12000, 24000, 48000};
/* macOS:   1s, 1s, 1s, 1s, 2s, 4s, 8s, 16s */
static const int rto_macos[]  = {1000, 1000, 1000, 1000, 2000, 4000, 8000, 16000};

#define RTO_LINUX   0
#define RTO_WINDOWS 1
#define RTO_MACOS   2
#define RTO_CUSTOM  3

static unsigned long get_rto_jiffies(struct fp_entry *fp, int retransmit)
{
    struct hev_tcpfp_req *req = &fp->req;
    int ms = 1000; /* default 1s */

    switch (req->rto_pattern) {
    case RTO_LINUX:
        if (retransmit < ARRAY_SIZE(rto_linux))
            ms = rto_linux[retransmit];
        else
            ms = 64000;
        break;
    case RTO_WINDOWS:
        if (retransmit < ARRAY_SIZE(rto_windows))
            ms = rto_windows[retransmit];
        else
            ms = 48000;
        break;
    case RTO_MACOS:
        if (retransmit < ARRAY_SIZE(rto_macos))
            ms = rto_macos[retransmit];
        else
            ms = 32000;
        break;
    case RTO_CUSTOM:
        if (retransmit < req->rto_count)
            ms = req->rto_values[retransmit];
        else if (req->rto_count > 0)
            ms = req->rto_values[req->rto_count - 1];
        break;
    default:
        if (req->rto_initial_ms > 0)
            ms = req->rto_initial_ms << retransmit; /* exponential */
        break;
    }

    return msecs_to_jiffies(ms);
}

/*
 * Called from netfilter on SYN retransmits (not the initial SYN — kprobe
 * handles that). Set icsk_rto for the NEXT retransmit, since this one
 * was already scheduled with the previous RTO value.
 */
static void apply_rto(struct sock *sk, struct fp_entry *fp)
{
    struct inet_connection_sock *icsk;
    int next;

    if (fp->req.rto_pattern == 0 && fp->req.rto_initial_ms == 0)
        return;

    icsk = inet_csk(sk);
    if (!icsk)
        return;

    /*
     * SYN retransmit path.
     * The kernel already doubled icsk_rto and sent this SYN.
     * We set icsk_rto for the NEXT retransmit AND re-arm the timer
     * so the kernel can't double it before we get called again.
     */
    next = fp->syn_retransmits;
    icsk->icsk_rto = get_rto_jiffies(fp, next);

    /* Re-arm timer with our exact value for the next retransmit */
    if (timer_pending(&icsk->icsk_retransmit_timer))
        mod_timer(&icsk->icsk_retransmit_timer,
                  jiffies + icsk->icsk_rto);

    fp->syn_retransmits = next + 1;
}

static const struct file_operations dev_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = fp_ioctl,
    .compat_ioctl = fp_ioctl,
};

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
        /* Windows-style: ISN increments by ~rate per second */
        u32 rate = req->isn_incr_rate ? req->isn_incr_rate : 250000;
        unsigned long elapsed = now - isn_time_last_jiffies;
        u32 inc = (u32)((u64)elapsed * rate / HZ);
        isn_time_counter += inc;
        isn_time_last_jiffies = now;
        return isn_time_counter;
    }
    default: /* ISN_RANDOM */
        return get_random_u32();
    }
}

/*
 * --- kprobe on tcp_connect ---
 * Fires right before the SYN is built. We have full access to the socket:
 * - Set tp->write_seq to our ISN (kernel uses this as the SYN seq number)
 * - Set icsk->icsk_rto to our initial RTO (kernel uses this for retransmit timer)
 * No delta tracking needed. No timing offset. Perfect.
 */
/*
 * kprobe on tcp_connect: PRE handler sets ISN (write_seq).
 * tcp_connect reads write_seq at line 4109 to build the SYN.
 */
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

/*
 * kretprobe on tcp_connect_init — fires when tcp_connect_init RETURNS.
 * At this point icsk_rto is set to tcp_timeout_init() = 1s.
 * We override it to our value. tcp_connect then arms the timer with OUR rto.
 * This is the native approach — no timer hacking, the kernel uses our value.
 */
struct connect_init_data {
    struct sock *sk;
};

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
    struct inet_connection_sock *icsk;
    struct fp_entry *fp;
    u64 cookie;

    if (!sk) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;
    if (fp->req.rto_pattern == 0 && fp->req.rto_initial_ms == 0)
        return 0;

    /* Override icsk_rto. tcp_connect will read this value to arm the timer.
     * No timer hacking — the kernel natively uses our value. */
    icsk = inet_csk(sk);
    icsk->icsk_rto = get_rto_jiffies(fp, 0);
    fp->syn_retransmits = 1;
    return 0;
}

static struct kretprobe krp_connect_init = {
    .handler = krp_connect_init_ret,
    .entry_handler = krp_connect_init_entry,
    .data_size = sizeof(struct connect_init_data),
    .maxactive = 20,
    .kp.symbol_name = "tcp_connect_init",
};

/*
 * kprobe on tcp_retransmit_timer — fires at the START of the retransmit
 * timer callback, BEFORE the kernel doubles icsk_rto.
 * We set icsk_rto to our value so the kernel's "double" gives us what we want.
 * Strategy: set icsk_rto = target/2, kernel doubles it → target.
 */
/*
 * kprobe on tcp_retransmit_timer — post_handler fires AFTER the kernel
 * doubled icsk_rto and rescheduled the timer. We override both.
 */
/*
 * PRE handler: fires BEFORE kernel doubles icsk_rto.
 * We set icsk_rto to target/2 so the kernel's doubling gives us target.
 * Then the kernel arms the timer with the doubled value = our target.
 */
static int kp_retransmit_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    struct inet_connection_sock *icsk;
    struct fp_entry *fp;
    u64 cookie;
    unsigned long rto;
    int idx;

    if (!sk) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;
    if (fp->req.rto_pattern == 0 && fp->req.rto_initial_ms == 0)
        return 0;

    icsk = inet_csk(sk);
    idx = fp->syn_retransmits;
    rto = get_rto_jiffies(fp, idx);
    fp->syn_retransmits = idx + 1;

    /* Set exact target. Kernel arms timer with this value, then doubles
     * for next time. Our next pre_handler call overrides the doubled value. */
    icsk->icsk_rto = rto;
    return 0;
}

static struct kprobe kp_retransmit = {
    .symbol_name = "tcp_retransmit_timer",
    .pre_handler = kp_retransmit_pre,
};

/* --- SYN rewrite (in-place, no skb resize) --- */

static void rewrite_syn(struct sk_buff *skb, struct fp_entry *fp)
{
    struct tcphdr *th = tcp_hdr(skb);
    unsigned int hdrlen, opts_len;
    u8 *opts, *p;
    u16 mss_val = 0;
    u8 ws_val = 0;
    u32 tsval = 0, tsecr = 0;
    int i, wrote;
    struct hev_tcpfp_req *req = &fp->req;

    if (!th || !th->syn || th->ack)
        return;

    if (req->tcp_options_count == 0 && req->tcp_window == 0)
        return;

    hdrlen = th->doff * 4;
    opts = (u8 *)th + sizeof(struct tcphdr);
    opts_len = hdrlen - sizeof(struct tcphdr);

    if (skb_ensure_writable(skb, skb_transport_offset(skb) + hdrlen))
        return;
    th = tcp_hdr(skb);
    opts = (u8 *)th + sizeof(struct tcphdr);

    /* Parse kernel option values */
    p = opts;
    while (p < opts + opts_len) {
        u8 kind = *p, len;
        if (kind == OPT_EOL) break;
        if (kind == OPT_NOP) { p++; continue; }
        if (p + 1 >= opts + opts_len) break;
        len = *(p + 1);
        if (len < 2 || p + len > opts + opts_len) break;
        if (kind == OPT_MSS && len >= 4)
            mss_val = ntohs(*(u16 *)(p + 2));
        else if (kind == OPT_WS && len >= 3)
            ws_val = *(p + 2);
        else if (kind == OPT_TS && len >= 10) {
            tsval = ntohl(*(u32 *)(p + 2));
            tsecr = ntohl(*(u32 *)(p + 6));
        }
        p += len;
    }

    if (req->wscale > 0)
        ws_val = req->wscale;

    /* Rewrite options in-place */
    if (req->tcp_options_count > 0) {
        memset(opts, 0, opts_len);
        p = opts;
        wrote = 0;

        for (i = 0; i < req->tcp_options_count && i < 16; i++) {
            u8 kind = req->tcp_options_order[i];
            int need;
            switch (kind) {
            case OPT_NOP: case OPT_EOL: need = 1; break;
            case OPT_MSS: need = 4; break;
            case OPT_WS:  need = 3; break;
            case OPT_SACK: need = 2; break;
            case OPT_TS:  need = 10; break;
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
                *p++ = OPT_TS; *p++ = 10;
                *(u32 *)p = htonl(tsval); p += 4;
                *(u32 *)p = htonl(tsecr); p += 4; break;
            }
            wrote = p - opts;
        }

        /* Trim TCP header */
        {
            int new_padded = (wrote + 3) & ~3;
            int new_hdrlen = sizeof(struct tcphdr) + new_padded;
            int old_total = th->doff * 4;
            if (new_hdrlen < old_total && new_padded <= (int)opts_len) {
                th->doff = new_hdrlen / 4;
                /* Adjust IP total length — handled below per-protocol */
            }
        }
    }

    /* Set window */
    if (req->tcp_window > 0)
        th->window = htons(req->tcp_window);
}

/* --- Timestamp clock scaling (works on any packet with TS option) --- */

static void scale_timestamps(struct tcphdr *th, u32 target_hz)
{
    unsigned int hdrlen = th->doff * 4;
    u8 *opts = (u8 *)th + sizeof(struct tcphdr);
    unsigned int opts_len = hdrlen - sizeof(struct tcphdr);
    u8 *p = opts;

    while (p < opts + opts_len) {
        u8 kind = *p, len;
        if (kind == OPT_EOL) break;
        if (kind == OPT_NOP) { p++; continue; }
        if (p + 1 >= opts + opts_len) break;
        len = *(p + 1);
        if (len < 2 || p + len > opts + opts_len) break;
        if (kind == OPT_TS && len >= 10) {
            u32 ts = ntohl(*(u32 *)(p + 2));
            if (target_hz < 1000)
                ts = ts / (1000 / target_hz);
            else if (target_hz > 1000)
                ts = ts * (target_hz / 1000);
            *(u32 *)(p + 2) = htonl(ts);
        }
        p += len;
    }
}

/* --- Outgoing hook (LOCAL_OUT) — IPv4 --- */

static unsigned int
nf_out_v4(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *th;
    struct sock *sk;
    struct fp_entry *fp;
    u64 cookie;
    int tcp_len, trim;

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

    if (skb_ensure_writable(skb, skb_transport_offset(skb) +
                            sizeof(struct tcphdr)))
        return NF_ACCEPT;
    iph = ip_hdr(skb);
    th = tcp_hdr(skb);
    if (!th) return NF_ACCEPT;

    /* SYN rewrite */
    if (th->syn && !th->ack) {
        int old_doff = th->doff;
        rewrite_syn(skb, fp);
        iph = ip_hdr(skb);
        th = tcp_hdr(skb);
        trim = (old_doff - th->doff) * 4;
        if (trim > 0)
            iph->tot_len = htons(ntohs(iph->tot_len) - trim);

        /* RTO handled entirely by kprobes (tcp_connect + tcp_retransmit_timer) */
    }

    /* IP ID */
    if (fp->req.ip_id_behavior == IPID_RANDOM)
        iph->id = htons(get_random_u16());
    else if (fp->req.ip_id_behavior == IPID_ZERO)
        iph->id = 0;

    /* RST behavior */
    if (th->rst) {
        if (fp->req.rst_df) iph->frag_off |= htons(IP_DF);
        if (fp->req.rst_window) th->window = htons(fp->req.rst_window);
        if (fp->req.rst_ttl) iph->ttl = fp->req.rst_ttl;
    }

    /* FIN DF */
    if (th->fin && fp->req.fin_df)
        iph->frag_off |= htons(IP_DF);

    /* ACK DF */
    if (th->ack && !th->syn && !th->fin && !th->rst && fp->req.ack_df)
        iph->frag_off |= htons(IP_DF);

    /* Timestamp clock */
    if (fp->req.ts_clock > 0 && fp->req.ts_clock != 1000)
        scale_timestamps(th, fp->req.ts_clock);

    /* Checksums */
    iph->check = 0;
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    tcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
    th->check = 0;
    th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                   tcp_len, IPPROTO_TCP,
                                   csum_partial((u8 *)th, tcp_len, 0));
    skb->ip_summed = CHECKSUM_NONE;
    return NF_ACCEPT;
}

/* No LOCAL_IN hook needed — kprobe sets ISN directly, no delta tracking */

/* --- Outgoing hook — IPv6 --- */

static unsigned int
nf_out_v6(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ipv6hdr *ip6h;
    struct tcphdr *th;
    struct sock *sk;
    struct fp_entry *fp;
    u64 cookie;
    int tcp_len, trim;

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

    /* SYN rewrite */
    if (th->syn && !th->ack) {
        int old_doff = th->doff;
        rewrite_syn(skb, fp);
        ip6h = ipv6_hdr(skb);
        th = tcp_hdr(skb);
        trim = (old_doff - th->doff) * 4;
        if (trim > 0)
            ip6h->payload_len = htons(ntohs(ip6h->payload_len) - trim);

    }

    /* IPv6 flow label */
    if (fp->req.flow_label)
        ip6h->flow_lbl[0] = (ip6h->flow_lbl[0] & 0xF0) |
                             ((fp->req.flow_label >> 16) & 0x0F);

    /* RST */
    if (th->rst) {
        if (fp->req.rst_window) th->window = htons(fp->req.rst_window);
        if (fp->req.rst_ttl) ip6h->hop_limit = fp->req.rst_ttl;
    }

    /* Timestamp clock */
    if (fp->req.ts_clock > 0 && fp->req.ts_clock != 1000)
        scale_timestamps(th, fp->req.ts_clock);

    /* TCP checksum (IPv6 uses pseudo-header) */
    tcp_len = ntohs(ip6h->payload_len);
    th->check = 0;
    th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
                                 tcp_len, IPPROTO_TCP,
                                 csum_partial((u8 *)th, tcp_len, 0));
    skb->ip_summed = CHECKSUM_NONE;
    return NF_ACCEPT;
}

/* No IPv6 LOCAL_IN hook needed — kprobe handles ISN directly */

/* --- Netfilter hooks --- */

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

    /* kprobes for ISN + RTO */
    ret = register_kprobe(&kp_tcp_connect);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_connect failed (%d)\n", ret);

    ret = register_kretprobe(&krp_connect_init);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_connect_init failed (%d)\n", ret);

    ret = register_kprobe(&kp_retransmit);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_retransmit_timer failed (%d)\n", ret);

    hash_init(fp_table);
    isn_time_last_jiffies = jiffies;
    isn_time_counter = get_random_u32();

    pr_info("hev-tcpfp: v4 loaded (kprobe ISN+RTO, NF options, IPv4+IPv6)\n");
    return 0;
}

static void __exit hev_tcpfp_exit(void)
{
    struct fp_entry *e;
    struct hlist_node *tmp;
    int bkt, i;

    unregister_kprobe(&kp_retransmit);
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
    pr_info("hev-tcpfp: v4 unloaded\n");
}

module_init(hev_tcpfp_init);
module_exit(hev_tcpfp_exit);
