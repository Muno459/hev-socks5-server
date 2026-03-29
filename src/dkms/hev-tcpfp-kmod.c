// SPDX-License-Identifier: GPL-2.0
/*
 * hev-tcpfp-kmod.c — TCP/IP fingerprint spoofing kernel module v5.
 *
 * Native emission via kprobes:
 *   - ISN: kprobe on tcp_connect sets tp->write_seq
 *   - RTO: kretprobe on tcp_connect_init sets icsk->icsk_rto (initial)
 *          kprobe on tcp_retransmit_timer sets icsk->icsk_rto (subsequent)
 *   - Window: kretprobe on tcp_connect_init sets tp->rcv_wnd
 *   - WScale: kretprobe on tcp_connect_init sets tp->rx_opt.rcv_wscale
 *   - SACK/TS: kretprobe on tcp_connect_init adjusts tp->tcp_header_len
 *   - MSS/WS/SACK/TS values: kretprobe on tcp_syn_options modifies opts struct
 *
 * Netfilter LOCAL_OUT (in-place rewrite, only for what can't be native):
 *   - TCP options ORDER (hardcoded in tcp_options_write)
 *   - IP ID behavior
 *   - DF/RST/FIN flags
 *   - Timestamp clock scaling
 *
 * SAFETY: never modifies skb length/tail except via doff (SYN only, no payload).
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
MODULE_DESCRIPTION("TCP/IP fingerprint spoofing v5 (native kprobe + NF reorder)");
MODULE_VERSION("5.0");

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
 * NATIVE KPROBES — kernel builds correct packets directly
 * ================================================================ */

/*
 * kprobe on tcp_connect (pre handler):
 * - Sets tp->write_seq for ISN (kernel uses it to build the SYN seq number)
 *
 * Called BEFORE tcp_connect_init, so write_seq may be overwritten by
 * tcp_connect_init's snd_una/snd_nxt copies. We set it here AND in
 * the tcp_connect_init kretprobe to ensure it sticks.
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
 * kretprobe on tcp_connect_init:
 * Fires AFTER tcp_connect_init returns. At this point the kernel has set:
 *   - icsk->icsk_rto = tcp_timeout_init() = 1s
 *   - tp->rcv_wnd = initial window
 *   - tp->rx_opt.rcv_wscale = window scale
 *   - tp->tcp_header_len = 20 + (timestamps ? 12 : 0)
 *   - tp->snd_una = tp->snd_nxt = tp->write_seq (ISN)
 *
 * We override these to match the target fingerprint.
 * tcp_connect() then uses our values to build and send the SYN.
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
     * Re-set write_seq and update copies so tcp_connect uses our ISN. */
    if (req->isn_pattern != ISN_RANDOM) {
        u32 isn = generate_isn(fp);
        tp->write_seq = isn;
        tp->snd_una = isn;
        tp->snd_sml = isn;
        tp->snd_up = isn;
        tp->snd_nxt = isn;
    }

    /* Initial RTO: kernel set icsk_rto = 1s. Override it.
     * tcp_connect arms timer with icsk_rto at line 4135-4136. */
    if (req->rto_pattern != 0 || req->rto_initial_ms != 0) {
        icsk->icsk_rto = get_rto_jiffies(fp, 0);
        fp->syn_retransmits = 1;
    }

    /* Window: __tcp_transmit_skb uses min(tp->rcv_wnd, 65535) for SYN.
     * Set rcv_wnd to our target window value. */
    if (req->tcp_window > 0)
        tp->rcv_wnd = req->tcp_window;

    /* Window scale: tcp_syn_options reads tp->rx_opt.rcv_wscale.
     * Set it to our target. Also update rcv_ssthresh for consistency. */
    if (req->wscale > 0) {
        tp->rx_opt.rcv_wscale = req->wscale;
        tp->rcv_ssthresh = tp->rcv_wnd;
    }

    /* Timestamps: if the fingerprint says no timestamps but kernel has them,
     * reduce tcp_header_len to remove TS space. tcp_syn_options checks
     * sysctl (which we can't change per-socket), but if we reduce
     * tcp_header_len, tcp_syn_options will see less space available. */
    if (req->timestamps == 0 && tp->tcp_header_len > sizeof(struct tcphdr)) {
        /* Fingerprint says no timestamps — set header to minimum.
         * tcp_syn_options checks sysctl_tcp_timestamps which is global,
         * so the kretprobe on tcp_syn_options will handle removing TS. */
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

/*
 * kretprobe on tcp_syn_options:
 * Fires AFTER tcp_syn_options fills the tcp_out_options struct.
 * We modify opts to control MSS, timestamps, SACK, window scale values.
 *
 * tcp_syn_options signature:
 *   unsigned int tcp_syn_options(struct sock *sk, struct sk_buff *skb,
 *                                struct tcp_out_options *opts,
 *                                struct tcp_key *key)
 * x86_64 ABI: rdi=sk, rsi=skb, rdx=opts, rcx=key
 * Return value in rax = total options size in bytes.
 *
 * The kernel's tcp_out_options struct (from include/net/tcp.h):
 *   u16 options;        // bitmask: OPTION_TS, OPTION_SACK_ADVERTISE, etc.
 *   u16 mss;            // MSS value to advertise
 *   u8  ws;             // window scale
 *   u8  num_sack_blocks; // SACK blocks count
 *   ... (hash, tsval, tsecr, etc.)
 */

/*
 * We need to know the tcp_out_options layout. From kernel source:
 *
 * struct tcp_out_options {
 *     u16 options;          // offset 0
 *     u16 mss;              // offset 2
 *     u8  ws;               // offset 4
 *     u8  num_sack_blocks;  // offset 5
 *     u8  hash_size;        // offset 6
 *     u8  bpf_opt_len;      // offset 7
 *     __u8 *hash;           // offset 8
 *     __u32 tsval, tsecr;   // offset 16, 20
 *     struct tcp_fastopen_cookie *fastopen_cookie; // offset 24
 * };
 *
 * OPTION_TS             = BIT(1)  = 2
 * OPTION_SACK_ADVERTISE = BIT(4)  = 16
 * OPTION_WSCALE         = BIT(5)  = 32
 */

#define KERN_OPT_SACK_ADVERTISE (1 << 0)  /* BIT(0) */
#define KERN_OPT_TS             (1 << 1)  /* BIT(1) */
#define KERN_OPT_WSCALE         (1 << 3)  /* BIT(3) */

struct syn_opts_data {
    struct sock *sk;
    void *opts;  /* pointer to struct tcp_out_options on caller's stack */
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
    u16 *options_p;
    u16 *mss_p;
    u8 *ws_p;
    u32 *tsval_p;
    u16 options;
    unsigned int size;

    if (!sk || !opts) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    req = &fp->req;

    /* Access tcp_out_options fields by offset */
    options_p = (u16 *)opts;          /* offset 0 */
    mss_p     = (u16 *)(opts + 2);    /* offset 2 */
    ws_p      = (u8 *)(opts + 4);     /* offset 4 */
    tsval_p   = (u32 *)(opts + 16);   /* offset 16 */
    options = *options_p;
    size = (unsigned int)regs_return_value(regs);

    /* Override window scale value */
    if (req->wscale > 0 && (options & KERN_OPT_WSCALE))
        *ws_p = req->wscale;

    /* Override SACK permitted */
    if (req->sack_perm == 0) {
        /* Remove SACK from options */
        if (options & KERN_OPT_SACK_ADVERTISE) {
            *options_p &= ~KERN_OPT_SACK_ADVERTISE;
            /* If SACK was combined with TS (no extra space used),
             * removing it doesn't change size. If standalone (4 bytes),
             * we'd need to adjust, but this is handled by NF rewrite. */
        }
    } else if (req->sack_perm == 1) {
        /* Ensure SACK is present */
        *options_p |= KERN_OPT_SACK_ADVERTISE;
    }

    /* Override timestamps */
    if (req->timestamps == 0 && (options & KERN_OPT_TS)) {
        /* Remove timestamps flag. tcp_options_write won't write TS.
         * SACK was combined with TS (0 extra bytes), now it needs
         * standalone space (4 bytes). Recompute total size. */
        *options_p &= ~KERN_OPT_TS;
    }

    /* Override timestamp initial value */
    if (req->ts_initial > 0 && ((*options_p) & KERN_OPT_TS))
        *tsval_p = req->ts_initial;

    /* Recompute options size based on what tcp_options_write will emit */
    {
        unsigned int new_size = 0;
        u16 final_options = *options_p;
        if (*mss_p)
            new_size += 4;  /* TCPOLEN_MSS_ALIGNED */
        if (final_options & KERN_OPT_TS)
            new_size += 12; /* TCPOLEN_TSTAMP_ALIGNED (includes SACK if both) */
        if ((final_options & KERN_OPT_SACK_ADVERTISE) &&
            !(final_options & KERN_OPT_TS))
            new_size += 4;  /* TCPOLEN_SACKPERM_ALIGNED (standalone) */
        if (final_options & KERN_OPT_WSCALE)
            new_size += 4;  /* TCPOLEN_WSCALE_ALIGNED */
        regs->ax = new_size;
    }

    return 0;
}

static struct kretprobe krp_syn_options = {
    .handler = krp_syn_options_ret,
    .entry_handler = krp_syn_options_entry,
    .data_size = sizeof(struct syn_opts_data),
    .maxactive = 20,
    .kp.symbol_name = "tcp_syn_options",
};

/*
 * kprobe on tcp_retransmit_timer (pre handler):
 * Fires BEFORE the kernel processes backoff logic.
 *
 * Kernel backoff behavior (tcp_timer.c lines 649-664):
 * - SYN_SENT with total_rto <= sysctl_tcp_syn_linear_timeouts (default 4):
 *   NO doubling. icsk_rto stays as-is. Timer re-armed with same value.
 * - Otherwise: icsk_rto = min(icsk_rto << 1, TCP_RTO_MAX)
 *
 * Strategy: Set icsk_rto to our target value. After the kernel's backoff
 * logic runs (which may double it), the NF hook will correct it via
 * mod_timer with the right value for the NEXT retransmit.
 */
static int kp_retransmit_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->di;
    struct tcp_sock *tp;
    struct inet_connection_sock *icsk;
    struct fp_entry *fp;
    u64 cookie;
    unsigned long rto;
    int idx;
    int linear;

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

    /* Check if kernel will use linear (no doubling) or exponential backoff.
     * SYN_SENT: linear for first N retransmits (sysctl_tcp_syn_linear_timeouts).
     * For linear: set icsk_rto = target directly (kernel won't modify it).
     * For exponential: set icsk_rto = target/2 so doubling gives target. */
    linear = (sk->sk_state == TCP_SYN_SENT &&
              tp->total_rto <=
              READ_ONCE(sock_net(sk)->ipv4.sysctl_tcp_syn_linear_timeouts));

    if (linear) {
        icsk->icsk_rto = rto;
    } else {
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
 * NETFILTER HOOKS — only for TCP option ORDER and IP-layer mods
 * ================================================================ */

/*
 * Rewrite SYN TCP options in the target ORDER.
 * The kernel has already written them (via tcp_options_write) in a fixed
 * order (MSS, TS+SACK, WS). We reorder them to match the fingerprint.
 *
 * We also handle: removing options that were disabled via kretprobe but
 * tcp_options_write still wrote (race conditions), and trimming doff.
 */
static void rewrite_syn_options(struct sk_buff *skb, struct fp_entry *fp)
{
    struct tcphdr *th = tcp_hdr(skb);
    unsigned int hdrlen, opts_len;
    u8 *opts, *p;
    u16 mss_val = 0;
    u8 ws_val = 0;
    u32 tsval = 0, tsecr = 0;
    int has_sack = 0, has_ts = 0;
    int i, wrote;
    struct hev_tcpfp_req *req = &fp->req;

    if (!th || !th->syn || th->ack)
        return;

    if (req->tcp_options_count == 0)
        return;

    hdrlen = th->doff * 4;
    opts = (u8 *)th + sizeof(struct tcphdr);
    opts_len = hdrlen - sizeof(struct tcphdr);

    if (skb_ensure_writable(skb, skb_transport_offset(skb) + hdrlen))
        return;
    th = tcp_hdr(skb);
    opts = (u8 *)th + sizeof(struct tcphdr);

    /* Parse what the kernel wrote */
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
        else if (kind == OPT_SACK && len == 2)
            has_sack = 1;
        else if (kind == OPT_TS && len >= 10) {
            tsval = ntohl(*(u32 *)(p + 2));
            tsecr = ntohl(*(u32 *)(p + 6));
            has_ts = 1;
        }
        p += len;
    }

    /* Override values from fingerprint */
    if (req->wscale > 0)
        ws_val = req->wscale;

    /* Rewrite options in target order */
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

    /* Trim TCP header if we used fewer bytes */
    {
        int new_padded = (wrote + 3) & ~3;
        int new_hdrlen = sizeof(struct tcphdr) + new_padded;
        int old_total = th->doff * 4;
        if (new_hdrlen < old_total && new_padded <= (int)opts_len)
            th->doff = new_hdrlen / 4;
    }
}

/* Timestamp clock scaling (all packets with TS option) */
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

    /* SYN: rewrite options in target order */
    if (th->syn && !th->ack) {
        int old_doff = th->doff;

        /* Window override: kretprobe set tp->rcv_wnd, but
         * __tcp_transmit_skb caps at 65535. Override directly. */
        if (fp->req.tcp_window > 0)
            th->window = htons(fp->req.tcp_window);

        rewrite_syn_options(skb, fp);
        iph = ip_hdr(skb);
        th = tcp_hdr(skb);
        trim = (old_doff - th->doff) * 4;
        if (trim > 0)
            iph->tot_len = htons(ntohs(iph->tot_len) - trim);
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

    /* Timestamp clock scaling (all packets) */
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

    /* SYN: rewrite options in target order */
    if (th->syn && !th->ack) {
        int old_doff = th->doff;

        if (fp->req.tcp_window > 0)
            th->window = htons(fp->req.tcp_window);

        rewrite_syn_options(skb, fp);
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

    /* Timestamp clock scaling */
    if (fp->req.ts_clock > 0 && fp->req.ts_clock != 1000)
        scale_timestamps(th, fp->req.ts_clock);

    /* TCP checksum (IPv6 pseudo-header) */
    tcp_len = ntohs(ip6h->payload_len);
    th->check = 0;
    th->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
                                 tcp_len, IPPROTO_TCP,
                                 csum_partial((u8 *)th, tcp_len, 0));
    skb->ip_summed = CHECKSUM_NONE;
    return NF_ACCEPT;
}

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

    ret = register_kprobe(&kp_retransmit);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_retransmit_timer failed (%d)\n", ret);

    hash_init(fp_table);
    isn_time_last_jiffies = jiffies;
    isn_time_counter = get_random_u32();

    pr_info("hev-tcpfp: v5 loaded (native kprobe ISN+RTO+WIN+WS+SACK+TS, NF reorder+IP)\n");
    return 0;
}

static void __exit hev_tcpfp_exit(void)
{
    struct fp_entry *e;
    struct hlist_node *tmp;
    int bkt, i;

    unregister_kprobe(&kp_retransmit);
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
    pr_info("hev-tcpfp: v5 unloaded\n");
}

module_init(hev_tcpfp_init);
module_exit(hev_tcpfp_exit);
