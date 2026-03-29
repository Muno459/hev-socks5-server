// SPDX-License-Identifier: GPL-2.0
/*
 * hev-tcpfp-kmod.c — TCP/IP fingerprint spoofing kernel module v7.
 *
 * Function replacement via ftrace + struct injection via kprobes.
 *
 * ftrace (function redirect):
 *   - tcp_options_write: for fingerprinted sockets, our function runs
 *     INSTEAD of the original. Writes options in target order from
 *     scratch. Original never executes. For non-fingerprinted sockets,
 *     the original kernel code runs 100% unchanged.
 *
 * kprobes (struct field injection — kernel reads our values natively):
 *   - ISN: kprobe tcp_connect → tp->write_seq
 *   - RTO: kretprobe tcp_connect_init → icsk->icsk_rto (initial)
 *          kprobe tcp_retransmit_timer → icsk->icsk_rto (subsequent)
 *   - Window: kretprobe tcp_connect_init → tp->rcv_wnd
 *   - WScale: kretprobe tcp_connect_init → tp->rx_opt.rcv_wscale
 *   - SACK/TS/WS flags: kretprobe tcp_syn_options → opts struct
 *
 * Netfilter LOCAL_OUT (IP-layer only, no TCP modifications):
 *   - IP ID behavior
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
#include <linux/ftrace.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <net/ipv6.h>
#include <net/inet_connection_sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Muno459 (SkyProxy)");
MODULE_DESCRIPTION("TCP/IP fingerprint spoofing v7 (ftrace function redirect + kprobes)");
MODULE_VERSION("7.0");

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
    u8 option_strip_after;
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

    /* Recompute exact size based on what our byte-level writer emits.
     * If we have a custom option order, count actual byte sizes.
     * If no custom order, use kernel-style 32-bit aligned sizes. */
    new_size = 0;
    if (req->tcp_options_count > 0) {
        int k;
        for (k = 0; k < req->tcp_options_count; k++) {
            switch (req->tcp_options_order[k]) {
            case OPT_NOP: case OPT_EOL: new_size += 1; break;
            case OPT_MSS:  new_size += 4; break;  /* kind+len+val16 */
            case OPT_WS:   new_size += 3; break;  /* kind+len+val8 */
            case OPT_SACK: new_size += 2; break;  /* kind+len */
            case OPT_TS:
                if (*options_p & KERN_OPT_TS)
                    new_size += 10; /* kind+len+tsval+tsecr */
                break;
            }
        }
        new_size = (new_size + 3) & ~3; /* pad to 32-bit boundary */
    } else {
        /* No custom order: kernel writes with 32-bit aligned padding */
        u16 f = *options_p;
        if (*(u16 *)(opts + 2)) new_size += 4;  /* MSS */
        if (f & KERN_OPT_TS) new_size += 12;    /* TS+NOP padding */
        if ((f & KERN_OPT_SACK_ADVERTISE) && !(f & KERN_OPT_TS))
            new_size += 4;
        if (f & KERN_OPT_WSCALE) new_size += 4;
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

/* ================================================================
 * FTRACE FUNCTION REDIRECT: tcp_options_write
 *
 * For fingerprinted sockets: our function REPLACES tcp_options_write.
 * The original never executes. Our code writes options in the correct
 * order from scratch. The TCP checksum is computed AFTER our function
 * returns, so it naturally covers our bytes.
 *
 * For non-fingerprinted sockets: ftrace callback doesn't modify regs.
 * The original kernel tcp_options_write runs 100% unchanged.
 *
 * tcp_options_write signature (x86_64):
 *   void tcp_options_write(th, tp, tcprsk, opts, key)
 *   rdi=th, rsi=tp, rdx=tcprsk, rcx=opts, r8=key
 *
 * tcp_out_options layout (kernel 6.8):
 *   offset 0:  u16 options (bitmask)
 *   offset 2:  u16 mss
 *   offset 4:  u8  ws
 *   offset 5:  u8  num_sack_blocks
 *   offset 16: u32 tsval
 *   offset 20: u32 tsecr
 * ================================================================ */

static unsigned long ftrace_opts_target_addr;

/*
 * Our tcp_options_write for fingerprinted sockets.
 * Called INSTEAD of the kernel's — the original never runs.
 * Same calling convention (params in same registers).
 */
static void notrace fp_tcp_options_write(struct tcphdr *th,
    struct tcp_sock *tp, void *tcprsk, void *opts, void *key)
{
    struct fp_entry *fp;
    struct hev_tcpfp_req *req;
    u64 cookie;
    u16 options = *(u16 *)opts;
    u16 mss     = *(u16 *)(opts + 2);
    u8  ws;
    u32 tsval   = *(u32 *)(opts + 16);
    u32 tsecr   = *(u32 *)(opts + 20);
    u8  num_sack_blocks = *(u8 *)(opts + 5);

    cookie = atomic64_read(&((struct sock *)tp)->sk_cookie);
    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return;

    req = &fp->req;
    ws = req->wscale > 0 ? req->wscale : *(u8 *)(opts + 4);

    /* TS clock scaling — applied to ALL packets */
    if (req->ts_clock > 0 && req->ts_clock != 1000 && tsval) {
        if (req->ts_clock < 1000)
            tsval = tsval / (1000 / req->ts_clock);
        else
            tsval = tsval * (req->ts_clock / 1000);
    }

    /* ECN: set ECE+CWR on initial SYN, clear on retransmits.
     * Darwin enables ECN on the first SYN but drops it on all retransmits.
     * tcp_connect_init kretprobe sets syn_retransmits=1 for the initial SYN.
     * tcp_retransmit_timer kprobe increments it for each retransmit.
     * So: initial SYN = 1, first retransmit = 2, etc.
     * We want ECN only when syn_retransmits <= 1. */
    if (th->syn && !th->ack) {
        if ((req->quirks & (1u << 3)) && fp->syn_retransmits <= 1) {
            *((u8 *)th + 13) |= 0xC0; /* ECE + CWR */
        } else if (req->quirks & (1u << 3)) {
            *((u8 *)th + 13) &= ~0xC0; /* clear on retransmits */
        }
    }

    /* === SYN: write options in target order (byte-level) === */
    if (th->syn && !th->ack && req->tcp_options_count > 0) {
        u8 *p = (u8 *)(th + 1);
        int i;
        int stripped = 0;

        /* Option stripping: after N retransmits, Darwin sends
         * a stripped SYN with only MSS + SACK_PERM + EOL.
         * fp->syn_retransmits tracks how many SYNs have been sent. */
        if (req->option_strip_after > 0 &&
            fp->syn_retransmits > req->option_strip_after) {
            stripped = 1;
        }

        if (stripped) {
            /* Stripped SYN: MSS, SACK_PERM, EOL only */
            *p++ = TCPOPT_MSS; *p++ = TCPOLEN_MSS;
            *(u16 *)p = htons(mss); p += 2;
            *p++ = TCPOPT_SACK_PERM; *p++ = TCPOLEN_SACK_PERM;
            *p++ = TCPOPT_EOL;
        } else {
            for (i = 0; i < req->tcp_options_count && i < 16; i++) {
                switch (req->tcp_options_order[i]) {
                case OPT_NOP: *p++ = TCPOPT_NOP; break;
                case OPT_EOL: *p++ = TCPOPT_EOL; break;
                case OPT_MSS:
                    *p++ = TCPOPT_MSS; *p++ = TCPOLEN_MSS;
                    *(u16 *)p = htons(mss); p += 2;
                    break;
                case OPT_WS:
                    *p++ = TCPOPT_WINDOW; *p++ = TCPOLEN_WINDOW;
                    *p++ = ws;
                    break;
                case OPT_SACK:
                    *p++ = TCPOPT_SACK_PERM; *p++ = TCPOLEN_SACK_PERM;
                    break;
                case OPT_TS:
                    if (options & KERN_OPT_TS) {
                        *p++ = TCPOPT_TIMESTAMP; *p++ = TCPOLEN_TIMESTAMP;
                        *(u32 *)p = htonl(tsval); p += 4;
                        *(u32 *)p = htonl(tsecr); p += 4;
                    }
                    break;
                }
            }
        }
        return;
    }

    /* === Established: standard order + TS clock scaling === */
    {
        __be32 *ptr = (__be32 *)(th + 1);

        if (options & KERN_OPT_TS) {
            *ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                           (TCPOPT_TIMESTAMP << 8) | TCPOLEN_TIMESTAMP);
            *ptr++ = htonl(tsval);
            *ptr++ = htonl(tsecr);
        }

        if (num_sack_blocks) {
            struct tcp_sack_block *sp = tp->rx_opt.dsack ?
                tp->duplicate_sack : tp->selective_acks;
            int s;
            *ptr++ = htonl((TCPOPT_NOP << 24) | (TCPOPT_NOP << 16) |
                           (TCPOPT_SACK << 8) |
                           (TCPOLEN_SACK_BASE +
                            num_sack_blocks * TCPOLEN_SACK_PERBLOCK));
            for (s = 0; s < num_sack_blocks; s++) {
                *ptr++ = htonl(sp[s].start_seq);
                *ptr++ = htonl(sp[s].end_seq);
            }
            tp->rx_opt.dsack = 0;
        }
    }
}

/*
 * ftrace callback — decides per-call whether to redirect.
 * Non-fingerprinted sockets: don't touch regs → original runs.
 * Fingerprinted sockets: regs->ip = our function → original skipped.
 */
static void notrace ftrace_opts_handler(unsigned long ip,
                                         unsigned long parent_ip,
                                         struct ftrace_ops *op,
                                         struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct tcp_sock *tp;
    struct fp_entry *fp;
    u64 cookie;

    if (!regs) return;

    tp = (struct tcp_sock *)regs->si; /* rsi = tp */
    if (!tp) return;

    cookie = atomic64_read(&((struct sock *)tp)->sk_cookie);
    if (!cookie) return;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return;
    if (!fp->req.tcp_options_count && !fp->req.ts_clock)
        return;

    /* Redirect: our function runs instead of original */
    regs->ip = (unsigned long)fp_tcp_options_write;
}

static struct ftrace_ops ftrace_opts_ops = {
    .func    = ftrace_opts_handler,
    .flags   = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
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

/* --- kprobe: ip_local_out --- Native IP ID override
 *
 * ip_local_out(net, sk, skb) is the last function called before
 * the packet enters netfilter LOCAL_OUT and then the device.
 * At this point the IP header is fully built including iph->id.
 * The kernel zeros IP ID when DF is set (ip_select_ident_segs).
 * We override it here for Windows-style id+ (non-zero with DF).
 *
 * x86_64: rdi=net, rsi=sk, rdx=skb
 */
static int kp_ip_local_out_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct sock *sk = (struct sock *)regs->si;
    struct sk_buff *skb = (struct sk_buff *)regs->dx;
    struct iphdr *iph;
    struct fp_entry *fp;
    u64 cookie;

    if (!sk || !skb) return 0;
    cookie = atomic64_read(&sk->sk_cookie);
    if (!cookie) return 0;

    rcu_read_lock();
    fp = fp_find(cookie);
    rcu_read_unlock();
    if (!fp) return 0;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return 0;

    {
        struct tcphdr *th;
        int modified = 0;
        unsigned int ip_hdr_len = iph->ihl * 4;

        /* IP ID */
        if (fp->req.ip_id_behavior == IPID_RANDOM) {
            iph->id = htons(get_random_u16());
            modified = 1;
        } else if (fp->req.ip_id_behavior == IPID_ZERO && iph->id != 0) {
            iph->id = 0;
            modified = 1;
        }

        /* RST/FIN/ACK DF + RST TTL/window */
        if (skb->len >= ip_hdr_len + sizeof(struct tcphdr)) {
            th = (struct tcphdr *)((u8 *)iph + ip_hdr_len);

            if (th->rst) {
                if (fp->req.rst_df) {
                    iph->frag_off |= htons(IP_DF);
                    modified = 1;
                }
                if (fp->req.rst_ttl) {
                    iph->ttl = fp->req.rst_ttl;
                    modified = 1;
                }
                if (fp->req.rst_window) {
                    th->window = htons(fp->req.rst_window);
                    /* TCP checksum will be computed by the kernel after us */
                }
            }

            if (th->fin && fp->req.fin_df) {
                iph->frag_off |= htons(IP_DF);
                modified = 1;
            }

            if (th->ack && !th->syn && !th->fin && !th->rst && fp->req.ack_df) {
                iph->frag_off |= htons(IP_DF);
                modified = 1;
            }
        }

        if (modified) {
            iph->check = 0;
            iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
        }
    }

    return 0;
}

static struct kprobe kp_ip_local_out = {
    .symbol_name = "ip_local_out",
    .pre_handler = kp_ip_local_out_pre,
};

/* No netfilter hooks. Everything handled natively via kprobes + ftrace. */

/* --- init/exit --- */

static int __init hev_tcpfp_init(void)
{
    int ret;

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

    /* Native kprobes + ftrace (no netfilter) */
    ret = register_kprobe(&kp_tcp_connect);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_connect failed (%d)\n", ret);

    ret = register_kretprobe(&krp_connect_init);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_connect_init failed (%d)\n", ret);

    ret = register_kretprobe(&krp_syn_options);
    if (ret < 0)
        pr_warn("hev-tcpfp: kretprobe tcp_syn_options failed (%d)\n", ret);

    /* ftrace redirect for tcp_options_write */
    {
        struct kprobe kp_resolve = { .symbol_name = "tcp_options_write" };
        ret = register_kprobe(&kp_resolve);
        if (ret == 0) {
            ftrace_opts_target_addr = (unsigned long)kp_resolve.addr;
            unregister_kprobe(&kp_resolve);

            ret = ftrace_set_filter_ip(&ftrace_opts_ops,
                                        ftrace_opts_target_addr, 0, 0);
            if (ret == 0) {
                ret = register_ftrace_function(&ftrace_opts_ops);
                if (ret < 0)
                    pr_warn("hev-tcpfp: ftrace register failed (%d)\n", ret);
                else
                    pr_info("hev-tcpfp: ftrace redirect tcp_options_write active\n");
            } else {
                pr_warn("hev-tcpfp: ftrace filter failed (%d)\n", ret);
            }
        } else {
            pr_warn("hev-tcpfp: resolve tcp_options_write failed (%d)\n", ret);
        }
    }

    ret = register_kprobe(&kp_retransmit);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe tcp_retransmit_timer failed (%d)\n", ret);

    ret = register_kprobe(&kp_ip_local_out);
    if (ret < 0)
        pr_warn("hev-tcpfp: kprobe ip_local_out failed (%d)\n", ret);

    hash_init(fp_table);
    isn_time_last_jiffies = jiffies;
    isn_time_counter = get_random_u32();

    pr_info("hev-tcpfp: v7 loaded (ftrace tcp_options_write redirect, kprobes ISN+RTO+WIN+WS+SACK+TS, NF IP-layer)\n");
    return 0;
}

static void __exit hev_tcpfp_exit(void)
{
    struct fp_entry *e;
    struct hlist_node *tmp;
    int bkt;

    unregister_kprobe(&kp_ip_local_out);
    unregister_kprobe(&kp_retransmit);
    if (ftrace_opts_target_addr) {
        unregister_ftrace_function(&ftrace_opts_ops);
        ftrace_set_filter_ip(&ftrace_opts_ops, ftrace_opts_target_addr, 1, 0);
    }
    unregister_kretprobe(&krp_syn_options);
    unregister_kretprobe(&krp_connect_init);
    unregister_kprobe(&kp_tcp_connect);

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
    pr_info("hev-tcpfp: v7 unloaded\n");
}

module_init(hev_tcpfp_init);
module_exit(hev_tcpfp_exit);
