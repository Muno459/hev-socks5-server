
<p align="center">
  <img src="docs/header.svg" alt="SkyProxy" width="700">
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#tcp-fingerprinting">TCP Fingerprinting</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#research">Research</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/netfilter-zero-brightgreen" alt="zero netfilter">
  <img src="https://img.shields.io/badge/hooks-ftrace%20%2B%20kprobes-blue" alt="native hooks">
  <img src="https://img.shields.io/badge/p0f-distance%200-blueviolet" alt="p0f verified">
  <img src="https://img.shields.io/badge/DKMS-hot--loadable-orange" alt="hot-loadable">
</p>

## Features

- **Zero netfilter** - no packet rewriting framework. All hooks are kprobes + ftrace, native to the kernel's function call chain
- **Native TCP emission** - the kernel's own TCP stack builds correct packets. ftrace replaces `tcp_options_write` for fingerprinted sockets; original code runs untouched for everything else
- **Session-persistent** - fingerprint applies to the entire TCP session, not just the SYN. Timestamps, window scaling, and options stay consistent throughout
- **Wire-verified** - all profiles verified at p0f distance 0 with active fingerprint verification (RTO patterns, ECN behavior, option stripping)
- **Hot-loadable** - `git clone && make && run`. Kernel module auto-builds, loads, and unloads cleanly
- **Zero impact** - only proxy connections are modified. All other system TCP traffic is untouched
- **Splice zero-copy** - high-performance data relay with multi-worker threading
- **Multiple formats** - p0f v3, JA4T, preset names, and mirror mode. Auto-detected
- IPv4/IPv6 dual stack with native hooks on both `ip_local_out` and `ip6_local_out`
- Standard SOCKS5 `CONNECT` and `UDP ASSOCIATE` commands

## Quick Start

```bash
git clone --recursive https://github.com/Muno459/skyproxy
cd skyproxy
make
```

```bash
./bin/skyproxy conf/main.yml
```

The default auth has a user `user` with password `pass(*)`. The fingerprint goes inside the parentheses:

```bash
# Preset
curl -x socks5h://user:pass(win11)@127.0.0.1:1080 http://example.com
curl -x socks5h://user:pass(macos)@127.0.0.1:1080 http://example.com

# Custom p0f signature (dots replace colons)
curl -x socks5h://user:pass(4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0)@127.0.0.1:1080 http://example.com

# Custom JA4T signature
curl -x socks5h://user:pass(65535_2-1-3-1-1-4_1460_8)@127.0.0.1:1080 http://example.com

# Mirror the client's own TCP fingerprint
curl -x socks5h://user:pass(mirror)@127.0.0.1:1080 http://example.com
```

Or configure per-user profiles in `conf/auth.json`:

```json
{ "username": "user", "password": "pass", "preset": "win11" }
```

```bash
curl -x socks5h://user:pass@127.0.0.1:1080 http://example.com
```

### Requirements

- Linux kernel 5.10+ with headers (`apt install linux-headers-$(uname -r)`)
- GCC, make
- Root (for kernel module)

## TCP Fingerprinting

### How it works

7 native hooks into the kernel's TCP/IP stack. Zero netfilter.

| Hook | Function | What it controls |
|------|----------|-----------------|
| ftrace | `tcp_options_write` | TCP option order + TS clock scaling (all packets) |
| kprobe | `tcp_connect` | ISN (Initial Sequence Number) |
| kretprobe | `tcp_connect_init` | Initial RTO, window, wscale |
| kretprobe | `tcp_syn_options` | SACK/TS/WS flags + header size |
| kprobe | `tcp_retransmit_timer` | RTO pattern (linear/exponential) |
| kprobe | `ip_local_out` | IPv4 IP ID, RST/FIN/ACK DF |
| kprobe | `ip6_local_out` | IPv6 flow label, RST behavior |

For fingerprinted sockets, `tcp_options_write` is replaced via ftrace - our function writes options in the correct order from scratch. The original kernel function never executes. For non-fingerprinted sockets, the original runs untouched.

ECN flags (ECE+CWR) are set on the initial SYN and cleared on retransmits, matching real Darwin behavior. Option stripping (Darwin sends a stripped SYN after 10 retransmits) is handled in the same ftrace replacement.

The window scales normally after the SYN - the kernel's own `tcp_select_window()` manages it based on real buffer state. We only control the initial advertised window and wscale.

### Supported formats

SkyProxy auto-detects the format from the input:

**p0f v3**: `ver:ttl:olen:mss:wsize,scale:olayout:quirks:pclass`
```
4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
```

**JA4T**: `window_options_mss_wscale[_rto]`
```
65535_2-1-3-1-1-4_1460_8_1-2-4-8
```

**Presets**: `win11`, `win10`, `windows`, `winxp`, `macos`, `mac`, `ios`, `iphone`, `android`, `linux`
```bash
curl -x socks5h://user:pass(win11)@server:1080 http://target
```

**Mirror**: copies the connecting client's TCP fingerprint using [`TCP_SAVE_SYN`](https://github.com/torvalds/linux/commit/cd8ae85299d54155702a56811b2e035e63064d3d) (kernel 4.2+, originally developed at Google). Detects OS family from the SYN and applies matching active parameters (RTO, option stripping).
```bash
curl -x socks5h://user:pass(mirror)@server:1080 http://target
```

| Client SYN | Detected OS | Active Preset |
|------------|-------------|---------------|
| TTL 128, no timestamps | Windows | RTO: 1-2-4-8 |
| TTL 64, ECN enabled | Darwin | RTO: 1x5-2-4-8-16-32, strip #11, ECN first-SYN |
| TTL 64, no ECN | Linux/Android | RTO: 1x5-2-4-8-16-32 |

### Active TCP fingerprint parameters

Append `~` after the signature for active fingerprinting:

```
4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0~rto=1000-2000-4000-8000,ecn=1,strip=10
```

| Parameter | Values | Description |
|-----------|--------|-------------|
| `rto=` | `l` (Linux), `w` (Windows), `m` (macOS), `1000-2000-4000` (custom ms) | Retransmission timeout pattern |
| `isn=` | `r` (random), `t` (time-based), `c` (constant), `i` (incremental) | Initial sequence number pattern |
| `ts=` | `250`, `1000`, etc. | Timestamp clock rate in Hz |
| `cc=` | `cubic`, `reno`, `bbr` | Congestion control algorithm |
| `ecn=` | `1` (enable), `0` (disable) | ECN negotiation (ECE+CWR on initial SYN only) |
| `strip=` | `10` (strip after N retransmits) | Option stripping on final SYN retransmit |

### Wire-verified profiles

All profiles verified at **p0f distance 0** with active fingerprint verification:

| Profile | p0f Detection | Active Verification |
|---------|--------------|---------------------|
| Windows 10/11 | `Windows NT kernel 5.x` | RTO 1-2-4-8, IP ID non-zero with DF |
| macOS / iOS | `Mac OS X` | RTO 1x5-2-4-8-16-32, ECN first-SYN-only, option strip #11 |
| Linux 3.11+ | `Linux 3.11 and newer` | RTO 1x5-2-4-8-16-32 |
| Windows XP | `Windows XP` | No timestamps, no wscale |
| iOS (active) | Same passive as macOS | 60ms RTO within 2ms precision, strip #11 |

For detailed fingerprint research from real devices (Windows 11, macOS Tahoe, iOS 26, Android 16, Pixel 9 XL), see [docs/tcp-fingerprint-research.md](docs/tcp-fingerprint-research.md).

## Configuration

### Server config (`conf/main.yml`)

```yaml
main:
  workers: 4
  port: 1080
  listen-address: '::'
  listen-ipv6-only: false
  domain-address-type: unspec

auth:
  file: conf/auth.json

misc:
  connect-timeout: 30000
```

### Auth file (`conf/auth.json`)

```json
[
  { "username": "user", "password": "pass(*)" },

  { "username": "tom", "password": "pass" },

  { "username": "win10", "password": "pass",
    "p0f": "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0~rto=1000-2000-4000-8000" },

  { "username": "fast", "password": "pass",
    "ja4t": "65535_2-1-3-1-1-4_1460_8_1-2-4-8" },

  { "username": "stealth", "password": "pass", "preset": "macos" },

  { "username": "transparent", "password": "pass", "preset": "mirror" }
]
```

Each user can have a fingerprint via three field names:
- `p0f` - custom p0f v3 signature
- `ja4t` - custom JA4T signature
- `preset` - built-in preset name or `mirror`

All three auto-detect the format. `password: "pass(*)"` enables dynamic fingerprinting where the client sends the fingerprint inside the parentheses at connect time.

Reload auth without restarting:

```bash
killall -SIGUSR1 skyproxy
```

### Build options

```bash
make                      # binary + kernel module + load
make exec                 # binary only
make dkms                 # kernel module only
make ENABLE_STATIC=1      # static binary
make kmod-load            # load kernel module
make kmod-unload          # unload kernel module
```

## Research

See [docs/tcp-fingerprint-research.md](docs/tcp-fingerprint-research.md) for original TCP/IP fingerprint research including:

- Passive + active fingerprint data from 6 real devices
- 2-packet OS identification flowchart (1 SYN = OS family, 1 retransmit = exact OS)
- iOS 60ms retransmit discovery
- Darwin ECN + option stripping behavior
- iCloud Private Relay fingerprint analysis

## Credits

Built on [hev-socks5-server](https://github.com/heiher/hev-socks5-server) by [hev](https://hev.cc).

## License

SkyProxy Non-Commercial License. See [LICENSE](LICENSE).

Non-commercial use only. Attribution to [Muno459](https://github.com/Muno459) required. Kernel module additionally licensed under GPL-2.0.
