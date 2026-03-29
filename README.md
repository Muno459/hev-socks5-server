
<p align="center">
<pre align="center">
    ███████╗██╗  ██╗██╗   ██╗██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗
    ██╔════╝██║ ██╔╝╚██╗ ██╔╝██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝
    ███████╗█████╔╝  ╚████╔╝ ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝
    ╚════██║██╔═██╗   ╚██╔╝  ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝
    ███████║██║  ██╗   ██║   ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║
    ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝
              High-performance SOCKS5 proxy with TCP/IP fingerprint spoofing
</pre>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#tcp-fingerprinting">TCP Fingerprinting</a> &bull;
  <a href="#configuration">Configuration</a> &bull;
  <a href="#api">API</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/speed-splice%20zero--copy-brightgreen" alt="speed">
  <img src="https://img.shields.io/badge/fingerprint-p0f%20verified-blue" alt="fingerprint">
  <img src="https://img.shields.io/badge/kernel-DKMS%20hot--loadable-orange" alt="kernel">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
</p>

## Features

- **High-performance** splice-based zero-copy data relay with multi-worker threading
- **TCP/IP fingerprint spoofing** per-user OS fingerprint profiles via DKMS kernel module
- **p0f signature support** configure fingerprints using standard p0f v3 signature strings
- **Dynamic fingerprinting** encode fingerprint in SOCKS5 password field at runtime
- **Session-persistent** fingerprint applies to entire TCP session, not just SYN
- **Hot-loadable** `git clone && make && run`, kernel module auto-builds and loads
- **Zero impact** only proxy connections are modified, all other system TCP traffic untouched
- IPv4/IPv6 dual stack
- Standard `CONNECT` and `UDP ASSOCIATE` commands
- Extended `FWD UDP` command (UDP in TCP)
- Multiple username/password authentication

## Quick Start

```bash
git clone --recursive https://github.com/Muno459/skyproxy
cd skyproxy
make          # builds binary + kernel module + loads it
```

Edit `conf/auth.json` with your fingerprint profiles, then:

```bash
./bin/skyproxy conf/main.yml
```

Connect through the proxy:

```bash
curl -x socks5h://win10:pass@127.0.0.1:1080 http://example.com
```

That's it. The outgoing connection now has a Windows 10 TCP/IP fingerprint.

### Requirements

- Linux kernel 5.10+ with headers installed (`apt install linux-headers-$(uname -r)`)
- GCC, make
- Root access (for kernel module loading)

## TCP Fingerprinting

### How it works

The kernel module uses **ftrace function redirection** and **kprobe struct injection** to make the Linux TCP stack natively emit packets matching any target OS fingerprint. For fingerprinted sockets, our function runs instead of the kernel's `tcp_options_write`. For everything else, the original kernel code runs untouched.

| Parameter | Mechanism | Scope |
|-----------|-----------|-------|
| TCP option order | ftrace redirect of `tcp_options_write` | Per-packet |
| Window size | Struct injection `tp->rcv_wnd` | SYN + negotiated |
| Window scale | Struct injection `tp->rx_opt.rcv_wscale` | SYN + negotiated |
| SACK/Timestamps | Struct injection `opts->options` flags | Session-wide |
| ISN pattern | Struct injection `tp->write_seq` | SYN |
| RTO pattern | Struct injection `icsk->icsk_rto` | Retransmits |
| TS clock rate | ftrace redirect (scaling in option writer) | Per-packet |
| IP TTL | `setsockopt(IP_TTL)` | Socket-wide |
| IP ID | Netfilter (IP-layer) | Per-packet |

### Supported signature formats

SkyProxy accepts both **p0f v3** and **JA4T** fingerprint formats. Auto-detected based on input.

### p0f signature format

```
ver:ttl:olen:mss:wsize,scale:olayout:quirks:pclass
```

| Field | Description | Example |
|-------|-------------|---------|
| `ver` | IP version (4 or 6) | `4` |
| `ttl` | Initial TTL | `128` (Windows), `64` (Linux) |
| `olen` | IP options length | `0` |
| `mss` | TCP MSS value | `1460` |
| `wsize,scale` | Window size and scale factor | `65535,8` or `mss*20,7` |
| `olayout` | TCP option order | `mss,nop,ws,nop,nop,sok` |
| `quirks` | IP/TCP quirks | `df,id+` |
| `pclass` | Payload class (0=no payload) | `0` |

### Active TCP fingerprint parameters

Append `~` after the p0f signature for active fingerprinting parameters:

```
4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0~rto=w,isn=t,ts=250
```

| Parameter | Values | Description |
|-----------|--------|-------------|
| `rto=` | `l` (Linux), `w` (Windows), `m` (macOS), `1000-2000-4000` (custom ms) | Retransmission timeout pattern |
| `isn=` | `r` (random), `t` (time-based), `c` (constant), `i` (incremental) | Initial sequence number pattern |
| `ts=` | `250`, `1000`, etc. | Timestamp clock rate in Hz |
| `cc=` | `cubic`, `reno`, `bbr` | Congestion control algorithm |
| `ecn=` | `1` (enable), `0` (disable) | ECN negotiation (ECE+CWR on SYN) |
| `strip=` | `10` (strip after N retransmits) | Option stripping on final SYN retransmit |

### JA4T signature format

```
window_options_mss_wscale[_rto]
```

| Field | Description | Example |
|-------|-------------|---------|
| `window` | TCP window size | `65535` |
| `options` | TCP options as hyphen-separated kind numbers | `2-1-3-1-1-4` |
| `mss` | Maximum segment size | `1460` |
| `wscale` | Window scale factor | `8` |
| `rto` | (optional) Retransmission timings in seconds, R-prefixed retry count | `1-2-4-8-R6` |

TCP option kind numbers: 0=EOL, 1=NOP, 2=MSS, 3=WS, 4=SACK, 8=TS

Examples:

```
# Windows 11
65535_2-1-3-1-1-4_1460_8_1-2-4-8

# Linux
29200_2-4-8-1-3_1460_7_1-1-1-1-1-2-4-8-16-32

# macOS
65535_2-1-3-1-1-8-4-0_1460_6
```

JA4T signatures can be used anywhere p0f signatures are accepted: in auth.json `"p0f"` field, or in dynamic password encoding.

### Preset profiles

Use built-in OS presets instead of writing full signatures:

```bash
curl -x socks5h://fp:secret(win11)@server:1080 http://target
curl -x socks5h://fp:secret(macos)@server:1080 http://target
curl -x socks5h://fp:secret(ios)@server:1080 http://target
curl -x socks5h://fp:secret(android)@server:1080 http://target
curl -x socks5h://fp:secret(linux)@server:1080 http://target
```

Available presets: `win11`, `win10`, `windows`, `winxp`, `macos`, `mac`, `ios`, `iphone`, `android`, `linux`

Presets include the complete fingerprint with real-device RTO patterns captured from actual hardware. They work in auth.json too:

```json
{ "username": "stealth", "password": "pass", "p0f": "macos" }
```

### Mirror mode

Mirror the connecting client's TCP fingerprint onto the outgoing connection:

```bash
curl -x socks5h://fp:secret(mirror)@server:1080 http://target
```

Uses the kernel's `TCP_SAVE_SYN`/`TCP_SAVED_SYN` (available since Linux 4.2, [originally developed at Google](https://github.com/torvalds/linux/commit/cd8ae85299d54155702a56811b2e035e63064d3d)) to capture the raw SYN headers from the incoming client connection.

Mirror mode does two things:

1. **Passive fingerprint from the real SYN**: parses the client's TTL, window size, TCP options, MSS, window scale, ECN flags, and IP ID behavior directly from the captured SYN headers. These exact values are applied to the outgoing connection.

2. **Active fingerprint from OS detection**: identifies the client's OS family from the SYN signals (TTL 128 = Windows, TTL 64 + ECN = macOS, TTL 64 = Linux) and applies the matching preset's active parameters (RTO pattern, retransmit count, option stripping). This means the outgoing connection has correct retransmission behavior too, not just correct SYN options.

| SYN Signal | Detected OS | Active Preset Applied |
|------------|-------------|----------------------|
| TTL 128, no timestamps | Windows | `windows` (RTO: 1-2-4-8) |
| TTL 64, ECN enabled | Darwin | `macos` (RTO: 1x5-2-4-8-16-32, strip on #11) |
| TTL 64, no ECN | Linux/Android | `linux` (RTO: 1x5-2-4-8-16-32) |

Mirror mode works in auth.json too (also accepts `ja4t` and `preset` field names):

```json
{ "username": "transparent", "password": "pass", "p0f": "mirror" }
```

### Dynamic fingerprinting via password

Set a wildcard user with `(*)` in the password:

```json
[
  { "username": "fp", "password": "secret(*)" }
]
```

The client encodes a p0f or JA4T signature in the password:

```bash
# p0f format (dots replace colons in password encoding)
curl -x socks5h://fp:secret(4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0)@server:1080 http://target

# JA4T format (no encoding needed, underscores are fine in passwords)
curl -x socks5h://fp:secret(65535_2-1-3-1-1-4_1460_8_1-2-4-8)@server:1080 http://target
```

### Verified OS profiles

All profiles verified at **p0f distance 0** (exact match):

| Profile | p0f Detection | Signature |
|---------|--------------|-----------|
| Windows 10/11 | `Windows NT kernel 5.x` | `4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0` |
| macOS / iOS | `Mac OS X` | `4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0` |
| Linux 3.11+ | `Linux 3.11 and newer` | `4:64:0:1460:mss*20,7:mss,sok,ts,nop,ws:df:0` |
| Windows XP | `Windows XP` | `4:128:0:1460:65535,0:mss,nop,nop,sok:df,id+:0` |

For detailed fingerprint research including active TCP analysis (retransmission timing, option stripping, ECN behavior) across Windows 11, macOS Tahoe, iOS 26, Android 16, and Linux 6.8, see [docs/tcp-fingerprint-research.md](docs/tcp-fingerprint-research.md).

## Configuration

### Main config

SkyProxy uses YAML for server configuration (`conf/main.yml`):

```yaml
main:
  workers: 4
  port: 1080
  listen-address: '::'
  listen-ipv6-only: false
  bind-address: ''
  bind-interface: ''
  domain-address-type: unspec
  mark: 0

auth:
  file: conf/auth.json

misc:
  connect-timeout: 30000
  # log-file: stderr
  # log-level: warn
  # pid-file: /run/skyproxy.pid
  # limit-nofile: 65535
```

### Authentication

SkyProxy supports two auth file formats. Both extend the upstream hev-socks5-server format with additional fields (`iface`, `p0f`, fingerprint).

**Plaintext format** (`conf/auth.txt`):

```
<username> <password> [<mark>] [<source_ip>] [<iface>]
```

- `username` string up to 255 chars
- `password` string up to 255 chars
- `mark` hex socket mark (optional, use `0` if unused)
- `source_ip` IPv4/IPv6 bind address (optional)
- `iface` network interface to bind to, e.g. `eth0`, `wlan0` (optional)

**JSON format** (`conf/auth.json`):

```json
[
  { "username": "tom", "password": "pass" },

  { "username": "jerry", "password": "pass", "mark": "0x1a" },

  { "username": "alice", "password": "pass", "iface": "wlan0" },

  { "username": "win10", "password": "pass",
    "p0f": "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0~rto=w" },

  { "username": "stealth", "password": "pass", "preset": "macos" },

  { "username": "fast", "password": "pass",
    "ja4t": "65535_2-1-3-1-1-4_1460_8_1-2-4-8" },

  { "username": "transparent", "password": "pass", "p0f": "mirror" },

  { "username": "fp", "password": "secret(*)" }
]
```

The JSON format supports all plaintext fields plus:
- `p0f` p0f v3 signature, JA4T signature, preset name (`macos`), or `mirror`
- `ja4t` alias for `p0f` (accepts JA4T signatures)
- `preset` alias for `p0f` (accepts preset names)
- `fingerprint` object with individual fields (`ttl`, `mss`, `window`, `df`, etc.)
- `password: "pass(*)"` wildcard for dynamic fingerprint via client password

### Live reload

Reload auth without restarting:

```bash
killall -SIGUSR1 skyproxy
```

## Build Options

```bash
make                      # binary + kernel module + load
make exec                 # binary only (no kernel module)
make dkms                 # kernel module only
make ENABLE_STATIC=1      # static binary
make kmod-load            # load kernel module
make kmod-unload          # unload kernel module
```

### Cross-platform

The proxy binary builds on Linux, Android, iOS, macOS, and Windows (MSYS2). The TCP fingerprint kernel module is Linux-only and requires kernel headers.

## API

```c
int hev_socks5_server_main_from_file (const char *config_path);
int hev_socks5_server_main_from_str (const unsigned char *config_str,
                                     unsigned int config_len);
void hev_socks5_server_quit (void);
```

## Credits

Built on top of [hev-socks5-server](https://github.com/heiher/hev-socks5-server) by [hev](https://hev.cc).

## License

SkyProxy Non-Commercial License. See [LICENSE](LICENSE).

Non-commercial use only. Attribution to [Muno459](https://github.com/Muno459) required. Kernel module additionally licensed under GPL-2.0. Built on [hev-socks5-server](https://github.com/heiher/hev-socks5-server) (MIT) by [hev](https://hev.cc).
