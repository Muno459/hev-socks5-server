
<p align="center">
<pre align="center">
    ██╗  ██╗███████╗██╗   ██╗    ███████╗ ██████╗  ██████╗██╗  ██╗███████╗███████╗
    ██║  ██║██╔════╝██║   ██║    ██╔════╝██╔═══██╗██╔════╝██║ ██╔╝██╔════╝██╔════╝
    ███████║█████╗  ██║   ██║    ███████╗██║   ██║██║     █████╔╝ ███████╗███████╗
    ██╔══██║██╔══╝  ╚██╗ ██╔╝    ╚════██║██║   ██║██║     ██╔═██╗ ╚════██║╚════██║
    ██║  ██║███████╗ ╚████╔╝     ███████║╚██████╔╝╚██████╗██║  ██╗███████║███████║
    ╚═╝  ╚═╝╚══════╝  ╚═══╝      ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚══════╝╚══════╝
                    High-performance SOCKS5 proxy with TCP/IP fingerprint spoofing
</pre>
</p>

<p align="center">
  <a href="#features">Features</a> &bull;
  <a href="#quick-start">Quick Start</a> &bull;
  <a href="#tcp-fingerprinting">TCP Fingerprinting</a> &bull;
  <a href="#benchmarks">Benchmarks</a> &bull;
  <a href="#api">API</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/speed-splice%20zero--copy-brightgreen" alt="speed">
  <img src="https://img.shields.io/badge/fingerprint-p0f%20verified-blue" alt="fingerprint">
  <img src="https://img.shields.io/badge/kernel-DKMS%20hot--loadable-orange" alt="kernel">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license">
</p>

---

## Features

- **High-performance** — splice-based zero-copy data relay, multi-worker threading
- **TCP/IP fingerprint spoofing** — per-user OS fingerprint profiles via DKMS kernel module
- **p0f signature support** — configure fingerprints using standard p0f v3 signature strings
- **Dynamic fingerprinting** — encode fingerprint in SOCKS5 password field at runtime
- **Session-persistent** — fingerprint applies to entire TCP session, not just SYN
- **Hot-loadable** — `git clone && make && run`, kernel module auto-builds and loads
- **Zero impact** — only proxy connections are modified, all other system TCP traffic untouched
- IPv4/IPv6 dual stack
- Standard `CONNECT` and `UDP ASSOCIATE` commands
- Extended `FWD UDP` command (UDP in TCP)
- Multiple username/password authentication

## Quick Start

```bash
git clone --recursive https://github.com/Muno459/hev-socks5-server
cd hev-socks5-server
make          # builds binary + kernel module + loads it
```

Edit `conf/auth.json` with your fingerprint profiles, then:

```bash
./bin/hev-socks5-server conf/main.yml
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

The kernel module uses **ftrace function redirection** and **kprobe struct injection** to make the Linux TCP stack natively emit packets matching any target OS fingerprint. No packet rewriting — the kernel builds correct packets from the start.

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

### Auth file format

`conf/auth.json`:

```json
[
  { "username": "user1", "password": "pass" },

  { "username": "win10", "password": "pass",
    "p0f": "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0" },

  { "username": "linux6", "password": "pass",
    "p0f": "4:64:0:1460:mss*20,7:mss,sok,ts,nop,ws:df:0" },

  { "username": "macos", "password": "pass",
    "p0f": "4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0" },

  { "username": "winxp", "password": "pass",
    "p0f": "4:128:0:1460:65535,0:mss,nop,nop,sok:df,id+:0" }
]
```

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

### Dynamic fingerprinting via password

Set a wildcard user with `(*)` in the password:

```json
[
  { "username": "fp", "password": "secret(*)" }
]
```

The client encodes the p0f signature in the password:

```bash
# Password format: secret(<p0f signature>)
curl -x socks5h://fp:secret(4.128.0.1460.65535,8.mss,nop,ws,nop,nop,sok.df,id+.0)@server:1080 http://target
```

Note: dots (`.`) replace colons (`:`) in the password encoding.

### Verified OS profiles

All profiles verified at **p0f distance 0** (exact match):

| Profile | p0f Detection | Signature |
|---------|--------------|-----------|
| Windows 10/11 | `Windows NT kernel 5.x` | `4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0` |
| Linux 3.11+ | `Linux 3.11 and newer` | `4:64:0:1460:mss*20,7:mss,sok,ts,nop,ws:df:0` |
| Windows XP | `Windows XP` | `4:128:0:1460:65535,0:mss,nop,nop,sok:df,id+:0` |

## Architecture

```
                          SOCKS5 Client
                               |
                    +-----------------------+
                    |   hev-socks5-server   |
                    |  (userspace proxy)    |
                    +-----------+-----------+
                                |
                    setsockopt (TTL, MSS, DF, window)
                    ioctl /dev/hev-tcpfp (cookie + fingerprint)
                                |
                    +-----------+-----------+
                    |   hev-tcpfp.ko        |
                    |   (kernel module)     |
                    |                       |
                    |  ftrace redirect:     |
                    |    tcp_options_write   |
                    |                       |
                    |  kprobe injection:    |
                    |    tcp_connect (ISN)   |
                    |    tcp_connect_init    |
                    |    tcp_syn_options     |
                    |    tcp_retransmit_timer|
                    |                       |
                    |  netfilter (IP only): |
                    |    IP ID behavior     |
                    +-----------+-----------+
                                |
                          TCP/IP Stack
                      (builds correct packets)
                                |
                            Network
```

## Config

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
  # pid-file: /run/hev-socks5-server.pid
  # limit-nofile: 65535
```

### Authentication file

Supports both plaintext and JSON formats:

**Plaintext** (`conf/auth.txt`):
```
username password [mark] [source_ip] [interface]
```

**JSON** (`conf/auth.json`):
```json
[
  { "username": "tom", "password": "pass" },
  { "username": "jerry", "password": "pass", "mark": "0x1a" },
  { "username": "alice", "password": "pass", "iface": "wlan0" },
  { "username": "win10", "password": "pass",
    "p0f": "4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0~rto=w" }
]
```

Reload auth without restart:
```bash
killall -SIGUSR1 hev-socks5-server
```

## Benchmarks

See [benchmarks](https://github.com/heiher/hev-socks5-server/wiki/Benchmarks) for full details.

The proxy uses splice-based zero-copy for data relay — fingerprint spoofing adds zero overhead to data transfer. The kernel module only operates on connection setup (SYN) and per-packet timestamp scaling.

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

## Use Cases

### Android App
* [Socks5](https://github.com/heiher/socks5)

### iOS App
* [Socks5](https://github.com/heiher/socks5-ios)

## Contributors

* **hev** - https://hev.cc
* **ammar faizi** - https://github.com/ammarfaizi2
* **pexcn** - <i@pexcn.me>

## License

MIT
