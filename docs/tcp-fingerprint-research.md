# TCP/IP OS Fingerprint Research: Real-World Device Analysis

**Date:** March 29, 2026
**Researcher:** Muno459
**Methodology:** Passive SYN capture + active retransmission analysis against controlled blackhole endpoints
**Devices tested:** Windows 11 (Chrome), macOS Tahoe (Safari), iOS 26 (Safari, raw + iCloud Private Relay), Android 16 / Pixel 9 XL (Chrome), Linux 6.8 Ubuntu 24.04

---

## 1. Passive Fingerprinting (SYN Analysis)

Each device connected to an HTTP listener on a controlled VPS. SYN packets were captured and analyzed using p0f v3.09b and raw tcpdump.

### 1.1 Windows 11 (Chrome 146)

```
raw_sig  = 4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0
```

| Field | Value | Notes |
|-------|-------|-------|
| IP version | 4 | |
| TTL | 128 | Classic Windows identifier |
| IP options length | 0 | |
| MSS | 1460 | Standard Ethernet |
| Window | 65535 | Maximum unscaled |
| Window scale | 8 (256x) | Effective window: 16MB |
| Option order | MSS, NOP, WS, NOP, NOP, SACK_PERM | Unique Windows ordering |
| DF | yes | |
| IP ID | non-zero incremental (`id+`) | Per-connection counter |
| ECN | no | |
| Timestamps | no | Windows never sends TS |
| Payload class | 0 | |

**Key observations:**
- Windows has the most distinctive passive fingerprint of any major OS. No timestamps, unique option ordering (NOP between MSS and WS, double NOP before SACK), and TTL 128 make it trivially identifiable.
- The `id+` quirk (non-zero IP ID despite DF) is a Windows-specific behavior. Linux zeros the IP ID when DF is set as a privacy measure.
- Window scale 8 is aggressive - Windows allocates a 16MB receive window, reflecting its assumption of high-bandwidth links.

### 1.2 macOS Tahoe (Safari & Chrome)

```
raw_sig  = 4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
```

| Field | Value | Notes |
|-------|-------|-------|
| TTL | 64 | Unix-family default |
| MSS | 1460 | Standard Ethernet |
| Window | 65535 | Maximum unscaled |
| Window scale | 6 (64x) | Effective window: 4MB |
| Option order | MSS, NOP, WS, NOP, NOP, TS, SACK_PERM, EOL | Darwin-specific |
| DF | yes | |
| IP ID | zero (DF set) | Standard Unix behavior |
| ECN | **yes** | macOS enables ECN by default |
| Timestamps | yes | |
| EOL padding | +1 byte | 1 byte of padding after options |
| TS clock | 1000 Hz | Measured directly from TS val deltas |

**Key observations:**
- macOS enables **ECN (Explicit Congestion Notification)** by default. This is visible in the SYN flags (`SEW` = SYN + ECE + CWR). Very few operating systems do this - it's a strong Darwin identifier.
- The `eol+1` (1 byte of trailing padding) is unique to Darwin. Linux pads to 32-bit alignment differently.
- The option order places timestamps AFTER window scale, unlike Linux which puts timestamps first. This ordering is hardcoded in the XNU kernel's `tcp_output.c`.
- Window scale 6 (64x) is more conservative than Windows (256x) or Linux (128x).
- Both Safari and Chrome on macOS produce identical TCP fingerprints. The TCP stack is an OS-level property, not a browser-level one. Browser choice is only visible in HTTP headers.

### 1.3 iOS 26 (iPhone, Safari, raw connection)

```
raw_sig  = 4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0
```

**Identical TCP fingerprint to macOS.** This is expected - iOS and macOS share the same XNU/Darwin kernel. The TCP stack is the same code compiled for different architectures (ARM vs x86). From a network fingerprinting perspective, iOS and macOS are indistinguishable at the TCP layer.

Differentiation requires HTTP-layer analysis:
- **User-Agent**: `iPhone; CPU iPhone OS 26` vs `Macintosh; Intel Mac OS X`
- **HTTP header ordering**: Safari on iOS uses a different header order than Safari on macOS (Priority header position differs)

### 1.4 iCloud Private Relay

```
raw_sig  = 4:64:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
```

| Field | Value | Notes |
|-------|-------|-------|
| TTL | 64 | |
| Window | mss*44 (64240) | Standard Linux auto-tuned |
| Window scale | 7 (128x) | |
| Option order | MSS, SACK_PERM, TS, NOP, WS | Standard Linux ordering |
| ECN | no | Unlike the iOS device behind it |
| IP ID | non-zero (`id+`) | |

**Key observations:**
- iCloud Private Relay **completely strips the iOS TCP fingerprint**. The relay terminates the TCP connection at a Cloudflare edge server running Linux, then opens a new connection to the destination. The destination sees a standard Linux fingerprint, not iOS.
- This is a significant privacy feature - it defeats TCP-layer OS fingerprinting entirely.
- The `id+` quirk (non-zero IP ID with DF) suggests Cloudflare's Linux kernel has a custom configuration or older kernel behavior. Modern Linux (5.x+) zeros the IP ID when DF is set.
- ECN is notably absent, even though the originating iOS device sends ECN. The relay does not propagate ECN negotiation.

### 1.5 Android 16 / Pixel 9 XL (Chrome)

```
raw_sig  = 4:64:0:1460:mss*44,7:mss,sok,ts,nop,ws:df,id+:0
```

**Identical to iCloud Private Relay and standard Linux.** Android uses the Linux kernel, so its TCP stack produces a standard Linux fingerprint. 

There is no way to distinguish Android from desktop Linux or any Linux-based infrastructure at the TCP layer.

### 1.6 Linux 6.8 (Ubuntu 24.04, VPS)

```
raw_sig  = 4:64:0:65495:mss*1,7:mss,sok,ts,nop,ws:df,id+:0
```

Standard Linux fingerprint. The loopback MSS of 65495 (MTU 65535) is a loopback artifact. On a real NIC with MTU 1500, this becomes `1460:mss*44,7`.

---

## 2. Active Fingerprinting (Retransmission Analysis)

To capture retransmission behavior, each device connected to a blackhole port where the server's SYN-ACK was silently dropped by an iptables rule. This forced each device to retransmit SYN packets according to its OS-specific retransmission timer, revealing the complete RTO (Retransmission Timeout) pattern.

### 2.1 Windows 11

```
RTO:     1.00s → 2.00s → 4.00s → 8.00s
Pattern: Pure exponential doubling from 1s
Retransmits: 4
Total duration: ~15s
Options: Stable (never change)
```

**Analysis:**
- Windows uses a simple exponential backoff with no linear phase.
- Only 4 retransmits before giving up - the most aggressive timeout of any tested platform.
- TCP options remain identical across all retransmits. Windows never strips or modifies options during retransmission.
- The initial RTO of 1 second matches RFC 6298.

### 2.2 macOS Tahoe (Safari & Chrome)

```
RTO:     1s → 1s → 1s → 1s → 1s → 2s → 4s → 8s → 16s → 32s
Pattern: 5 linear at 1s, then exponential doubling
Retransmits: 10
Total duration: ~67s
Options: Strip on final SYN (#11) → mss,sackOK,eol (removes WS, TS, NOPs)
ECN: First SYN only (SEW flags)
```

**Analysis:**
- macOS uses the same linear-then-exponential pattern as Linux (`tcp_syn_linear_timeouts = 4` gives 5 linear retransmits). This makes sense given XNU's BSD heritage and modern TCP RFCs.
- The **option stripping on the final SYN** is a significant active fingerprinting signal. After 10 failed retransmits, macOS sends one last SYN with reduced options (`mss,sackOK,eol` only - no window scale, no timestamps). This is a compatibility fallback: if the connection is failing because a middlebox doesn't understand modern TCP options, the stripped SYN might succeed.
- ECN flags (`SEW`) appear only on the first SYN. Retransmits drop the ECE/CWR flags, which is standard ECN behavior (RFC 3168 section 6.1.1).
- The consistency across 8 separate flows (all showing the same pattern within ±50ms) confirms this is a deterministic kernel behavior, not application-level retry logic.

### 2.3 iOS 26 (iPhone)

```
RTO:     60ms → 60ms → 60ms → 60ms → 60ms → 120ms → 230ms → 460ms → 920ms → 1830ms → 3650ms → 3650ms
Pattern: 5 at 60ms, then exponential doubling, caps at ~3.65s
Retransmits: 12
Total duration: ~11.2s
Options: Strip on SYN #11 → mss,sackOK,eol (same as macOS)
ECN: First SYN only
TS clock: 1000 Hz (confirmed: exactly 60 TS ticks between 60ms retransmits)
```

**Analysis:**
- iOS has a **radically different retransmission strategy** from macOS, despite sharing the same XNU kernel. The initial RTO is 60ms - 16.7x faster than the RFC 6298 recommended 1 second. This is confirmed by the TS val deltas: exactly 60 ticks at 1000 Hz = 60ms.
- This aggressive behavior is likely an optimization for mobile networks where latency is often the limiting factor. By retransmitting quickly, iOS can establish connections faster on cellular networks where packets are frequently lost.
- The 5-linear-then-exponential pattern is the same structure as macOS and Linux, just with different base timing. The exponential phase doubles from 60ms (120 → 230 → 460 → 920 → 1830 → 3650).
- The **cap at 3.65s** (two consecutive 3650ms retransmits) is unique to iOS. macOS and Linux continue doubling up to 32s and beyond.
- The option stripping on SYN #11 (identical to macOS) confirms shared XNU code for the compatibility fallback.
- Total connection attempt duration is only 11.2 seconds - iOS gives up much faster than any other platform.

**This is a strong active fingerprinting signal.** No other OS retransmits at 60ms intervals. A network observer who sees 5 SYN packets 60ms apart can confidently identify iOS,.

### 2.4 Android / Pixel 9 XL

```
RTO:     1.02s → 2.01s → 4.07s → 8.19s → 16.13s
Pattern: Pure exponential doubling from 1s
Retransmits: 5
Total duration: ~31s
Options: Stable (never change)
TS clock: 1000 Hz
```

**Analysis:**
- Standard Linux exponential backoff. The `tcp_syn_linear_timeouts` sysctl was likely 0 on this kernel (no linear phase, unlike the VPS).
- Options remain stable - Linux does not implement the option stripping fallback that Darwin uses.
- 5 retransmits is the default `tcp_syn_retries` value.

### 2.5 Linux 6.8 (VPS)

```
RTO:     1.03s → 1.02s → 1.02s → 1.02s → 1.02s → 2.05s → 4.03s → 8.19s → 16.38s → 32.26s
Pattern: 5 linear at 1s, then exponential doubling
Retransmits: 10 (tcp_syn_retries = 6 + linear adds)
Total duration: ~68s
Options: Stable (never change)
TS clock: 1000 Hz
```

**Analysis:**
- This VPS runs kernel 6.8 with `tcp_syn_linear_timeouts = 4`, producing 5 linear retransmits at 1s followed by exponential doubling. This matches the macOS pattern exactly.
- Unlike macOS, Linux never strips options during retransmission.
- The slight overshoot in later retransmits (8.19s instead of 8.00s, 16.38s instead of 16.00s) is due to kernel timer granularity and scheduling latency. Earlier retransmits are more precise because the system is less loaded.

### 2.6 iCloud Private Relay (Cloudflare)

```
RTO:     1.00s → 1.02s → 1.02s → 1.02s → 1.03s → 2.05s → 4.03s
Pattern: 5 linear at 1s, then exponential (gives up after 4s retransmit)
Retransmits: 7
Total duration: ~11.2s
Options: Stable (never change)
TS clock: 1000 Hz
```

**Analysis:**
- Uses the same linear-then-exponential pattern as standard Linux, but **gives up much earlier** - after only 7 retransmits (11.2 seconds) vs 10 retransmits (68 seconds) for standard Linux.
- This early termination is likely a Cloudflare configuration: `tcp_syn_retries` set lower to free up resources quickly. Edge servers handle millions of connections and can't afford to wait 68 seconds per failed outbound connection.
- The early give-up behavior distinguishes Cloudflare's Linux from standard Linux deployments.

---

## 3. Comparative Analysis

### 3.1 RTO Pattern Taxonomy

The tested platforms fall into four distinct retransmission families:

| Family | Pattern | Members |
|--------|---------|---------|
| **Windows** | `1-2-4-8` (pure exponential, 4 retransmits) | Windows 11 |
| **Linux standard** | `1-1-1-1-1-2-4-8-16-32` (5 linear + exponential) | Linux 6.8, macOS, iCloud Relay |
| **iOS aggressive** | `60ms×5, then doubling, cap 3.65s` | iOS 26 |
| **Linux minimal** | `1-2-4-8-16` (pure exponential, 5 retransmits) | Android (Pixel 9 XL) |

The Linux standard and macOS patterns are identical in timing, differing only in whether options are stripped on the final attempt. This reflects their shared BSD/POSIX heritage and adherence to the same TCP RFCs.

### 3.2 Option Mutation During Retransmission

Only Darwin-based systems (macOS + iOS) modify TCP options during SYN retransmission:

| Platform | Behavior | Final SYN options |
|----------|----------|-------------------|
| Windows 11 | Stable | Same as initial |
| macOS | Strips on #11 | `mss,sackOK,eol` |
| iOS | Strips on #11 | `mss,sackOK,eol` |
| Android | Stable | Same as initial |
| Linux | Stable | Same as initial |

This option stripping is a compatibility mechanism. If a middlebox (firewall, NAT, load balancer) is dropping connections because it doesn't understand window scaling or timestamps, the stripped SYN with only MSS and SACK might succeed. This behavior is unique to XNU and can be used to identify Apple devices even when other fingerprint parameters are masked.

### 3.3 ECN Deployment

Only Apple devices enable ECN by default:

| Platform | ECN in SYN |
|----------|-----------|
| macOS | Yes (SEW flags) |
| iOS | Yes (SEW flags) |
| Windows 11 | No |
| Android | No |
| Linux 6.8 | No |
| iCloud Relay | No |

Apple has shipped ECN-enabled by default since macOS 10.11 and iOS 9 (2015). This is a strong OS family identifier. Note that iCloud Private Relay does NOT propagate ECN - the relay server (Cloudflare Linux) establishes a new connection without ECN.

### 3.4 Privacy Implications

**iCloud Private Relay is effective at hiding TCP fingerprints.** The relay completely replaces the iOS TCP personality with a standard Linux signature. However:

- The relay's Linux signature has a distinctive short timeout (7 retransmits, 11.2s) that could identify it as a Cloudflare edge server.
- Multiple connections from the same relay IP with identical `mss*44,7` signatures could be correlated.
- The HTTP User-Agent still reveals `iPhone; CPU iPhone OS 26`, defeating the TCP-layer privacy. Apple could improve this by also masking the UA in Private Relay.


### 3.5 Fingerprint Durability

Some fingerprint signals are more resistant to masking than others:

| Signal | Survives iCloud Relay? | Spoofed by SkyProxy? |
|--------|----------------------|-------------------|
| TCP option order | No | Yes (ftrace) |
| TTL | Replaced | Yes (setsockopt) |
| Window/WScale | Replaced | Yes (struct injection) |
| ECN | No | Not yet |
| Timestamps | Replaced | Yes (kretprobe) |
| TS clock rate | Replaced | Yes (ftrace) |
| RTO pattern | No | Yes (kprobe) |
| IP ID behavior | Replaced | Yes (netfilter) |
| Option stripping | No | Not yet |

---

## 4. Minimal-Packet OS Identification

A key finding of this research is how few packets are needed to identify the remote operating system with high confidence.

### 4.1 One packet (initial SYN)

The initial SYN alone contains enough signals to identify the OS family:

```
                            Incoming SYN
                                 |
                    +------------+------------+
                    |                         |
              TTL = 128?                 TTL = 64?
                    |                         |
              [WINDOWS]              ECN flags set?
                                     (SEW in SYN)
                                    /            \
                                  Yes             No
                                   |               |
                              [DARWIN]          [LINUX]
                           (macOS / iOS)    (Linux / Android)
```

Each family has multiple confirming signals in the same packet:

| Signal | Windows | Darwin (macOS/iOS) | Linux (Android) |
|--------|---------|-------------------|-----------------|
| TTL | 128 | 64 | 64 |
| Timestamps | Absent | Present | Present |
| ECN (SEW flags) | No | **Yes** | No |
| Option order | mss,nop,ws,nop,nop,sok | mss,nop,ws,nop,nop,ts,sok,eol+1 | mss,sok,ts,nop,ws |
| eol+1 padding | No | **Yes** | No |
| Window scale | 8 | 6 | 7 |
| Window size | 65535 | 65535 | mss*44 |
| IP ID with DF | Non-zero (id+) | Zero | Zero |

Any single row is enough to separate the families. Combined, they provide redundant confirmation. A firewall, WAF, or IDS only needs to inspect one SYN packet to classify the OS family with near-certainty.

### 4.2 Two packets (SYN + first retransmit)

The first retransmit separates operating systems within families:

```
                         OS family known
                         from initial SYN
                              |
               +--------------+--------------+
               |              |              |
          [DARWIN]        [LINUX]        [WINDOWS]
               |              |              |
        First retransmit  First retransmit   (already
        delta?            delta?              identified)
          /      \          /      \
      ~60ms     ~1s      ~1s      ~2s
        |        |        |        |
     [iOS]   [macOS]  [Linux*]  [Android**]
```

\* Linux with `tcp_syn_linear_timeouts >= 1` (default on kernel 6.1+)
\*\* Android or Linux with `tcp_syn_linear_timeouts = 0`

At this point, with just 2 packets (initial SYN + first retransmit), an observer can identify:
- **Windows 11** - 100% confidence from SYN alone
- **iOS** - 100% confidence (60ms retransmit is unique across all tested platforms)
- **macOS** - high confidence (1s retransmit + Darwin SYN features)
- **Android vs Linux** - requires additional retransmits to differentiate (both use ~1s or ~2s)

### 4.3 Three packets and beyond (confirmation signals)

Additional retransmits provide confirming evidence and separate ambiguous cases:

| Packet | What it reveals |
|--------|----------------|
| SYN #1 | OS family (Windows / Darwin / Linux) |
| SYN #2 | iOS vs macOS (60ms vs 1s). Android vs standard Linux (2s vs 1s) |
| SYN #3 | Confirms exponential vs linear pattern. Windows 1-2-**4** vs Android 1-2-**4** (same, need other signals) |
| SYN #6 | Linux/macOS transition from linear to exponential (1s phase ends, 2s begins) |
| SYN #11 | Darwin option stripping (mss,sackOK,eol). Linux never strips. Definitive Darwin confirmation |
| SYN #12-13 | iOS RTO cap at 3.65s (two consecutive). macOS continues doubling to 32s |

### 4.4 Combined identification matrix

For a network observer collecting the initial SYN plus retransmits:

| Packets needed | Confidence | Can identify |
|---------------|------------|-------------|
| 1 (SYN only) | ~95% | Windows vs Darwin vs Linux family |
| 2 (+ 1 retransmit) | ~99% | iOS specifically (60ms is unique) |
| 3 (+ 2 retransmits) | ~99% | macOS vs Linux (linear vs exponential) |
| 6 (+ 5 retransmits) | 100% | All platforms including Android vs Linux |
| 11 (+ 10 retransmits) | 100% | Darwin confirmed by option stripping |

### 4.5 Defensive implications

This analysis shows that TCP-layer OS fingerprinting is extremely efficient. A passive network observer, middlebox, WAF, or CDN can identify the connecting OS with high confidence from minimal traffic. This has implications for:

- **Anti-bot systems** that verify the claimed User-Agent matches the TCP fingerprint. A bot claiming to be Chrome on Windows but showing Linux TCP characteristics will be flagged.
- **Fraud detection** where the TCP fingerprint of a connection is compared against the expected device type for a user account.
- **Access control** where certain OS types are blocked or rate-limited based on TCP fingerprint.
- **Privacy** where TCP fingerprinting can track users across IP address changes, since the OS fingerprint is stable and not affected by cookies, browser settings, or IP rotation.

The only effective countermeasure is to spoof the TCP fingerprint at the kernel level, which is what SkyProxy implements.

---

## 5. Implications for SkyProxy

These findings inform the fingerprint profiles that SkyProxy needs to support:

### 5.1 Passive fingerprint profiles (p0f signatures)

```
# Windows 11
4:128:0:1460:65535,8:mss,nop,ws,nop,nop,sok:df,id+:0

# macOS / iOS (Darwin)
4:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol+1:df,ecn:0

# Linux / Android
4:64:0:1460:mss*44,7:mss,sok,ts,nop,ws:df:0
```

### 5.2 Active fingerprint profiles

```
# Windows 11:  rto=1000-2000-4000-8000  (4 retransmits, no option strip)
# macOS:       rto=1000-1000-1000-1000-1000-2000-4000-8000-16000-32000  (strip on #11)
# iOS:         rto=60-60-60-60-60-120-230-460-920-1830-3650-3650  (strip on #11)
# Linux:       rto=1000-1000-1000-1000-1000-2000-4000-8000-16000-32000  (no strip)
# Android:     rto=1000-2000-4000-8000-16000  (no strip)
```

### 5.3 Features not yet spoofed

The following active fingerprint behaviors are observed but not yet implemented in SkyProxy:

1. **ECN negotiation** - macOS/iOS set ECE+CWR on initial SYN. SkyProxy does not yet spoof ECN flags.
2. **Option stripping on final retransmit** - Darwin strips options after 10 retransmits. SkyProxy retransmits with stable options.
3. **iOS 60ms initial RTO** - Linux kernel minimum timer resolution makes sub-100ms RTO difficult to achieve precisely.
4. **RTO cap** - iOS caps at 3.65s. SkyProxy's exponential doubling continues without cap.
5. **`eol+1` padding** - Darwin's 1-byte trailing padding after options. SkyProxy handles this via byte-level option writing.
6. **Per-retransmit ECN flag removal** - Darwin drops ECE/CWR after first SYN.

---

## 6. Methodology Notes

### 6.1 Passive capture setup

- HTTP listener on VPS port 8888 (Python socket server)
- p0f v3.09b on the network interface
- Devices connected via browser (Safari/Chrome)

### 6.2 Active capture setup

- Per-platform blackhole ports (8891-8894)
- iptables rule: `OUTPUT -p tcp --sport <port> --tcp-flags SYN,ACK SYN,ACK -j DROP`
- Server TCP stack sends SYN-ACK (kernel accepts connection) but the SYN-ACK is silently dropped before reaching the wire
- Client sees no response and retransmits SYN according to its RTO algorithm
- Full retransmission pattern captured until client gives up

### 6.3 Timestamp clock measurement

p0f's `raw_freq` field is unreliable - it estimates clock rate from `tsval / estimated_uptime`, which introduces large errors. Direct measurement from consecutive packet TS val deltas over known wall-clock intervals gives precise results.

All tested platforms with timestamps use **1000 Hz** TS clocks:
- macOS: 1002.2 Hz (measured over 34.9s)
- iOS: 998.3 Hz (measured over 2.0s)
- Linux 6.8: 1000.0 Hz
- Android: 1000.0 Hz
- iCloud Relay: 1000.0 Hz

---

*Research conducted as part of the SkyProxy project for authorized security testing purposes.*
