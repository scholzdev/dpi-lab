# dpi-lab: A Minimal DPI Pipeline for Studying Censorship-Grade Traffic Interference

## Abstract

This project implements, at small scale, the core mechanisms documented in
research on the Great Firewall of China (GFW) and similar national-scale DPI
systems: passive payload/metadata classification (keyword, TLS SNI, JA3 client
fingerprinting), active connection reset (RST) injection, DNS response
spoofing, entropy-based detection of protocols designed to evade signature
matching, active probing to confirm a suspected protocol before acting on it,
Great-Cannon-style HTTP response injection between two owned hosts, adaptive
IP-reputation blocking with automatic expiry, and (Linux only) genuine
in-path enforcement via NFQUEUE - the one mechanism here that can guarantee
a block rather than race for one. The goal
is not to replicate GFW's scale or deployment model, but to build and
empirically verify each mechanism in isolation, against traffic I fully
control, as a concrete demonstration of understanding for network security
and penetration testing work.

## 1. Threat model / what this is and isn't

**What it is:** a single-host, on-path-capture DPI implementation that can
observe traffic (IPv4 and IPv6) crossing one network interface, classify flows
by payload content (keyword, TLS SNI, DNS query name), by TLS client
fingerprint (JA3), or by statistical shape (Shannon entropy of the first
segment), and - only when explicitly enabled - forge TCP RST packets or
spoofed DNS responses to interfere with a matched connection, replicating
techniques described by Clayton, Murdoch & Watson (2006) and later GFW
measurement work. Repeated offenses from one source IP within a time window
trigger auto-escalation to a hard, TTL-bounded IP block, loosely modeling the
GFW's reputation-list behavior. Separately, local bandwidth throttling
(macOS `pfctl`/`dnctl`) is the one mechanism here that's genuinely inline
rather than off-path spoofing, since it's the only one that modifies state
this machine is itself authoritative over.

**What it explicitly is not:** a deployable censorship system. It has no
notion of network-wide chokepoint deployment, no rule-distribution mechanism,
and - critically - every test in this write-up was run against traffic I
generated myself, between endpoints I own (a lab VM pair, my Raspberry Pi at
`10.27.0.10`, and my own domain `florianscholz.dev`). RST injection
(`--inject`), DNS redirect (`--redirect-dns`), throttling, active probing,
and response injection are all opt-in and off by default; none were ever run
against third-party traffic. Active probing (§3.8) - connecting out to a
suspected circumvention server to confirm before acting - is implemented
strictly against an explicit allow-list of hosts I own
(`config/probe_targets.yml`); it never fires against the arbitrary flagged
destination itself. Great-Cannon-style response injection (§3.9) - the real
technique substitutes malicious content into a plaintext response, weaponizing
the requester against an unrelated third party (the 2015 GitHub DDoS is the
documented case) - is implemented here too, but only between two hosts on
`config/cannon.yml`'s allow-list, with an inert payload (a marker string
and/or a redirect to another owned host). What stays out of scope is the part
of the real technique that can't be reduced to "own lab only" at all: pointing
the injected content at a genuine third-party target. That's not a config
knob here, it's simply not built - there's no code path that takes an
attack-target argument.

**Real-world chokepoint requirement.** A production deployment needs to sit at
a point *all* target traffic transits - for the GFW, that's the national
border routers; for a home network, it would be the gateway/router, not each
client's own interface. Running per-device (as this project does, on a
laptop's own NIC) only affects that device's own traffic - this distinction
came up directly during testing and is worth stating precisely rather than
hand-waving "runs on every interface."

**Off-path vs. inline, and why it matters for what each mechanism can do.**
Everything except throttling here is off-path: it can only forge *additional*
packets that race the real traffic, never drop or delay the real packets
themselves. That's sufficient for RST injection and DNS spoofing (the forged
packet just needs to arrive first) but fundamentally cannot implement
bandwidth throttling - there's no packet to forge that makes a real TCP
stream slower. Throttling instead modifies this machine's own kernel traffic
shaping (`pfctl`/`dnctl` dummynet pipes), which only works because the local
kernel is authoritative over its own interface; a GFW-scale deployment would
need to be genuinely inline (a border router) to do the same thing to
someone else's traffic.

## 2. Architecture

```
   packets in (pnet::datalink, live capture, IPv4 + IPv6)
          │
          ▼
   ┌─────────────┐
   │  Eth/IP/TCP/ │   src/main.rs - decode Ethernet, dispatch v4/v6
   │  UDP decode  │
   └──────┬───────┘
          ▼
   ┌─────────────┐
   │ reassembly   │   src/reassembly.rs - per-flow TCP stream reassembly,
   │              │   anchored on the SYN's ISN (see §4.1 for why that
   │              │   distinction matters)
   └──────┬───────┘
          ▼
   ┌─────────────┐
   │  classify    │   src/classify.rs - Aho-Corasick keyword match,
   │              │   TLS ClientHello SNI + JA3 fingerprint, DNS query parsing
   └──────┬───────┘
          ▼
   ┌─────────────┐
   │  detect      │   src/detect.rs - Shannon entropy on first segment,
   │              │   flags high-entropy non-TLS as possible obfuscated proxy
   └──────┬───────┘
          ▼
   ┌─────────────┐    ┌───────────────┐    ┌────────────────┐
   │  inject      │    │  redirect     │    │  throttle       │
   │ (opt-in, RST)│    │ (opt-in, DNS  │    │ (opt-in, local  │
   │              │    │  A/AAAA spoof)│    │  pfctl/dnctl)   │
   └──────┬───────┘    └───────────────┘    └────────────────┘
          ▼
   ┌─────────────┐    ┌───────────────┐
   │  probe       │    │  escalate     │   src/probe.rs - on a [detect] hit,
   │ (allow-list  │    │               │   confirm via known-protocol handshake
   │  only)       │    │               │   before trusting the heuristic;
   └──────────────┘    │               │   src/engine.rs - repeated offenders
                        │               │   auto-promote to a TTL-bounded IP
                        │               │   block, persisted
                        └───────────────┘
```

All of the above is orchestrated per-packet by `Engine::handle_frame_v4`/`_v6`
in `src/engine.rs`, which owns per-flow state (`HashMap<FlowKey, FlowState>`),
the injection/redirect channels, and the escalation/block-list state. Block
lists (SNI, JA3, IP, signatures) and the DNS redirect map are loaded from
`config/*.yml` at startup rather than hardcoded, so adding a rule is a text
edit, not a rebuild; CLI flags (`--block-sni`, `--block-ja3`, `--block-ip`,
`--block-sig`) add to whatever's already in those files.

## 3. Design rationale, mechanism by mechanism

### 3.1 Passive classification (keyword, SNI, DNS)

The GFW's earliest and still-active technique is plaintext substring matching
on packet payloads - the classic keyword filter. This project implements the
same idea with Aho-Corasick multi-pattern matching (`classify::Signatures`)
rather than a naive per-pattern scan, which is the standard choice for
production-grade multi-signature matching (Suricata uses the same algorithm
family). Signatures are scanned against the *reassembled* stream (with a
small re-scan overlap at the previous scan boundary), not each raw packet in
isolation - an early version missed keywords split across a TCP segment
boundary, the same fragmentation problem described for SNI parsing below.

Because most traffic today is TLS, payload-content matching alone is largely
obsolete - but the TLS ClientHello's Server Name Indication (SNI) extension is
sent **in plaintext** before encryption is established, and the GFW is
documented to filter on it directly. `classify::parse_client_hello` hand-parses
the ClientHello structure (record header → handshake header → extensions →
`server_name` extension) to extract the requested hostname without needing a
full TLS library. ClientHellos routinely span multiple TCP segments in modern
browsers (GREASE, ALPS, key-share, ECH padding) - the parser retries against
the growing reassembled buffer as more segments arrive rather than giving up
after the first packet, up to a capped byte budget before falling back to
entropy classification. Likewise, DNS queries are still sent in plaintext
over UDP/53 by default, and `classify::parse_dns_query_full` extracts the
queried domain from the question section - notably, this also recovers the
domain from **DNS responses**, since a response echoes its question section.

### 3.2 JA3 TLS client fingerprinting

SNI filtering only sees the *destination* the client claims to want; it says
nothing about *what kind of client* is talking. JA3 (as used operationally by
several real DPI/threat-intel systems) fingerprints the TLS stack itself -
`classify::ja3` builds the canonical `version,ciphers,extensions,curves,
ec_point_formats` string from the ClientHello and MD5-hashes it, with GREASE
values (RFC 8701 - reserved cipher/extension/group codepoints browsers send
specifically to prevent ossification of TLS parsers) stripped before hashing,
per the standard JA3 spec. This lets a rule match "this is curl" or "this is
a specific circumvention tool's TLS stack" independent of which domain it's
talking to, and complements SNI/keyword matching rather than replacing it -
a client can rotate domains but its TLS library's fingerprint changes far
less often.

**A real-world blind spot, found during testing.** Encrypted Client Hello
(ECH) - live and enabled by default in Safari against ECH-supporting origins
during this project's testing - encrypts the *entire* inner ClientHello
(including SNI) inside an outer, mostly-fixed ClientHello. Both SNI
extraction and JA3 fingerprinting of the real client operate on the outer,
ECH-obscuring ClientHello and lose the information they're trying to extract.
This is not a bug in this project's parser; it's the documented purpose of
ECH, and it's exactly the kind of blind spot real DPI/censorship systems are
currently contending with - worth stating precisely rather than glossing over,
since it directly bears on how much SNI/JA3-based filtering can still see in
practice.

### 3.3 Active interference (RST injection)

Rather than sitting inline and dropping packets, the GFW is documented (again,
Clayton et al. 2006) to inject forged TCP RST packets to both connection
endpoints on a match - an off-path technique that requires no interception
capability, only the ability to see traffic and spoof a source address.
`inject::build_rst` constructs a correctly-checksummed IPv4/TCP RST using
pnet's own checksum routines (rather than hand-rolled arithmetic, to avoid
subtle correctness bugs in a security-sensitive packet-construction path), and
`inject::reset_flow` sends one to each endpoint: one spoofed as the client with
`seq = client's next unsent sequence number`, one spoofed as the server with
`seq =` the ACK value observed in the triggering packet (a value the real
client has already accepted as valid, so it falls inside its receive window).

### 3.4 DNS response spoofing

The GFW is also documented to inject forged DNS *responses* - racing the real
resolver's answer with a spoofed one pointing the client somewhere else
entirely, rather than merely resetting the connection. `redirect::build_dns_response`
constructs a spoofed A (IPv4) or, where the platform allows it, AAAA (IPv6)
response for a query matching an entry in `config/redirect.yml` (original
domain → target hostname, resolved to a real IP once at startup, not
hardcoded, since real IPs change). IPv6 spoofing needed a second, separate raw
socket path (`redirect::Ipv6DnsSender`) - a **real platform constraint**
turned up here, not assumed: macOS's libc bindings genuinely lack
`IPV6_HDRINCL` (confirmed by grepping the actual Darwin libc source, not
inferred from a "probably not implemented" guess), so full custom IPv6 header
construction the way IPv4's `IP_HDRINCL` allows isn't available on this
platform. `Ipv6DnsSender` is Linux-only in its working form; on macOS it
reports this limitation explicitly at startup (`[redirect-v6] disabled: ...`)
rather than silently doing nothing, which matters for a tool whose entire
premise is that its behavior should be legible, not surprising.

### 3.5 Entropy-based detection of obfuscated protocols

The GFW's current unsolved problem is that circumvention tools - obfs4,
Shadowsocks, and similar - are explicitly designed to produce output
indistinguishable from uniform random noise, defeating both keyword and SNI
matching from the very first byte of the connection. `detect::shannon_entropy`
computes standard Shannon entropy (bits/byte) over a payload; a real TLS
ClientHello, despite being "encrypted" traffic in the colloquial sense, has
recognizable *structure* in its unencrypted handshake fields (fixed content
type byte, version field, named extension types), giving it a distinguishable
entropy/structure signature from true obfuscated protocols. `classify_first_segment`
flags a connection whose accumulated first-segment buffer is both high-entropy
(≥7.0 bits/byte) *and* fails to parse as a ClientHello after the retry budget
above is exhausted. 7.0, not the more obvious 7.5: for a realistic
~300-byte first segment, birthday collisions keep measured entropy for
genuinely random data around 7.2-7.4, not near the theoretical max of 8 - a
7.5 threshold, calibrated against an unrealistically large test fixture,
silently missed real random payloads at realistic sizes (confirmed
empirically against a real `/dev/urandom` 300-byte sample). Acting on an
entropy hit (`--inject-on-detect`) is a
separate opt-in from acting on a signature/SNI/JA3 hit, since it's a
heuristic with a real false-positive rate rather than a deterministic match.

### 3.6 Adaptive escalation with TTL-bounded persistence

A single blocked SNI/JA3/signature hit resets one connection; it doesn't
follow the offending source. Real reputation-list-style censorship (the GFW's
apparent behavior, per the measurement literature, though the exact mechanism
isn't publicly documented) tracks offending sources across connections and
escalates. `Engine`'s `escalation` map counts block events per source IP
within a rolling window (`ESCALATE_WINDOW = 60s`); after `ESCALATE_THRESHOLD
= 3` offenses, the source IP is auto-promoted to a hard IP block -
independent of protocol or content, the bluntest possible rule, checked before
any payload inspection at all. Unlike a permanent list edit, escalated blocks
carry a TTL (`ESCALATION_TTL = 1 hour`, a deliberately conservative default
for a lab tool) and expire automatically, both in-memory (checked once per
packet against a live `Instant`, cheap since the list stays small) and across
restarts - `config/escalated_ip.yml` persists each entry as `ip:
unix-epoch-expiry` rather than a flat list, so the remaining TTL survives a
process restart instead of resetting to a fresh hour, and already-expired
entries are dropped rather than silently re-applied. This mirrors the
intuition that reputation-based blocks decay rather than being permanent,
scoped down from a real distributed reputation system to a single process's
in-memory + flat-file state - a deliberate simplification given the scale
(a lab tool, dozens of entries at most, no concurrent writers); a database
would be pure overhead here.

### 3.7 Local bandwidth throttling

The one mechanism in this project that isn't off-path packet forgery:
`throttle::throttle_ip` configures a macOS `dnctl` (dummynet) pipe with a
bandwidth cap and loads a matching `pfctl` anchor rule routing that IP's
traffic through it - modifying this machine's own kernel traffic-shaping
state directly, which off-path spoofing structurally cannot do (see §1). Rate
limits load from `config/throttle.yml` (ip → kbit/s) at startup and are
cleared automatically (`throttle::clear_all`) on Ctrl-C, so a crashed or
interrupted session doesn't leave the machine's real traffic shaped after the
tool itself is gone.

### 3.8 Active probing, scoped to an owned allow-list

A [detect] hit is a heuristic (high entropy, fails to parse as a ClientHello)
- it says "this looks like it could be an obfuscated proxy," not "this is
one." The GFW is documented to reduce that false-positive rate by actively
probing the suspected server itself: connecting to it and speaking a known
proxy protocol (SOCKS5, an HTTP CONNECT request, etc.) to see if it responds
the way that protocol's real server would. `probe::probe` does exactly that -
a plain outbound `TcpStream` (no spoofing, no raw socket; this is dpi-lab
itself as the client) tries a SOCKS5 greeting and an HTTP CONNECT in turn,
returning a label for whichever gets a matching reply, `None` if neither did.

The critical scoping decision: **this only ever fires against hosts on
`config/probe_targets.yml`**, checked with the same `ip_rule_matches` (exact
or CIDR) used for IP blocking. A [detect] hit whose src/dst isn't on that
list logs the heuristic result and stops there - it never triggers an
outbound connection. This is the one mechanism in the project where "own lab
only" had to be enforced *architecturally*, not just by not-invoking a flag:
active probing's entire mechanism of action is an outbound network request to
whatever address the (attacker-influenceable) traffic being classified
happens to claim, so the allow-list is a hard boundary in the code path, not
a policy note.

The probe result gates the block decision: for a flow whose src/dst is on
the allow-list, `--inject-on-detect` only fires if the probe actually
confirms a known proxy protocol - a heuristic hit against a host that
answers like an ordinary server is very likely a false positive, and probing
exists specifically to catch that case before acting on it. A flow with no
allow-listed endpoint at all has nothing to probe and falls back to trusting
the entropy heuristic alone, same as before probing existed.

### 3.9 Great-Cannon-style response injection, between two owned hosts

The Great Cannon (Citizen Lab, 2015) is an on-path injection tool China ran
alongside the GFW: when it saw an unencrypted HTTP request for certain
resources (in the documented 2015 case, ads/analytics JS served from Baidu),
it substituted a malicious script into the response instead of the real one -
turning the requester's own browser into an unwitting participant in a DDoS
against an unrelated third party (GitHub, in that case). It's a fundamentally
different move from RST injection: RST just tears a connection down, this
rewrites what the connection actually delivers.

`cannon::inject_response` replicates the injection mechanism on a strictly
reduced scope: it fires only when **both** the requester and the server are
on `config/cannon.yml`'s allow-list (checked with the same `ip_rule_matches`
used everywhere else), and the substituted body is always inert - a visible
marker string and, optionally, a redirect (`302` + `Location`) to another
host you own. There's no code path that takes a real attack target; the
mechanism the Great Cannon actually weaponizes (injecting content that
attacks a party who isn't part of the connection at all) simply isn't
implemented, not merely disabled.

Computing a valid forged response is a slightly different problem than RST
injection: the spoofed packet has to carry the sequence number the *real
server* would have used for its next byte, which isn't visible from the
request alone. `TcpStream::next_seq` exposes each direction's next-expected
byte (ISN plus everything reassembled so far), so as long as dpi-lab observed
the server's SYN-ACK on this flow, the reverse-direction flow's tracked state
gives a valid seq for free. If the SYN-ACK wasn't captured (e.g. dpi-lab
started mid-connection), there's nothing to forge against and the mechanism
stays silent for that flow rather than guessing.

The watched port (default 80) is configurable (`config/cannon.yml`'s `port`
field), not hardcoded - it turned out to matter immediately in practice: the
lab Pi already has a reverse proxy (Traefik) holding port 80 for real
services, so testing used port 81 instead rather than disrupting that
routing to free the real port.

### 3.10 Deterministic lockdown (inline, not off-path)

Every mechanism above §3.7 is off-path: it forges an *extra* packet that
races the real traffic and can lose (§1). `--lockdown` is the second
genuinely inline mechanism (alongside throttling): instead of racing a
spoofed RST, an IP/SNI/JA3/signature/detect match adds that source IP to a
dedicated pf anchor (`block drop quick from/to <ip>`) - the kernel itself
then drops every subsequent packet for that IP, deterministically, no race
to lose. It's the actual "lockdown" primitive a real firewall or GFW-style
border device would use; RST injection only approximates that behavior from
off-path, and only ever probabilistically.

Unlike escalation (which re-checks an in-memory list against every packet),
lockdown fires immediately on the *first* match rather than after N
offenses, and its effect lives in the kernel's own firewall table rather
than dpi-lab's process memory - so it keeps blocking even if dpi-lab itself
is killed mid-session, until `clear_all()` runs on a clean exit or someone
manually clears the anchor. TTL-bounded and persisted the same way as
escalated IPs (`config/lockdown.yml`, ip -> unix-epoch expiry), except
expiry here has to actively re-push the reduced rule set to pf, not just
update in-memory state - a stale kernel rule doesn't expire on its own just
because dpi-lab's own bookkeeping says it should.

**A real bug found and fixed while building this**: `pfctl -a <anchor> -f -`
replaces an anchor's entire rule set on every call, not append to it.
`throttle.rs`'s original `apply_all` (written earlier in this project) called
its per-IP helper once per config entry, each call individually reloading
the anchor - meaning only the *last* entry in `config/throttle.yml` would
ever actually be enforced, with every earlier entry silently overwritten.
Building lockdown's `apply_all` correctly (accumulate the full rule set,
write it once) surfaced the same latent bug in the mechanism it was modeled
after; fixed there too. Neither had been caught before because testing so
far only ever exercised a single throttle entry at a time.

### 3.11 Structural protocol handshake recognition (not keyword matching)

Keyword signatures (§3.1) search for a literal string anywhere in a payload -
crude, and evadable by anything that doesn't send that exact string
unmodified. Real protocols with fixed, documented wire formats can instead be
recognized *structurally*: specific bytes at specific offsets, often with an
exact total message length, independent of any string content. WireGuard's
handshake-initiation message is a clean example - message type `1`, 3
reserved zero bytes, then a fixed 148-byte total length (sender index +
ephemeral key + encrypted static key + encrypted timestamp + two MACs, all
fixed-size fields). `classify::matches_handshake` checks a `HandshakeRule`
(an optional exact length plus a list of offset -> expected-bytes anchors)
against a payload; `config/handshakes.yml` holds the actual rule database -
config-driven like every other block list here, not hardcoded, so adding a
second protocol (OpenVPN's opcode byte, say) is a YAML edit, not a rebuild.

**What this precisely does and doesn't catch.** It's more accurate to call
this a *handshake* blocker than a *protocol* blocker: it only recognizes the
handshake-initiation message itself, not an already-established session's
data traffic, which is opaque encrypted bytes with no fixed structure -
exactly the same blind spot entropy detection (§3.5) exists to (imperfectly)
address. The reason this still amounts to blocking the VPN in practice:
WireGuard has no fallback if its handshake-initiation never gets a response -
killing that one message is sufficient to prevent the tunnel from ever
forming, even though the *mechanism* only ever acts on one specific message
type, not "WireGuard traffic" as a general category. Because recognition is
structural rather than IP-based, it also fires on *any* WireGuard handshake
attempt regardless of which server it's aimed at - unlike `config/ip.yml`,
which requires already knowing the target IP in advance.

Wired into both the UDP and TCP paths of the same pipeline as everything
else: a match prints `[detect] <rule-name> on ...` and, with `--lockdown`,
pf-blocks the source IP; on the TCP side, a match also respects
`--inject-on-detect` the same way an entropy detect does. Rules carry an
optional `protocol: tcp|udp` field (`classify::rule_applies_to`) so a
UDP-only rule's byte anchors can't spuriously match an unrelated TCP stream
that happens to land on the same offsets, and vice versa - cheap correctness
once both transports feed the same rule database, not paranoia.

**Rule database, and an explicit confidence tier per entry.** No public
"database" of these signatures in this project's rule format exists (nDPI and
Wireshark's dissectors are the closest real references, but neither is a
drop-in - both encode detection as code, sometimes stateful, not a flat
offset+bytes list); `config/handshakes.yml`'s four seeded rules were each
hand-derived from a primary source, and are labeled with different confidence
levels rather than presented uniformly:

- `ssh-version-exchange` - **highest confidence**: RFC 4253 §4.2 specifies
  the literal ASCII `"SSH-"` prefix as every SSH connection's first bytes -
  a fixed protocol-mandated literal, not a guessed byte offset.
- `wireguard-handshake-init` - **live-verified** against a real `wg-easy`
  tunnel (§4.2), and separately cross-checked byte-for-byte against OpenGFW's
  (github.com/apernet/OpenGFW, MPL-2.0) `analyzer/udp/wireguard.go` - same
  type-byte, reserved-bytes, and 148-byte-length checks, independently
  arrived at before that cross-check confirmed them.
- `openvpn-hard-reset-client-v2` - originally the lowest-confidence entry
  ("recalled from general protocol knowledge, not checked against a source"),
  **since upgraded**: reading OpenGFW's `analyzer/udp/openvpn.go` confirmed
  the `0x38` byte value exactly (`opcode = byte>>3`, `P_CONTROL_HARD_RESET_
  CLIENT_V2 = 7`, `key_id = 0` on a fresh session -> `(7<<3)|0 = 0x38`). Still
  narrower than the real protocol, though: an exact-byte anchor can't express
  "top 5 bits == 7, any bottom 3 bits," so a hard-reset with nonzero `key_id`
  is missed - a real limitation of this project's byte-anchor rule schema
  (vs. OpenGFW's actual bitwise opcode check), not fixed here. Still not
  packet-captured against live OpenVPN traffic.
- `ikev2-sa-init` - derived from RFC 7296 §3.1's fixed 28-byte IKE header
  (Responder SPI, Version, Exchange Type, Flags, Message ID all zero/fixed on
  the first packet of an exchange); not live-verified against real IKEv2
  traffic, and not cross-checked against any reference implementation (IKEv2
  isn't one of OpenGFW's analyzers). Non-NAT-T only.

### 3.12 Genuine in-path enforcement via Linux NFQUEUE

Every mechanism above is off-path or local-only (§1, §3.10): RST injection
and DNS/response spoofing forge an extra packet and race it against the
real one because dpi-lab only ever sees a *copy* of traffic via passive
capture, never the real packet in transit; throttling and lockdown modify
the local kernel's own firewall, which only does anything for traffic that
machine's own network stack actually handles. Neither approach can offer a
*guarantee* - racing can lose, and local enforcement has nothing to act on
for traffic that never touches that machine at all.

Linux's NFQUEUE (`libnetfilter_queue`) removes both limitations at once: an
`nftables` rule diverts matching packets into userspace *before* the kernel
decides to forward them, and the receiving process must return an explicit
verdict - accept or drop - before the packet continues. The real packet is
held, not copied. `src/inline.rs` implements this via the `nfq` crate: an
nft table hooks the `forward` chain (this machine must actually be the
network's gateway, same requirement discussed for the router-on-a-stick
Pi/FritzBox setup - NFQUEUE doesn't grant visibility into traffic that
wouldn't already be routing through this box), queues everything to
userspace, and `InlineClassifier::classify` - reusing the same pure
matching functions as the passive path (`ip_rule_matches`,
`classify::parse_client_hello`/`ja3`/`matches_handshake`,
`classify::Signatures`) - returns a verdict per packet directly.

**Architecture reference, not copied code.** This design - nftables `queue`
rule into NFQUEUE, explicit accept/drop verdict per packet - is the same
approach OpenGFW (github.com/apernet/OpenGFW, MPL-2.0, a real production-
oriented open-source GFW implementation) uses in its `io/nfqueue.go`. That
file was read for architecture (queue setup, verdict model, the
protected-outbound-connection problem) before writing `src/inline.rs`
independently in Rust against the `nfq` crate rather than OpenGFW's
Go/`go-nfqueue` stack; no OpenGFW code was copied into this project. Citing
it here the same way Clayton et al. and Citizen Lab are cited elsewhere in
this write-up - read the real technique, build an independent
implementation, attribute the source.

**Deliberate scope reduction vs. the passive path.** `inline.rs` classifies
one packet at a time - no cross-packet TCP reassembly the way `engine.rs`'s
`TcpStream` does. A TLS ClientHello split across multiple segments (GREASE,
ECH padding, large extension lists - the exact case `engine.rs`'s reassembly
retry logic exists to handle, §3.1) won't be seen whole in inline mode.
OpenGFW's own approach doesn't hit this the same way because it also marks
already-decided flows via conntrack to skip re-inspection rather than doing
one-shot-per-packet classification; `inline.rs` re-inspects every packet of
every flow (correct, but wasteful past lab scale) rather than implementing
that bypass optimization - both are documented follow-ups, not oversights,
consistent with how every other simplification in this project is marked.

## 4. Evaluation

### 4.1 A real false-positive, found and fixed during testing

Initial entropy classification checked the first payload segment observed for
*any* flow. Live testing against real background traffic produced a false
positive: a real HTTPS connection to `54.175.92.109:443` was flagged
`possible-obfuscated-proxy`, despite being ordinary TLS.

**Root cause:** the flow's connection had been established *before* capture
started (or was a session-resumption reusing an existing TCP connection), so
the "first segment observed" by the tool was already-encrypted TLS
application data - which is, correctly, high entropy and structurally
indistinguishable from a real obfuscated protocol at that point in the stream.
The classifier's assumption ("first segment we see = ClientHello") was false
for any flow whose true start we didn't capture.

**Fix:** track whether the flow's actual SYN packet was observed
(`FlowState::saw_syn`); only run entropy classification on flows where it was.
Re-running the identical test scenario afterward against the same background
traffic produced no repeat false positive, while true positives (synthetic
`/dev/urandom` payloads sent to a controlled listener) continued to fire
correctly. This bug and its root-cause fix - rather than a symptom patch on
one call site - are, I'd argue, more informative for a research portfolio than
a clean run would have been: it demonstrates the actual failure mode
production entropy-based classifiers hit against real, messy network capture
conditions (missed connection starts, session resumption), not just the
happy path.

### 4.2 End-to-end verification against controlled infrastructure

All of the following were run live, not simulated:

- **Keyword match → RST, plaintext HTTP.** `curl "http://florianscholz.dev/?q=evil.com"`
  with `--inject` active: `[signature] evil.com in ...` → `[inject] RST sent
  both directions` → curl reported `curl: (56) Recv failure: Connection reset
  by peer`, i.e. the forged RST won the race against the real server's
  response and tore the connection down before content was received.
- **SNI match → RST, TLS handshake.** `curl -v --http1.1 "https://florianscholz.dev/"`
  with `florianscholz.dev` in `config/sni.yml`: reset fired during the TLS
  handshake itself - `curl: (35) Recv failure: Connection reset by peer`
  immediately after `Client hello (1)`, before any application data was
  exchanged.
- **JA3 match → RST.** `curl` from macOS with LibreSSL produces a stable,
  identifiable JA3 hash (`375c6162a492dfbf2795909110ce8424`); adding it to
  `config/ja3.yml` and re-running triggered `[ja3] ... client=curl/8.7.1
  (macOS/LibreSSL)` followed by the same reset sequence, confirmed against a
  Safari connection (different JA3, not blocked) to verify the match is
  actually client-specific and not just firing on every TLS handshake.
- **RST injection against a Raspberry Pi listener.** A plaintext `nc`/Python
  listener on `10.27.0.10:9999`; sending `evil.com` from the client triggered
  the same match → inject → connection-death sequence, confirmed on both
  sides (listener closed, client session dropped).
- **TCP reassembly correctness against real traffic.** Observed running
  totals matching expected transfer sizes across many real flows (e.g. a
  6.6KB+ reassembled TLS record stream to a Cloudflare-fronted host),
  confirming the reassembler (anchored on SYN ISN per §2) tracks real,
  imperfectly-ordered network traffic correctly, not just the synthetic
  unit-test fixtures.
- **Auto-escalation and expiry.** Three signature-match block events fired
  in quick succession from the same lab-VM source within the escalation
  window triggered `[escalate] auto-blocking ... (expires in 3600s,
  persisted)`; subsequent packets from that IP were blocked by the IP rule
  alone (`[ip] blocked flow ...`), regardless of content, and the entry
  survived a process restart with its remaining TTL intact via
  `config/escalated_ip.yml`.
- **Response injection against a Raspberry Pi.** `config/cannon.yml` scoped to
  the lab laptop and the Pi; a plain `python3 -m http.server` on the Pi
  (moved to a non-80 port since the Pi's Traefik container already holds 80 -
  `config/cannon.yml`'s `port` field exists specifically for this case) served
  a real directory listing as baseline. With `--inject --cannon` running,
  the identical `curl http://10.27.0.10:81/` returned `HTTP/1.1 200 OK`,
  `Content-Length: 61`, and the configured marker string in the body - the
  real Python server's response never reached curl at all, logged as
  `[cannon] injected response to <laptop>:<port> -> 10.27.0.10:81`. The
  forged response won the race outright on a LAN hop.

### 4.3 Known limitations

- **Race-dependent RST injection and DNS spoofing.** Whether the forged
  packet or the real server/resolver's response "wins" depends on relative
  latency; against fast CDN edges (this project's tests hit GitHub
  Pages/Fastly) the real GFW faces the identical problem, which is part of
  why on-path deployment (not off-path spoofing from an arbitrary point)
  matters for reliability at scale.
- **WAN seq-number visibility.** Off-LAN RST injection depends on directly
  observing both directions of a flow to compute valid seq/ack numbers;
  asymmetric routing (traffic in/out via different paths) would break this,
  a real constraint discussed in the GFW measurement literature.
- **Entropy threshold is a fixed heuristic** (`HIGH_ENTROPY_THRESHOLD = 7.0`,
  see §3.5 for why not 7.5), not tuned against a real obfs4/Shadowsocks corpus
  - the project's synthetic
  tests use `/dev/urandom`-style data as a stand-in. A rigorous evaluation
  would require capturing real obfs4 bridge traffic and measuring false
  positive/negative rates against a proper baseline, noted as follow-up work.
- **IPv6 active interference is limited on macOS.** Capture and passive
  classification work over IPv6; DNS AAAA-record spoofing requires
  `IPV6_HDRINCL`, genuinely absent from macOS's libc (see §3.4) - a Linux
  build regains full IPv6 spoofing. RST injection is IPv4-only regardless of
  platform, not yet ported to IPv6's different pseudo-header checksum.
- **Encrypted Client Hello (ECH) defeats SNI and JA3 extraction** for both
  the target domain and, since JA3 fingerprints the outer ClientHello, real
  client identification - confirmed live against Safari during testing (see
  §3.2). Fingerprinting the **outer** ClientHello's own shape (which is far
  more standardized across ECH-using clients) as a weaker signal is a
  plausible follow-up, not attempted here.
- **Escalation and throttling are single-process, flat-file state** - fine
  at lab scale (dozens of entries, no concurrent writers), not a design for
  a multi-host deployment; a real system would need a shared,
  concurrency-safe reputation store.
- **Response injection is IPv4-only**, same reason as RST injection (needs a
  separate raw IPv6 socket + pseudo-header checksum, not built).
- **Lockdown** has been verified live in the lab (pf actually drops matched
  traffic, `clear_all()` restores it on exit) in addition to
  `lockdown::tests`' ruleset-construction checks. IPv4-only in practice
  (blocked_ip/`ip_rule_matches` are IPv4-focused for CIDR; exact-IPv6 matches
  would work but haven't been exercised here). Kernel-level, not per-flow:
  locking an IP down blocks *all* its traffic, not just the
  matched flow - a broader blast radius than RST injection's per-connection
  reset, intentional for what "lockdown" means but worth stating precisely.
- **Handshake rule database has four entries at different confidence
  levels**, not four equally-trustworthy signatures - see §3.11's per-rule
  breakdown. The database mechanism generalizes cleanly (a YAML edit adds a
  protocol); what doesn't generalize is verification - each new rule still
  needs someone to confirm it against a real packet capture or a reference
  implementation. SSH's is a fixed protocol literal (highest confidence by
  construction); WireGuard's is both live-verified and cross-checked against
  OpenGFW's real implementation; OpenVPN's byte value is now cross-checked
  against source but not live-verified, and is narrower than the real
  protocol (misses nonzero `key_id`); IKEv2's is spec-derived only, checked
  against neither a capture nor a reference implementation. Treat the last
  two as drafts, not trusted signatures, until checked against real traffic.
- **QUIC detection was investigated and deliberately not attempted.**
  OpenGFW's QUIC analyzer decrypts the Initial packet's crypto payload
  (RFC 9001 Initial-secret derivation via HKDF, then AES-128-GCM) to reach
  the TLS ClientHello inside - real cryptographic work (~560 lines across
  header parsing, key derivation, and AEAD decryption in OpenGFW's
  `analyzer/udp/internal/quic/`), not a byte-anchor structural check like
  everything else in `handshakes.yml`. Correctly implementing that wasn't
  something to rush into this session just to close the gap - QUIC/HTTP-3
  traffic is currently invisible to this project entirely, a real and
  growing blind spot, but a properly-scoped follow-up rather than a corner
  cut here.
- **`--inline` (NFQUEUE) is unverified on real hardware.** Confirmed to
  compile cleanly and pass its pure-logic classifier tests when cross-checked
  against an `x86_64-unknown-linux-gnu` target (`cargo check`/`cargo test`
  type-check clean), but not yet actually run against live traffic on Linux -
  no Docker/Linux environment was available in the session that wrote it. The
  `InlineClassifier::classify` unit tests need no root/kernel access and
  should just work on real Linux; the nft-table setup and the NFQUEUE receive
  loop itself (`inline::run`) need root and an actual `nft`/NFQUEUE-capable
  kernel and have not been exercised at all yet. This is the least-verified
  mechanism in the project by a clear margin - treat it as a working draft
  until run on real hardware (the OpenWrt router this was built for is the
  natural next test), not as confirmed the way RST injection, cannon, and
  lockdown are in §4.2.

## 5. Related work

- Clayton, R., Murdoch, S. J., & Watson, R. N. M. (2006). *Ignoring the Great
  Firewall of China.* - original documentation of the RST-injection mechanism
  this project replicates.
- Ensafi, R. et al. - multiple measurement studies of GFW behavior and
  evolution.
- The GFW Report (gfw.report) - ongoing public measurement and documentation
  of GFW techniques, including SNI filtering and active probing.
- OONI (Open Observatory of Network Interference) and ICLab - open
  measurement platforms for network interference detection globally.
- RFC 8701 - GREASE, referenced for JA3's GREASE-stripping requirement.
- Marczak, B. et al. (Citizen Lab, 2015). *China's Great Cannon.* - original
  documentation of the response-injection mechanism §3.9 replicates on a
  strictly reduced, own-lab-only scope.
- OpenGFW (github.com/apernet/OpenGFW, MPL-2.0) - real, production-oriented
  open-source GFW implementation; its `io/nfqueue.go` was read for
  architecture (nftables `queue` + NFQUEUE verdict model) before writing
  `src/inline.rs` independently in Rust, per §3.12.

## 6. Ethics statement

Every mechanism here was built and tested exclusively against traffic and
infrastructure I own or explicitly control: a two-VM lab, a personal
Raspberry Pi on my LAN, and my own domain. RST injection, DNS redirect,
bandwidth throttling, active probing, and response injection are all disabled
by default; probing and response injection additionally require both flow
endpoints to be on an explicit allow-list, enforced in code, not just by not
passing a flag. None were ever directed at third-party traffic or
infrastructure. Response injection's payload is always inert (a marker string
and/or a redirect to another host I own) - the real Great Cannon's actual
weapon, injecting content that attacks a party outside the connection
entirely, has no implementation here at all, not merely a disabled one; there
is no parameter that could make it target anything but an owned host.
`--inline`'s NFQUEUE mode carries a different risk profile from everything
else here: it only does anything once the host running it is the actual
network gateway, at which point its effect applies to every device whose
traffic transits that gateway, not only the host itself. It was designed and
(to the extent tested so far) only ever run against a single-person home
network - on a shared network, honoring "own lab only" would require scoping
enforcement to specific devices rather than the whole gateway, a distinction
raised and worked through explicitly before any inline testing began. This
project studies and reproduces documented censorship mechanisms for
security-research purposes; it is not, and is not intended to become, a
deployable interception or censorship tool.
