# dpi-lab

A DPI pipeline - capture → reassemble → classify → active interference - built
to study and replicate mechanisms documented in Great Firewall research:
keyword/SNI/JA3 filtering, TCP RST injection, DNS response spoofing,
entropy-based detection of obfuscated proxy protocols, structural protocol
handshake recognition (e.g. WireGuard), allow-list-scoped active probing,
Great-Cannon-style HTTP response injection, adaptive TTL-bounded IP
escalation, local bandwidth throttling, deterministic pf-level lockdown, and
(Linux only) genuine in-path NFQUEUE enforcement. Built as a portfolio piece
for network security/penetration testing applications.

## Ethics / scope

Everything here was developed and tested against **traffic I generate myself**:
a two-VM lab, my own Raspberry Pi, and my own domain (`florianscholz.dev`). RST
injection, DNS redirect, throttling, active probing, response injection, and
lockdown are all off by default and only ever fired at connections/hosts I
control - active probing and response injection additionally only ever act
between hosts on an explicit allow-list (`config/probe_targets.yml`,
`config/cannon.yml`), enforced in code, and response injection's payload is
always inert (a marker string and/or a redirect to another host I own, never
executable content). This is not deployed against, and should not be run
against, third-party traffic or infrastructure - see `writeup.md` for the
full threat model.

`--inline` is a different risk category from everything else here: it only
does anything at all once the machine running it is the actual network
gateway, at which point it applies to *every device* whose traffic transits
that gateway, not just the host running dpi-lab. It was only ever run against
a single-person home network where I'm the sole user of every device on it -
on a shared network, "own lab only" would require scoping enforcement to
specific devices (see `writeup.md`), not the whole gateway.

**Disclaimer.** This is educational/research code, licensed under MIT (see
`LICENSE`) with no warranty. `--inject`, `--redirect-dns`, `--throttle`,
`--cannon`, `--lockdown`, `--inline`, and active probing forge packets, spoof
DNS, modify real firewall state, inject response content, intercept and
drop/accept live network traffic, and open outbound connections - running
any of them against networks, hosts, or traffic you don't own or have
explicit authorization to test almost certainly violates the law (e.g. wire
fraud / unauthorized access statutes) and, separately, your ISP's or
employer's acceptable-use policy. That's on you, not this code. Point it only
at infrastructure you own or are explicitly authorized to test.

## Build & run

```bash
cargo build
cargo test                              # 57 unit tests, no network/root needed
sudo ./target/debug/dpi-lab <interface> [flags]     # passive capture, off-path enforcement
sudo ./target/debug/dpi-lab --inline                # Linux only: genuine in-path NFQUEUE mode
```

No interface arg lists available interfaces (needs root/raw-socket capability
to actually capture). Key flags:

| Flag | Effect |
|---|---|
| `--inject` | forge TCP RST on a block match |
| `--inject-on-detect` | also fire on an entropy-based detect (separate opt-in - heuristic, not deterministic) |
| `--redirect-dns` | spoof DNS A/AAAA responses per `config/redirect.yml` |
| `--cannon` | inject a plaintext HTTP response per `config/cannon.yml` (own-lab hosts only) |
| `--lockdown` | any IP/SNI/JA3/signature/detect match hard-blocks that source IP at the pf level (deterministic, can't lose a race like `--inject`) |
| `--inline` | Linux only: genuine in-path NFQUEUE mode - accept/drop the real packet directly instead of racing a spoofed one. Replaces the whole passive-capture pipeline, not a modifier on it (no interface arg, no other flags apply) |
| `--trace` | print every raw TCP/UDP packet (flood); off by default, only classification/block events print |
| `--block-sni/-ja3/-ip/-sig <value>` | repeatable, adds one rule on top of the matching `config/*.yml` |

Block lists (`config/{sni,ja3,ip,signatures}.yml`), known protocol handshake
signatures (`config/handshakes.yml` - byte anchors + length, protocol-scoped, not keywords - WireGuard, IKEv2, OpenVPN, SSH seeded),
the DNS redirect map (`config/redirect.yml`), throttle rates
(`config/throttle.yml`), the active-probing allow-list
(`config/probe_targets.yml`), and the response-injection allow-list + payload
(`config/cannon.yml`) are all plain YAML - own lab hosts only, edit the file,
no rebuild needed. Auto-escalated IPs
(`config/escalated_ip.yml`) and lockdown IPs (`config/lockdown.yml`, written
by dpi-lab itself, not hand-edited) both persist with a TTL and survive
restarts; already-expired entries are dropped automatically. Ctrl-C prints a
block-event summary and clears any throttle/lockdown firewall state before
exiting.

## Reproducing the results in writeup.md

```bash
./scripts/repro_probe.sh              # active-probing logic, no root/network needed
sudo ./scripts/repro_sig_block.sh     # live signature-match -> RST block, needs root + your own domain
```

## Structure

| File | Role |
|---|---|
| `src/main.rs` | CLI + capture loop |
| `src/engine.rs` | per-packet pipeline: decode → reassemble → classify → inject/redirect → escalate |
| `src/reassembly.rs` | TCP stream reassembly, anchored on the SYN's ISN |
| `src/classify.rs` | keyword signatures (Aho-Corasick), TLS SNI + JA3 fingerprint, DNS query parsing |
| `src/detect.rs` | Shannon-entropy check for obfuscated/proxy traffic |
| `src/classify.rs`'s `HandshakeRule`/`matches_handshake` | structural protocol handshake recognition (byte anchors + length), config-driven via `config/handshakes.yml` |
| `src/inject.rs` | forged TCP RST construction + raw-socket send |
| `src/redirect.rs` | forged DNS A/AAAA response construction + send (IPv4 + IPv6) |
| `src/throttle.rs` | macOS `pfctl`/`dnctl` bandwidth throttling - the one inline (non-spoofing) mechanism |
| `src/probe.rs` | active probing (SOCKS5/HTTP-CONNECT handshake) against allow-listed hosts only |
| `src/cannon.rs` | Great-Cannon-style HTTP response injection, allow-listed pairs only |
| `src/lockdown.rs` | deterministic pf-level IP block - the other inline (non-spoofing) mechanism, alongside throttle.rs |
| `src/inline.rs` | Linux-only NFQUEUE mode - genuine in-path accept/drop, architecture referenced from OpenGFW (MPL-2.0), reimplemented independently in Rust |
| `src/timing.rs` | packet timing/size statistics |
| `src/config.rs` | YAML block-list/map loading, escalation-expiry persistence |

See `writeup.md` for the full report: threat model, design rationale per
mechanism, evaluation (including two documented bugs and their root-cause
fixes, and a real ECH blind-spot finding against Safari), known limitations,
and citations.
