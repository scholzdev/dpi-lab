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

Logging is via `log`/`env_logger` - `RUST_LOG` controls verbosity
(`RUST_LOG=info` is the default, matches what used to print unconditionally;
`RUST_LOG=debug` adds the `--trace` raw-packet dump's detail; `RUST_LOG=warn`
or `error` quiets it down). Timestamped, leveled lines to stderr, e.g.:
```
[2026-08-08T12:23:08Z WARN  dpi_lab] [scan] refusing 10.99.99.0/24: not a literal entry in config/probe_targets.yml
```
The block-event summary, `--scan` results, and the interface list stay on
plain stdout regardless of `RUST_LOG` - those are direct output, not log
events.

## Web UI

`dpi-lab-ui` is a separate, unprivileged binary (no root, no raw sockets) -
a browser-based config editor + live block/lockdown dashboard:

```bash
cargo build --release
./target/release/dpi-lab-ui                       # binds 127.0.0.1:8080 by default
sudo ./target/release/dpi-lab eth0 --inject --events-log events.jsonl
```

then open `http://127.0.0.1:8080`. The editor lists every `config/*.yml`
file and edits it as JSON (mirrors the YAML shape 1:1 - a flat list stays a
JSON array, `asn.yml`'s `{cidr,asn,name}` entries stay objects, etc.) -
**changes take effect on dpi-lab's next restart**, there's no hot-reload.
The events table polls `/api/events` every 2s, tailing whatever
`--events-log` file dpi-lab is appending to (empty/no data until dpi-lab is
actually running with that flag and has blocked something).

No authentication - matches this whole project's single-user/self-hosted
framing, same as dpi-lab itself. Binds to `127.0.0.1` only by default, so
it's not reachable over the network unless you explicitly rebind
(`--bind 0.0.0.0:8080`) or reverse-proxy it - doing either without adding
auth in front means anyone who can reach that port can rewrite your
blocklists.

## Docker

Linux only, either mode (this doesn't relax the platform requirement -
`--inline` is Linux-native NFQUEUE, and passive mode needs a real Linux
interface, not a Docker Desktop macOS/Windows VM's virtual one):

```bash
docker build -t dpi-lab .

docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v $(pwd)/config:/app/config dpi-lab passive eth0 --lockdown --block-sni evil.com

docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v $(pwd)/config:/app/config dpi-lab inline --downgrade-tls13
```

`--network host` is required either way - passive mode needs to see a real
host interface, `--inline` needs to actually sit in the host's forwarding
path (same "this machine must be the actual gateway" requirement native
`--inline` already has). `--cap-add=NET_ADMIN --cap-add=NET_RAW` covers raw
sockets + NFQUEUE + nftables; fall back to `--privileged` if something's
still denied under a locked-down Docker daemon config. Mount `config/` as
shown so blocklists/rules can be edited without rebuilding the image, same
as running natively.

The same image also runs `dpi-lab-ui` (see `## Web UI` above) via a third
mode - no `--network host`/cap_add needed, it's unprivileged:

```bash
docker run --rm -p 127.0.0.1:8080:8080 \
  -v $(pwd)/config:/app/config -v $(pwd)/data:/app/data \
  dpi-lab ui --bind 0.0.0.0:8080 --config-dir /app/config --events-log /app/data/events.jsonl
```

`docker-compose.yml` has ready-to-edit templates for all three modes,
wired to share `config/` and `data/events.jsonl` between the capture
container and the UI container.

**`--lockdown` and throttling don't work in this image** - they shell out
to macOS's `pfctl`/`dnctl`, which don't exist on Linux at all (not a Docker
limitation, a platform one). Both fail soft: a log line and the process
keeps running, every other mechanism (RST inject, DNS spoof, detection,
SNI/JA3/ASN/allowlist blocking, etc.) is unaffected. See `docker-compose.yml`
for ready-to-edit service templates.

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
