// Library surface for dpi-lab's packet-capture/classify/enforce pipeline.
// Consumed by src/main.rs (passive-capture + --inline + --scan CLI) and
// src/bin/dpi-lab-ui.rs (web dashboard) as two binaries of this same crate;
// also importable as `dpi_lab::...` from an external project.
pub mod asn;
pub mod cannon;
pub mod classify;
pub mod config;
pub mod detect;
pub mod events;
pub mod fragment;
pub mod engine;
pub mod h2;
pub mod inject;
#[cfg(target_os = "linux")]
pub mod inline; // whole file is also #![cfg(target_os = "linux")]
pub mod ipv6ext;
pub mod lockdown;
pub mod mitm;
pub mod probe;
pub mod quic;
pub mod reassembly;
pub mod redirect;
pub mod throttle;
pub mod timing;
