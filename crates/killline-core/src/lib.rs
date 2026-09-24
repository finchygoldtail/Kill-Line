//! Kill Line core: containment policy, deterministic rule engine, behavioural
//! heuristics, flight recorder and forensic bundles.
//!
//! This crate has no kernel or platform dependencies so that it can be
//! tested, fuzzed and audited on its own. Sensors (eBPF, …) produce
//! [`event::Observation`]s; the [`engine::Engine`] turns them into verdicts.

pub mod anomaly;
pub mod engine;
pub mod event;
pub mod incident;
pub mod pathmatch;
pub mod policy;
pub mod redact;
pub mod session;
pub mod store;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
