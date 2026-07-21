//! isopod-core — orchestrator library.
//!
//! Module layout per PLAN.md: vm, stage, snapshot, net, agent, store, image.
//! Modules land milestone by milestone; M1 shipped `paths`, `image` and `vm`
//! (the ephemeral dev-boot slice); M2 adds `agent` (the guest-agent vsock RPC
//! client) and the ephemeral run flow in `vm`.

pub mod agent;
pub mod image;
pub mod names;
pub mod paths;
pub mod vm;
