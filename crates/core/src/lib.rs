//! isopod-core — orchestrator library.
//!
//! Module layout per PLAN.md: vm, stage, snapshot, net, agent, store, image.
//! Modules land milestone by milestone; M1 ships `paths`, `image` and `vm`
//! (the ephemeral dev-boot slice of the VM lifecycle).

pub mod image;
pub mod paths;
pub mod vm;
