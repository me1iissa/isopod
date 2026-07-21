//! `isopod-fc` — a typed client for the Firecracker management API.
//!
//! Pinned to Firecracker **v1.16.1** (the vendored `firecracker.yaml` Swagger
//! 2.0 spec is the authoritative source for every model in [`models`]). The
//! crate is deliberately self-contained and dependency-light so it can later be
//! extracted as a standalone SDK.
//!
//! # What's here
//! * [`models`] — hand-written serde structs for the API types isopod needs.
//! * [`client`] — [`FcClient`], one HTTP client per VM over the API unix
//!   socket, with a runtime pre-boot/post-boot [`Phase`] guard.
//! * [`process`] — [`FcProcess`], `tokio`-based supervision of a Firecracker
//!   binary (spawn, socket-readiness wait, graceful/forced shutdown).
//! * [`id`] — [`VmId`] and [`IfName`] newtypes validating the identifiers
//!   Firecracker and the host kernel are picky about.
//! * [`vsock`] — hybrid-vsock connect/listen helpers.
//!
//! # Quick tour
//! ```no_run
//! use isopod_fc::{FcClient, FcProcess, FcProcessConfig, VmId};
//! use isopod_fc::models::{BootSource, Drive, MachineConfig};
//! use std::time::Duration;
//!
//! # async fn demo() -> isopod_fc::Result<()> {
//! let cfg = FcProcessConfig::new("/path/to/firecracker", "/run/vm.sock")
//!     .id(VmId::new("vm-1")?);
//! let mut proc = FcProcess::spawn(cfg).await?;
//!
//! let client = proc.client()?;
//! client.put_machine_config(&MachineConfig::new(1, 256)).await?;
//! client
//!     .put_boot_source(&BootSource::new("/img/vmlinux", "console=ttyS0 quiet"))
//!     .await?;
//! client
//!     .put_drive(&Drive::virtio("rootfs", "/img/rootfs.ext4", true, true))
//!     .await?;
//! client.instance_start().await?;
//! assert!(client.get_instance_info().await?.state.is_running());
//!
//! proc.shutdown(Duration::from_secs(2)).await?;
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod id;
pub mod models;
pub mod process;
pub mod vsock;

pub use client::{FcClient, Phase};
pub use error::{Error, PhaseError, Result};
pub use id::{IdError, IfName, VmId};
pub use process::{FcProcess, FcProcessConfig, LogLevel, StdioMode};

/// The Firecracker version this crate's models and behaviour are pinned to.
pub const FIRECRACKER_VERSION: &str = "1.16.1";
