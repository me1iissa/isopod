//! Guest-image pipeline: fetch a prebuilt CI kernel and build the rootfs image,
//! both fully unprivileged. Drives the `isopod image` subcommands.
//!
//! * [`fetch_kernel`] — enumerate Firecracker's public S3 CI prefixes and
//!   download the newest vmlinux of a requested series.
//! * [`build_rootfs`] — assemble a rootfs tree and lay it down as a sparse ext4
//!   image via `mkfs.ext4 -d` (no root).

mod kernel;
mod rootfs;
mod s3;

pub use kernel::{fetch_kernel, FetchKernelOutcome};
pub use rootfs::{
    base_image_path, build_rootfs, make_scratch_ext4, BuildRootfsOutcome, RootfsFlavor,
};
