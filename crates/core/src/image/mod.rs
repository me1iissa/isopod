//! Guest-image pipeline: fetch a prebuilt CI kernel and build the rootfs image,
//! both fully unprivileged. Drives the `isopod image` subcommands.
//!
//! * [`fetch_kernel`] — download the pinned, digest-verified CI vmlinux (or,
//!   explicitly unpinned, the newest upstream build of a requested series).
//! * [`build_rootfs`] — assemble a rootfs tree and lay it down as a sparse ext4
//!   image via `mkfs.ext4 -d` (no root).

mod kernel;
mod rootfs;
mod s3;

pub use kernel::{fetch_kernel, FetchKernelOutcome};
pub use rootfs::{
    base_content_id, base_image_path, build_rootfs, check_image_proto, list_images,
    make_scratch_ext4, read_image_meta, BuildRootfsOutcome, ImageEntry, ImageList, ImageMeta,
    RootfsFlavor,
};
