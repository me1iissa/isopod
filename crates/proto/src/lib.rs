//! isopod-proto — the host<->guest RPC contract.
//!
//! Transport: Firecracker hybrid vsock. The host connects to the guest agent's
//! `AF_VSOCK` listener on [`VSOCK_PORT`] (via the host-side UDS `CONNECT`
//! handshake, see `isopod-fc::vsock`). One connection per operation; the
//! connection is closed when the operation completes. Connections must be
//! assumed dead after any snapshot pause/resume/fork.
//!
//! Wire format: each message is a frame of `u32` little-endian payload length
//! followed by a JSON-encoded [`Request`] or [`Response`]. Frames are capped at
//! [`MAX_FRAME_LEN`] bytes. Binary data (exec output, file bytes) is base64
//! inside the JSON so frames are always valid UTF-8.
//!
//! Exec is streamed: the guest sends any number of `ExecStream` responses
//! (stdout/stderr chunks, ≤ [`EXEC_CHUNK_LEN`] raw bytes each) followed by
//! exactly one `ExecDone`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod frame;
pub mod msg;

pub use frame::{read_frame, write_frame, FrameError};
pub use msg::*;

/// Guest vsock port the agent listens on.
pub const VSOCK_PORT: u32 = 52;

/// Protocol version; bump on any incompatible wire change. Exchanged in
/// `Ping`/`Pong` so mismatched host/guest pairs fail fast and loud.
pub const PROTO_VERSION: u32 = 1;

/// Hard cap on a single frame's JSON payload (base64 overhead included).
pub const MAX_FRAME_LEN: u32 = 8 * 1024 * 1024;

/// Max raw bytes per `ExecStream` chunk (32 KiB, the E2B-proven chunk size).
pub const EXEC_CHUNK_LEN: usize = 32 * 1024;
