//! Error types for the Firecracker client, process supervisor and vsock helpers.
//!
//! The crate distinguishes three broad failure classes so callers can react
//! appropriately:
//!
//! * [`Error::Transport`] — the HTTP request never produced a well-formed
//!   response (socket gone, connection refused, body decode failure). Usually
//!   means the Firecracker process has died or the API socket is stale.
//! * [`Error::Api`] — Firecracker returned a non-success status. The VMM's own
//!   `fault_message` (from the API `Error` body) is preserved verbatim.
//! * [`Error::Phase`] — the call was rejected locally by the client's runtime
//!   phase guard before ever hitting the socket (e.g. a pre-boot-only `PUT`
//!   issued after `InstanceStart`).
//!
//! Every request-bound variant carries the request `path` so failures are
//! self-describing in logs.

use crate::client::Phase;
use crate::id::IdError;

/// Convenience alias with [`Error`] as the default error type.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Top-level error type for all fallible operations in this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The HTTP request failed at the transport layer (connect/send/timeout).
    ///
    /// On a per-VM unix socket this almost always means the Firecracker
    /// process exited or the socket file is stale.
    #[error("transport error talking to Firecracker at {path}: {source}")]
    Transport {
        /// API path the failing request targeted (e.g. `/machine-config`).
        path: String,
        /// Underlying `reqwest` error.
        #[source]
        source: reqwest::Error,
    },

    /// Firecracker returned a non-2xx status. Carries the VMM's `fault_message`.
    #[error("Firecracker API error: {method} {path} -> {status}: {fault_message}")]
    Api {
        /// HTTP method used.
        method: String,
        /// API path the request targeted.
        path: String,
        /// HTTP status code returned by Firecracker.
        status: u16,
        /// Firecracker's `fault_message` (or the raw body if it did not parse).
        fault_message: String,
    },

    /// The response body could not be deserialized into the expected type.
    #[error("failed to decode response body from {path}: {source}")]
    Decode {
        /// API path whose response failed to decode.
        path: String,
        /// Underlying `reqwest` decode error.
        #[source]
        source: reqwest::Error,
    },

    /// A method was called in the wrong lifecycle phase (see [`PhaseError`]).
    #[error(transparent)]
    Phase(#[from] PhaseError),

    /// An invalid VM id or interface name was supplied (see [`IdError`]).
    #[error(transparent)]
    Id(#[from] IdError),

    /// Failed to build the underlying `reqwest` client.
    #[error("failed to build HTTP client for socket {path}: {source}")]
    ClientBuild {
        /// Path to the unix socket the client was being bound to.
        path: String,
        /// Underlying `reqwest` error.
        #[source]
        source: reqwest::Error,
    },

    /// The Firecracker process failed to spawn.
    #[error("failed to spawn Firecracker process ({program}): {source}")]
    Spawn {
        /// The program that failed to launch (binary or command wrapper).
        program: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The API socket did not appear within the configured timeout after spawn.
    ///
    /// If Firecracker exited during startup, `exit` reports how.
    #[error("Firecracker API socket {path} did not become ready within {timeout_ms} ms{}",
        match .exit { Some(s) => format!(" (process exited: {s})"), None => String::new() })]
    SocketTimeout {
        /// Path to the API socket that never became connectable.
        path: String,
        /// The timeout that elapsed, in milliseconds.
        timeout_ms: u64,
        /// The process exit status, if Firecracker died before the socket appeared.
        exit: Option<String>,
    },

    /// A generic I/O error with contextual description.
    #[error("{context}: {source}")]
    Io {
        /// Human-readable description of what was being attempted.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The vsock `CONNECT` handshake with the guest did not succeed.
    #[error("vsock handshake failed on {path} (port {port}): {reason}")]
    VsockHandshake {
        /// Host-side unix socket path used for the handshake.
        path: String,
        /// Guest vsock port that was requested.
        port: u32,
        /// Human-readable reason (unexpected reply, closed stream, etc.).
        reason: String,
    },
}

impl Error {
    /// Returns the HTTP status code if this is an [`Error::Api`] variant.
    #[must_use]
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// Rejected because the client's tracked lifecycle phase did not permit the call.
///
/// The client tracks its own view of the VM lifecycle
/// (`Configuring` -> `Running` <-> `Paused`) from the calls it issues, and
/// rejects mis-sequenced operations locally instead of surfacing Firecracker's
/// less descriptive `400`s. See [`Phase`] and the
/// per-method rustdoc on [`FcClient`](crate::client::FcClient).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PhaseError {
    /// The method is pre-boot only but the VM has already been started.
    #[error("`{method}` is pre-boot only, but the VM is {actual:?}")]
    RequiresPreBoot {
        /// The client method that was rejected.
        method: &'static str,
        /// The phase the client was actually in.
        actual: Phase,
    },
    /// The method is post-boot only but the VM has not been started yet.
    #[error("`{method}` requires the VM to be booted, but it is still {actual:?}")]
    RequiresPostBoot {
        /// The client method that was rejected.
        method: &'static str,
        /// The phase the client was actually in.
        actual: Phase,
    },
    /// The method requires the VM to be in the `Running` phase.
    #[error("`{method}` requires the VM to be Running, but it is {actual:?}")]
    RequiresRunning {
        /// The client method that was rejected.
        method: &'static str,
        /// The phase the client was actually in.
        actual: Phase,
    },
    /// The method requires the VM to be in the `Paused` phase.
    #[error("`{method}` requires the VM to be Paused, but it is {actual:?}")]
    RequiresPaused {
        /// The client method that was rejected.
        method: &'static str,
        /// The phase the client was actually in.
        actual: Phase,
    },
}
