//! Request/response message types.
//!
//! Field discipline: additive changes only within a `PROTO_VERSION`; renames or
//! semantic changes bump the version.

use serde::{Deserialize, Serialize};

/// A host→guest request. `id` is echoed in every response to this request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    /// Correlation id chosen by the host; echoed in responses.
    pub id: u64,
    /// The operation to perform.
    pub op: RequestOp,
}

/// Operations the guest agent implements.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RequestOp {
    /// Liveness + version handshake.
    Ping,
    /// Execute a command; responses stream `ExecStream`* then one `ExecDone`.
    Exec(ExecRequest),
    /// Set the guest wall clock (host sends its own `CLOCK_REALTIME`).
    SyncClock {
        /// Seconds since the unix epoch.
        unix_secs: u64,
        /// Nanosecond remainder.
        nanos: u32,
    },
    /// Reconfigure the guest's IPv4 networking at runtime.
    ///
    /// Sent after a snapshot restore retargets the virtio-net backend to a new
    /// host tap: the restored guest keeps the same NIC *device* but its stale
    /// boot-time addressing must be replaced with the claimed slot's. The guest
    /// fully replaces `eth0`'s address, netmask, default route, and resolver
    /// config (the same ioctl path as boot-time configuration). Replies
    /// [`ResponseBody::Ok`] on success or [`ResponseBody::Error`] on failure
    /// (e.g. an unparseable address or a missing NIC).
    ConfigureNet {
        /// Guest IPv4 address in CIDR form, e.g. `"10.107.3.2/30"`.
        ip: String,
        /// Default gateway, e.g. `"10.107.3.1"`. An empty string means "no
        /// gateway" (the default route is left cleared).
        gw: String,
        /// DNS resolvers (dotted-quad strings) written to `/etc/resolv.conf`;
        /// malformed entries are dropped. Empty leaves `resolv.conf` untouched.
        dns: Vec<String>,
    },
    /// Write a file into the guest (single-frame; fits within `MAX_FRAME_LEN`).
    PutFile {
        /// Absolute destination path in the guest.
        path: String,
        /// Unix mode bits (e.g. 0o755).
        mode: u32,
        /// File contents, base64.
        data_b64: String,
    },
    /// Read a file from the guest (single-frame; errors if larger than `max_bytes`).
    GetFile {
        /// Absolute source path in the guest.
        path: String,
        /// Refuse to return more than this many raw bytes.
        max_bytes: u64,
    },
    /// Sync filesystems and power off the guest.
    Halt {
        /// If true, `sync()` before powering off.
        sync: bool,
    },
}

/// Parameters for `RequestOp::Exec`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecRequest {
    /// Program + arguments (argv[0] is the program; PATH is searched).
    pub argv: Vec<String>,
    /// Extra environment variables appended to the agent's baseline env.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
    /// Working directory (default `/root`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Kill the command after this many milliseconds (default: no limit; the
    /// host enforces its own outer timeout regardless).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    /// Bytes to write to the command's stdin (base64), then close it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdin_b64: Option<String>,
}

/// A guest→host response. `id` matches the originating request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
    /// Correlation id of the request this answers.
    pub id: u64,
    /// The response payload.
    pub body: ResponseBody,
}

/// Response payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResponseBody {
    /// Answer to `Ping`.
    Pong {
        /// Guest agent version (crate version).
        agent_version: String,
        /// Protocol version the agent speaks; host must match `PROTO_VERSION`.
        proto_version: u32,
        /// Guest uptime in seconds (restore-continuity diagnostics).
        uptime_s: f64,
    },
    /// One chunk of exec output.
    ExecStream {
        /// Which stream the chunk belongs to.
        stream: ExecStreamKind,
        /// Chunk contents, base64 (≤ `EXEC_CHUNK_LEN` raw bytes).
        data_b64: String,
    },
    /// Exec finished; exactly one per exec, always last.
    ExecDone {
        /// Process exit code (`None` if killed by signal).
        exit_code: Option<i32>,
        /// Terminating signal, if any.
        signal: Option<i32>,
        /// Wall time of the exec in milliseconds.
        duration_ms: u64,
        /// True if the in-guest `timeout_ms` fired.
        timed_out: bool,
    },
    /// Generic success (SyncClock, PutFile, Halt acknowledgement).
    Ok,
    /// Answer to `GetFile`.
    File {
        /// File contents, base64.
        data_b64: String,
        /// Unix mode bits of the source file.
        mode: u32,
    },
    /// The operation failed guest-side.
    Error {
        /// Human-readable failure description.
        message: String,
    },
}

/// Output stream identity for `ExecStream` chunks.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecStreamKind {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Encode raw bytes for a `data_b64` field.
pub fn b64_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode a `data_b64` field.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_json_shape_is_stable() {
        let req = Request {
            id: 7,
            op: RequestOp::Exec(ExecRequest {
                argv: vec!["echo".into(), "hi".into()],
                env: vec![],
                cwd: None,
                timeout_ms: Some(1000),
                stdin_b64: None,
            }),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"id":7,"op":{"op":"exec","argv":["echo","hi"],"timeout_ms":1000}}"#
        );
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn configure_net_json_shape_is_stable() {
        let req = Request {
            id: 5,
            op: RequestOp::ConfigureNet {
                ip: "10.107.3.2/30".into(),
                gw: "10.107.3.1".into(),
                dns: vec!["1.1.1.1".into()],
            },
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"id":5,"op":{"op":"configure_net","ip":"10.107.3.2/30","gw":"10.107.3.1","dns":["1.1.1.1"]}}"#
        );
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn response_json_shape_is_stable() {
        let resp = Response {
            id: 7,
            body: ResponseBody::ExecDone {
                exit_code: Some(0),
                signal: None,
                duration_ms: 12,
                timed_out: false,
            },
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert_eq!(
            json,
            r#"{"id":7,"body":{"kind":"exec_done","exit_code":0,"signal":null,"duration_ms":12,"timed_out":false}}"#
        );
        let back: Response = serde_json::from_str(&json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn b64_round_trip() {
        let data = b"\x00\xffbinary\n";
        assert_eq!(b64_decode(&b64_encode(data)).unwrap(), data);
    }
}
