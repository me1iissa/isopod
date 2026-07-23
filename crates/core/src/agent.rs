//! Host-side guest-agent RPC client.
//!
//! [`AgentClient`] speaks the [`isopod_proto`] contract to the guest agent over
//! Firecracker's hybrid vsock. Per PLAN.md the transport is *reconnect per
//! request*: every operation opens a fresh connection with
//! [`isopod_fc::vsock::connect_to_guest`] on [`isopod_proto::VSOCK_PORT`], sends
//! one request frame, consumes the response(s), and closes. This is what makes
//! the client robust across snapshot pause/resume/fork (which sever live vsock
//! connections but leave the guest listener intact) without any reconnection
//! bookkeeping.
//!
//! `exec` is streamed: the guest emits any number of `ExecStream` chunks
//! followed by exactly one `ExecDone`. Every byte is teed to a per-stream log
//! file while the first `inline_cap` bytes are kept in memory for inline
//! reporting (with a `truncated` flag and exact total byte counts).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

use isopod_proto::frame::{self, FrameError};
use isopod_proto::{
    b64_decode, b64_encode, ExecRequest, ExecStreamKind, Request, RequestOp, Response,
    ResponseBody, PROTO_VERSION, VSOCK_PORT,
};

/// Failures talking to the guest agent.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The vsock `CONNECT` handshake to the guest agent failed.
    #[error("connecting to guest agent vsock at {path}: {source}")]
    Connect {
        /// Host-side UDS path the connection targeted.
        path: String,
        /// Underlying fc-client error.
        #[source]
        source: isopod_fc::Error,
    },
    /// A frame could not be encoded, decoded, or transferred.
    #[error("RPC framing error on {path}: {source}")]
    Frame {
        /// Host-side UDS path the frame was exchanged on.
        path: String,
        /// Underlying framing error.
        #[source]
        source: FrameError,
    },
    /// The guest agent speaks a different protocol version than this host.
    #[error("guest agent protocol version {got} does not match host {expected}")]
    ProtoMismatch {
        /// The version this host requires ([`PROTO_VERSION`]).
        expected: u32,
        /// The version the guest agent reported.
        got: u32,
    },
    /// The guest was asked to assemble a stage-overlay root at boot and failed:
    /// it is running on the read-only base root, so any exec would see the
    /// wrong filesystem (dogfood finding #26). Fatal, like a proto mismatch.
    #[error(
        "guest stage-overlay root failed to assemble ({0}); the guest is running \
         on the read-only base root, refusing to run on the wrong rootfs"
    )]
    OverlayDegraded(String),
    /// The guest returned a response that does not fit the operation.
    #[error("guest agent returned an unexpected response: {0}")]
    Unexpected(String),
    /// The guest agent handled the request but reported a failure.
    #[error("guest agent reported an error: {0}")]
    Guest(String),
    /// The agent did not answer a ping within the readiness deadline.
    #[error("guest agent not ready after {0:?}")]
    NotReady(Duration),
    /// The exec stream ended before the terminating `ExecDone` frame.
    #[error(
        "exec stream ended before completion (stdout {stdout_bytes} B, \
         stderr {stderr_bytes} B captured): {reason}"
    )]
    ExecIncomplete {
        /// Stdout bytes received before the stream died.
        stdout_bytes: u64,
        /// Stderr bytes received before the stream died.
        stderr_bytes: u64,
        /// Why the stream ended early.
        reason: String,
    },
    /// A base64 payload from the guest could not be decoded.
    #[error("invalid base64 in guest {stream} payload: {detail}")]
    BadChunk {
        /// Which payload (`stdout`, `stderr`, or `file`).
        stream: &'static str,
        /// Decoder error text.
        detail: String,
    },
    /// A host-side I/O error (writing a tee log, etc.).
    #[error("{context}: {source}")]
    Io {
        /// What was being attempted.
        context: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Build an [`AgentError::Io`] mapper closure carrying `context`.
fn io_err(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> AgentError {
    let context = context.into();
    move |source| AgentError::Io { context, source }
}

/// Answer to [`AgentClient::ping`].
#[derive(Debug, Clone, PartialEq)]
pub struct Pong {
    /// Guest agent crate version.
    pub agent_version: String,
    /// Protocol version the guest speaks (always equal to [`PROTO_VERSION`] on
    /// success — a mismatch is surfaced as [`AgentError::ProtoMismatch`]).
    pub proto_version: u32,
    /// Guest uptime in seconds (useful as a restore-continuity diagnostic).
    pub uptime_s: f64,
}

/// A file returned by [`AgentClient::get_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetFile {
    /// Raw file contents.
    pub bytes: Vec<u8>,
    /// Unix mode bits of the source file.
    pub mode: u32,
}

/// Parameters for [`AgentClient::exec`].
#[derive(Debug, Clone)]
pub struct ExecSpec {
    /// Program + arguments (`argv[0]` is the program; the guest searches PATH).
    pub argv: Vec<String>,
    /// Extra environment variables appended to the agent's baseline env.
    pub env: Vec<(String, String)>,
    /// Working directory (guest default `/root` when `None`).
    pub cwd: Option<String>,
    /// In-guest timeout in milliseconds (`None` = no guest-side limit).
    pub timeout_ms: Option<u64>,
    /// Bytes to write to the command's stdin before closing it.
    pub stdin: Option<Vec<u8>>,
    /// Tee every stdout byte to this file.
    pub stdout_log: PathBuf,
    /// Tee every stderr byte to this file.
    pub stderr_log: PathBuf,
    /// Keep at most this many bytes of each stream in memory for inline reporting.
    pub inline_cap: usize,
}

/// The captured head of one output stream plus its exact size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamCapture {
    /// The first `inline_cap` bytes seen (may be less if the stream was shorter).
    pub inline: Vec<u8>,
    /// `true` if the stream produced more than `inline_cap` bytes.
    pub truncated: bool,
    /// Total number of bytes teed to the log (regardless of the inline cap).
    pub total_bytes: u64,
}

impl StreamCapture {
    /// Reconstruct a capture from already-persisted bytes (used to recover
    /// output after a host-side wall-clock timeout drops the live stream).
    #[must_use]
    pub fn from_bytes(data: &[u8], cap: usize) -> Self {
        let take = data.len().min(cap);
        Self {
            inline: data[..take].to_vec(),
            truncated: data.len() > cap,
            total_bytes: data.len() as u64,
        }
    }

    /// Lossy UTF-8 rendering of the in-memory (capped) portion.
    #[must_use]
    pub fn lossy_string(&self) -> String {
        String::from_utf8_lossy(&self.inline).into_owned()
    }
}

/// Result of a completed [`AgentClient::exec`].
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    /// Process exit code (`None` if terminated by a signal).
    pub exit_code: Option<i32>,
    /// Terminating signal, if any.
    pub signal: Option<i32>,
    /// Guest-reported wall time of the exec in milliseconds.
    pub duration_ms: u64,
    /// `true` if the in-guest `timeout_ms` fired.
    pub timed_out: bool,
    /// Captured stdout.
    pub stdout: StreamCapture,
    /// Captured stderr.
    pub stderr: StreamCapture,
}

/// A reconnect-per-request RPC client for one guest agent.
///
/// Cheap to construct and clone-free; every method opens its own vsock
/// connection, so a single [`AgentClient`] can be reused for a VM's whole
/// lifetime and across snapshot restores.
#[derive(Debug)]
pub struct AgentClient {
    uds_path: PathBuf,
    next_id: AtomicU64,
}

impl AgentClient {
    /// Create a client bound to a Firecracker hybrid-vsock host UDS path.
    #[must_use]
    pub fn new(uds_path: impl Into<PathBuf>) -> Self {
        Self {
            uds_path: uds_path.into(),
            next_id: AtomicU64::new(1),
        }
    }

    /// The host-side UDS path this client connects through.
    #[must_use]
    pub fn uds_path(&self) -> &Path {
        &self.uds_path
    }

    /// Retry `connect + ping` with a fixed ~50 ms backoff until `timeout`.
    ///
    /// This is the boot/resume readiness signal: the guest agent may not be
    /// listening on the vsock port yet during early boot, so connection refusals
    /// are retried. A [`AgentError::ProtoMismatch`] or
    /// [`AgentError::OverlayDegraded`] is fatal and returned immediately (the
    /// agent *is* up — just incompatible, or on the wrong rootfs).
    ///
    /// # Errors
    /// [`AgentError::NotReady`] if no successful ping lands within `timeout`,
    /// [`AgentError::ProtoMismatch`] on a version disagreement, or
    /// [`AgentError::OverlayDegraded`] if the guest's stage-overlay root failed
    /// to assemble.
    pub async fn wait_ready(&self, timeout: Duration) -> Result<Pong, AgentError> {
        const BACKOFF: Duration = Duration::from_millis(50);
        let deadline = Instant::now() + timeout;
        loop {
            match self.ping().await {
                Ok(pong) => return Ok(pong),
                Err(e @ (AgentError::ProtoMismatch { .. } | AgentError::OverlayDegraded(_))) => {
                    return Err(e)
                }
                Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(AgentError::NotReady(timeout));
            }
            tokio::time::sleep(BACKOFF).await;
        }
    }

    /// Liveness + version handshake.
    ///
    /// # Errors
    /// [`AgentError::ProtoMismatch`] if the guest speaks a different protocol
    /// version, [`AgentError::OverlayDegraded`] if the guest reports it failed
    /// to assemble its stage-overlay root (it is running on the read-only base
    /// root — executing there would hit the wrong filesystem, finding #26), or
    /// a connect/framing error.
    pub async fn ping(&self) -> Result<Pong, AgentError> {
        match self.request_one(RequestOp::Ping).await? {
            ResponseBody::Pong {
                agent_version,
                proto_version,
                uptime_s,
                overlay_error,
            } => {
                if proto_version != PROTO_VERSION {
                    return Err(AgentError::ProtoMismatch {
                        expected: PROTO_VERSION,
                        got: proto_version,
                    });
                }
                if let Some(message) = overlay_error {
                    return Err(AgentError::OverlayDegraded(message));
                }
                Ok(Pong {
                    agent_version,
                    proto_version,
                    uptime_s,
                })
            }
            ResponseBody::Error { message } => Err(AgentError::Guest(message)),
            other => Err(unexpected("ping", &other)),
        }
    }

    /// Push the host's current `CLOCK_REALTIME` to the guest.
    ///
    /// WSL2 guests resume with a stale wall clock (PLAN risk #6), so this is
    /// called on every boot/resume.
    ///
    /// # Errors
    /// A connect/framing error, or [`AgentError::Guest`] if the guest refused.
    pub async fn sync_clock_now(&self) -> Result<(), AgentError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let op = RequestOp::SyncClock {
            unix_secs: now.as_secs(),
            nanos: now.subsec_nanos(),
        };
        self.expect_ok("sync_clock", op).await
    }

    /// Reconfigure the guest's IPv4 networking at runtime (post snapshot-resume).
    ///
    /// A warm-pool snapshot bakes in the *build-time* slot's addressing (slot 0's
    /// `10.107.0.2/30`). When that snapshot is resumed into a different netns slot
    /// its NIC backend is retargeted to the claimed slot's host tap via a
    /// `network_overrides`, but the guest still carries the stale IP — so nothing
    /// would route (each slot is a distinct `/30`). This pushes the claimed slot's
    /// `ip`/`gw`/`dns` so the guest re-IPs `eth0` into the correct subnet and NAT
    /// egress works, exactly analogous to the clock resync
    /// ([`sync_clock_now`](Self::sync_clock_now)) every resume also performs.
    ///
    /// `ip_cidr` is the guest CIDR (`10.107.<i>.2/30`), `gw` the host side
    /// (`10.107.<i>.1`, empty string ⇒ leave the default route cleared), and `dns`
    /// the resolver list written to the guest's `/etc/resolv.conf`.
    ///
    /// # Errors
    /// A connect/framing error, or [`AgentError::Guest`] if the guest could not
    /// apply the config (an unparseable address, or a missing NIC).
    pub async fn configure_net(
        &self,
        ip_cidr: &str,
        gw: &str,
        dns: &[String],
    ) -> Result<(), AgentError> {
        let op = RequestOp::ConfigureNet {
            ip: ip_cidr.to_string(),
            gw: gw.to_string(),
            dns: dns.to_vec(),
        };
        self.expect_ok("configure_net", op).await
    }

    /// Run a command, teeing streamed output to the log files named in `spec`.
    ///
    /// # Errors
    /// [`AgentError::ExecIncomplete`] if the connection dies before `ExecDone`
    /// (with the byte counts seen so far), [`AgentError::Guest`] if the guest
    /// reports a spawn failure, or a connect/framing/IO error.
    pub async fn exec(&self, spec: ExecSpec) -> Result<ExecOutcome, AgentError> {
        let mut stream = self.connect().await?;
        let op = RequestOp::Exec(ExecRequest {
            argv: spec.argv,
            env: spec.env,
            cwd: spec.cwd,
            timeout_ms: spec.timeout_ms,
            stdin_b64: spec.stdin.as_deref().map(b64_encode),
        });
        self.write_request(&mut stream, op).await?;

        let mut out = StreamSink::create(&spec.stdout_log, spec.inline_cap).await?;
        let mut err = StreamSink::create(&spec.stderr_log, spec.inline_cap).await?;

        loop {
            let frame = frame::aio::read_frame::<_, Response>(&mut stream)
                .await
                .map_err(|e| self.frame_err(e))?;
            let Some(resp) = frame else {
                out.flush().await?;
                err.flush().await?;
                return Err(AgentError::ExecIncomplete {
                    stdout_bytes: out.total,
                    stderr_bytes: err.total,
                    reason: "connection closed before ExecDone".to_string(),
                });
            };
            match resp.body {
                ResponseBody::ExecStream {
                    stream: kind,
                    data_b64,
                } => {
                    let (sink, label) = match kind {
                        ExecStreamKind::Stdout => (&mut out, "stdout"),
                        ExecStreamKind::Stderr => (&mut err, "stderr"),
                    };
                    let bytes = b64_decode(&data_b64).map_err(|e| AgentError::BadChunk {
                        stream: label,
                        detail: e.to_string(),
                    })?;
                    sink.write(&bytes).await?;
                }
                ResponseBody::ExecDone {
                    exit_code,
                    signal,
                    duration_ms,
                    timed_out,
                } => {
                    out.flush().await?;
                    err.flush().await?;
                    return Ok(ExecOutcome {
                        exit_code,
                        signal,
                        duration_ms,
                        timed_out,
                        stdout: out.finish(),
                        stderr: err.finish(),
                    });
                }
                ResponseBody::Error { message } => {
                    out.flush().await?;
                    err.flush().await?;
                    return Err(AgentError::Guest(message));
                }
                other => return Err(unexpected("exec", &other)),
            }
        }
    }

    /// Ask the guest to `sync` (optionally) and power off.
    ///
    /// The guest severs the vsock connection as it powers down, so an `Ok`
    /// answer, a clean EOF, or a reset immediately afterwards are all treated as
    /// success. Only a guest-reported error or a malformed frame is surfaced.
    ///
    /// # Errors
    /// [`AgentError::Guest`] if the guest explicitly refused, or a non-I/O
    /// framing error.
    pub async fn halt(&self, sync: bool) -> Result<(), AgentError> {
        let mut stream = self.connect().await?;
        let id = self.next_id();
        let req = Request {
            id,
            op: RequestOp::Halt { sync },
        };
        if let Err(e) = frame::aio::write_frame(&mut stream, &req).await {
            // A broken pipe here just means the guest raced us to power off.
            return match e {
                FrameError::Io(_) => Ok(()),
                other => Err(self.frame_err(other)),
            };
        }
        match frame::aio::read_frame::<_, Response>(&mut stream).await {
            Ok(Some(resp)) => match resp.body {
                ResponseBody::Ok => Ok(()),
                ResponseBody::Error { message } => Err(AgentError::Guest(message)),
                other => Err(unexpected("halt", &other)),
            },
            Ok(None) => Ok(()),               // clean EOF right after Halt
            Err(FrameError::Io(_)) => Ok(()), // connection reset as guest powers off
            Err(other) => Err(self.frame_err(other)),
        }
    }

    /// Write a file into the guest.
    ///
    /// # Errors
    /// [`AgentError::Guest`] on a guest-side failure, or a connect/framing error.
    pub async fn put_file(&self, path: &str, mode: u32, data: &[u8]) -> Result<(), AgentError> {
        let op = RequestOp::PutFile {
            path: path.to_string(),
            mode,
            data_b64: b64_encode(data),
        };
        self.expect_ok("put_file", op).await
    }

    /// Read a file from the guest (refusing more than `max_bytes`).
    ///
    /// # Errors
    /// [`AgentError::Guest`] on a guest-side failure, or a connect/framing error.
    pub async fn get_file(&self, path: &str, max_bytes: u64) -> Result<GetFile, AgentError> {
        let op = RequestOp::GetFile {
            path: path.to_string(),
            max_bytes,
        };
        match self.request_one(op).await? {
            ResponseBody::File { data_b64, mode } => {
                let bytes = b64_decode(&data_b64).map_err(|e| AgentError::BadChunk {
                    stream: "file",
                    detail: e.to_string(),
                })?;
                Ok(GetFile { bytes, mode })
            }
            ResponseBody::Error { message } => Err(AgentError::Guest(message)),
            other => Err(unexpected("get_file", &other)),
        }
    }

    /// Set the guest's hostname to the VM's vanity name. Re-sent on every warm
    /// resume (exactly like [`configure_net`](Self::configure_net) and
    /// [`sync_clock_now`](Self::sync_clock_now)) because the snapshot bakes the
    /// builder VM's name.
    ///
    /// # Errors
    /// [`AgentError::Guest`] on a guest-side failure, or a connect/framing error.
    pub async fn set_hostname(&self, name: &str) -> Result<(), AgentError> {
        let op = RequestOp::SetHostname {
            name: name.to_string(),
        };
        self.expect_ok("set_hostname", op).await
    }

    /// Stream a guest file to `dest` on the host (`FileChunk`* then one
    /// `FileDone`), refusing guest files larger than `max_bytes`. Unlike
    /// [`get_file`](Self::get_file) the file never has to fit in one frame, so
    /// this is the artifact-extraction channel for build outputs (finding #21).
    /// The guest file's mode bits are applied to the host copy (the exec bit
    /// matters for binaries).
    ///
    /// # Errors
    /// [`AgentError::Guest`] if the guest refused (missing file, over
    /// `max_bytes`) or failed mid-stream, [`AgentError::Unexpected`] if the byte
    /// count disagrees with `FileDone` (file changed mid-copy) or the connection
    /// died, or a connect/framing/IO error. On any error the partial host file
    /// is removed.
    pub async fn copy_out(
        &self,
        guest_path: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<CopyOutcome, AgentError> {
        let mut stream = self.connect().await?;
        let op = RequestOp::CopyOut {
            path: guest_path.to_string(),
            max_bytes,
        };
        self.write_request(&mut stream, op).await?;

        let mut file = tokio::fs::File::create(dest)
            .await
            .map_err(io_err(format!("creating copy-out dest {}", dest.display())))?;
        let mut written: u64 = 0;
        let result = loop {
            let frame = frame::aio::read_frame::<_, Response>(&mut stream)
                .await
                .map_err(|e| self.frame_err(e));
            let resp = match frame {
                Ok(Some(resp)) => resp,
                Ok(None) => {
                    break Err(AgentError::Unexpected(format!(
                        "connection closed mid copy-out after {written} bytes"
                    )));
                }
                Err(e) => break Err(e),
            };
            match resp.body {
                ResponseBody::FileChunk { data_b64 } => {
                    let bytes = b64_decode(&data_b64).map_err(|e| AgentError::BadChunk {
                        stream: "file",
                        detail: e.to_string(),
                    })?;
                    match file.write_all(&bytes).await {
                        Ok(()) => written = written.saturating_add(bytes.len() as u64),
                        Err(e) => {
                            break Err(
                                io_err(format!("writing copy-out dest {}", dest.display()))(e),
                            );
                        }
                    }
                }
                ResponseBody::FileDone { total_bytes, mode } => {
                    if written != total_bytes {
                        break Err(AgentError::Unexpected(format!(
                            "copy-out streamed {written} bytes but the guest reported \
                             {total_bytes} (file changed mid-copy?)"
                        )));
                    }
                    if let Err(e) = file.flush().await {
                        break Err(io_err(format!("flushing copy-out dest {}", dest.display()))(e));
                    }
                    break Ok(CopyOutcome { total_bytes, mode });
                }
                ResponseBody::Error { message } => break Err(AgentError::Guest(message)),
                other => break Err(unexpected("copy_out", &other)),
            }
        };
        if result.is_ok() {
            use std::os::unix::fs::PermissionsExt;
            let mode = result.as_ref().map(|c| c.mode).unwrap_or(0o644);
            let _ = tokio::fs::set_permissions(dest, std::fs::Permissions::from_mode(mode)).await;
        } else {
            let _ = tokio::fs::remove_file(dest).await;
        }
        result
    }

    // -- internals ----------------------------------------------------------

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn frame_err(&self, source: FrameError) -> AgentError {
        AgentError::Frame {
            path: self.uds_path.display().to_string(),
            source,
        }
    }

    async fn connect(&self) -> Result<UnixStream, AgentError> {
        isopod_fc::vsock::connect_to_guest(&self.uds_path, VSOCK_PORT)
            .await
            .map_err(|source| AgentError::Connect {
                path: self.uds_path.display().to_string(),
                source,
            })
    }

    async fn write_request(
        &self,
        stream: &mut UnixStream,
        op: RequestOp,
    ) -> Result<(), AgentError> {
        let req = Request {
            id: self.next_id(),
            op,
        };
        frame::aio::write_frame(stream, &req)
            .await
            .map_err(|e| self.frame_err(e))
    }

    /// One request, exactly one response frame.
    async fn request_one(&self, op: RequestOp) -> Result<ResponseBody, AgentError> {
        let mut stream = self.connect().await?;
        self.write_request(&mut stream, op).await?;
        match frame::aio::read_frame::<_, Response>(&mut stream)
            .await
            .map_err(|e| self.frame_err(e))?
        {
            Some(resp) => Ok(resp.body),
            None => Err(AgentError::Unexpected(
                "connection closed before a response was received".to_string(),
            )),
        }
    }

    /// A one-request op whose only success answer is `Ok`.
    async fn expect_ok(&self, label: &'static str, op: RequestOp) -> Result<(), AgentError> {
        match self.request_one(op).await? {
            ResponseBody::Ok => Ok(()),
            ResponseBody::Error { message } => Err(AgentError::Guest(message)),
            other => Err(unexpected(label, &other)),
        }
    }
}

/// Describe an unexpected response body for error messages.
fn unexpected(op: &str, body: &ResponseBody) -> AgentError {
    AgentError::Unexpected(format!("{} response to {op}", body_kind(body)))
}

/// A short label for a response variant.
fn body_kind(body: &ResponseBody) -> &'static str {
    match body {
        ResponseBody::Pong { .. } => "pong",
        ResponseBody::ExecStream { .. } => "exec_stream",
        ResponseBody::ExecDone { .. } => "exec_done",
        ResponseBody::Ok => "ok",
        ResponseBody::File { .. } => "file",
        ResponseBody::FileChunk { .. } => "file_chunk",
        ResponseBody::FileDone { .. } => "file_done",
        ResponseBody::Error { .. } => "error",
    }
}

/// Result of [`AgentClient::copy_out`]: what landed on the host.
#[derive(Debug, Clone, Copy)]
pub struct CopyOutcome {
    /// Total raw bytes streamed (the guest file's size).
    pub total_bytes: u64,
    /// Unix mode bits of the guest source file (applied to the host copy).
    pub mode: u32,
}

/// Tees a stream to a log file while retaining a capped in-memory head.
struct StreamSink {
    log: tokio::fs::File,
    path: PathBuf,
    inline: Vec<u8>,
    cap: usize,
    total: u64,
    truncated: bool,
}

impl StreamSink {
    async fn create(path: &Path, cap: usize) -> Result<Self, AgentError> {
        let log = tokio::fs::File::create(path)
            .await
            .map_err(io_err(format!("creating exec log {}", path.display())))?;
        Ok(Self {
            log,
            path: path.to_path_buf(),
            inline: Vec::new(),
            cap,
            total: 0,
            truncated: false,
        })
    }

    async fn write(&mut self, bytes: &[u8]) -> Result<(), AgentError> {
        self.log
            .write_all(bytes)
            .await
            .map_err(io_err(format!("writing exec log {}", self.path.display())))?;
        self.total = self.total.saturating_add(bytes.len() as u64);
        if self.inline.len() < self.cap {
            let room = self.cap - self.inline.len();
            if bytes.len() <= room {
                self.inline.extend_from_slice(bytes);
            } else {
                self.inline.extend_from_slice(&bytes[..room]);
                self.truncated = true;
            }
        } else if !bytes.is_empty() {
            self.truncated = true;
        }
        Ok(())
    }

    async fn flush(&mut self) -> Result<(), AgentError> {
        self.log
            .flush()
            .await
            .map_err(io_err(format!("flushing exec log {}", self.path.display())))
    }

    fn finish(self) -> StreamCapture {
        StreamCapture {
            inline: self.inline,
            truncated: self.truncated,
            total_bytes: self.total,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Accept one connection, perform the Firecracker host-side vsock handshake,
    /// and hand back the raw stream positioned at the first RPC frame.
    async fn accept_handshake(listener: &UnixListener) -> UnixStream {
        let (mut conn, _) = listener.accept().await.unwrap();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = conn.read(&mut b).await.unwrap();
            if n == 0 {
                break;
            }
            line.push(b[0]);
            if b[0] == b'\n' {
                break;
            }
        }
        assert!(line.starts_with(b"CONNECT "), "handshake: {line:?}");
        conn.write_all(b"OK 52\n").await.unwrap();
        conn
    }

    async fn read_req(conn: &mut UnixStream) -> Request {
        frame::aio::read_frame::<_, Request>(conn)
            .await
            .unwrap()
            .unwrap()
    }

    async fn write_resp(conn: &mut UnixStream, id: u64, body: ResponseBody) {
        frame::aio::write_frame(conn, &Response { id, body })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ping_ok_returns_pong() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            assert!(matches!(req.op, RequestOp::Ping));
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Pong {
                    agent_version: "9.9.9".into(),
                    proto_version: PROTO_VERSION,
                    uptime_s: 1.5,
                    overlay_error: None,
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let pong = client.ping().await.expect("ping ok");
        assert_eq!(pong.agent_version, "9.9.9");
        assert_eq!(pong.proto_version, PROTO_VERSION);
        assert_eq!(pong.uptime_s, 1.5);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ping_rejects_proto_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let bad = PROTO_VERSION + 7;
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Pong {
                    agent_version: "x".into(),
                    proto_version: bad,
                    uptime_s: 0.0,
                    overlay_error: None,
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let err = client.ping().await.expect_err("mismatch must error");
        match err {
            AgentError::ProtoMismatch { expected, got } => {
                assert_eq!(expected, PROTO_VERSION);
                assert_eq!(got, bad);
            }
            other => panic!("expected ProtoMismatch, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ping_rejects_degraded_overlay_root() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Pong {
                    agent_version: "x".into(),
                    proto_version: PROTO_VERSION,
                    uptime_s: 0.4,
                    overlay_error: Some("mount layer /dev/vdk at /layers/10: ENOENT".into()),
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let err = client.ping().await.expect_err("degraded root must error");
        match err {
            AgentError::OverlayDegraded(msg) => assert!(msg.contains("/layers/10"), "{msg}"),
            other => panic!("expected OverlayDegraded, got {other:?}"),
        }
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wait_ready_retries_until_the_agent_answers() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        // Bind the listener only after a short delay so the first connect
        // attempts fail and wait_ready must retry.
        let sock2 = sock.clone();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let listener = UnixListener::bind(&sock2).unwrap();
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Pong {
                    agent_version: "ok".into(),
                    proto_version: PROTO_VERSION,
                    uptime_s: 0.1,
                    overlay_error: None,
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let pong = client
            .wait_ready(Duration::from_secs(5))
            .await
            .expect("agent becomes ready");
        assert_eq!(pong.agent_version, "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wait_ready_times_out_when_nothing_listens() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let client = AgentClient::new(&sock);
        let err = client
            .wait_ready(Duration::from_millis(150))
            .await
            .expect_err("must time out");
        assert!(matches!(err, AgentError::NotReady(_)), "{err:?}");
    }

    #[tokio::test]
    async fn exec_streams_tee_and_truncate() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let out_log = dir.path().join("exec-stdout.log");
        let err_log = dir.path().join("exec-stderr.log");
        let listener = UnixListener::bind(&sock).unwrap();

        // A 20-byte stdout chunk (exceeds the 8-byte inline cap) + a 3-byte
        // stderr chunk, then ExecDone.
        let stdout_payload = b"0123456789abcdefghij".to_vec();
        let stderr_payload = b"err".to_vec();
        let sp = stdout_payload.clone();
        let ep = stderr_payload.clone();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            assert!(matches!(req.op, RequestOp::Exec(_)));
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::ExecStream {
                    stream: ExecStreamKind::Stdout,
                    data_b64: b64_encode(&sp),
                },
            )
            .await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::ExecStream {
                    stream: ExecStreamKind::Stderr,
                    data_b64: b64_encode(&ep),
                },
            )
            .await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::ExecDone {
                    exit_code: Some(0),
                    signal: None,
                    duration_ms: 5,
                    timed_out: false,
                },
            )
            .await;
        });

        let client = AgentClient::new(&sock);
        let outcome = client
            .exec(ExecSpec {
                argv: vec!["echo".into()],
                env: vec![],
                cwd: None,
                timeout_ms: Some(1000),
                stdin: None,
                stdout_log: out_log.clone(),
                stderr_log: err_log.clone(),
                inline_cap: 8,
            })
            .await
            .expect("exec ok");
        server.await.unwrap();

        assert_eq!(outcome.exit_code, Some(0));
        assert!(!outcome.timed_out);
        // stdout: capped to 8, truncated, full total.
        assert_eq!(outcome.stdout.inline, b"01234567");
        assert!(outcome.stdout.truncated);
        assert_eq!(outcome.stdout.total_bytes, 20);
        // stderr: fits, not truncated.
        assert_eq!(outcome.stderr.inline, b"err");
        assert!(!outcome.stderr.truncated);
        assert_eq!(outcome.stderr.total_bytes, 3);
        // Every byte was teed to the log files.
        assert_eq!(std::fs::read(&out_log).unwrap(), stdout_payload);
        assert_eq!(std::fs::read(&err_log).unwrap(), stderr_payload);
    }

    #[tokio::test]
    async fn exec_errors_when_connection_dies_before_done() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let out_log = dir.path().join("exec-stdout.log");
        let err_log = dir.path().join("exec-stderr.log");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::ExecStream {
                    stream: ExecStreamKind::Stdout,
                    data_b64: b64_encode(b"partial"),
                },
            )
            .await;
            // Drop without an ExecDone frame.
            drop(conn);
        });
        let client = AgentClient::new(&sock);
        let err = client
            .exec(ExecSpec {
                argv: vec!["x".into()],
                env: vec![],
                cwd: None,
                timeout_ms: None,
                stdin: None,
                stdout_log: out_log,
                stderr_log: err_log,
                inline_cap: 64,
            })
            .await
            .expect_err("must fail");
        server.await.unwrap();
        match err {
            AgentError::ExecIncomplete { stdout_bytes, .. } => assert_eq!(stdout_bytes, 7),
            other => panic!("expected ExecIncomplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn halt_tolerates_ok_then_eof() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            assert!(matches!(req.op, RequestOp::Halt { sync: true }));
            write_resp(&mut conn, req.id, ResponseBody::Ok).await;
            drop(conn); // guest powers off, severing the connection
        });
        let client = AgentClient::new(&sock);
        client
            .halt(true)
            .await
            .expect("halt tolerates EOF after Ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn halt_tolerates_connection_death_without_reply() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let _req = read_req(&mut conn).await;
            // Never reply; just drop as if powering off mid-answer.
            drop(conn);
        });
        let client = AgentClient::new(&sock);
        client
            .halt(true)
            .await
            .expect("halt tolerates a connection reset");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sync_clock_expects_ok() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            assert!(matches!(req.op, RequestOp::SyncClock { .. }));
            write_resp(&mut conn, req.id, ResponseBody::Ok).await;
        });
        let client = AgentClient::new(&sock);
        client.sync_clock_now().await.expect("sync ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn configure_net_sends_slot_addressing_and_expects_ok() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            match req.op {
                RequestOp::ConfigureNet { ip, gw, dns } => {
                    assert_eq!(ip, "10.107.3.2/30");
                    assert_eq!(gw, "10.107.3.1");
                    assert_eq!(dns, vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
                }
                other => panic!("expected ConfigureNet, got {other:?}"),
            }
            write_resp(&mut conn, req.id, ResponseBody::Ok).await;
        });
        let client = AgentClient::new(&sock);
        client
            .configure_net(
                "10.107.3.2/30",
                "10.107.3.1",
                &["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            )
            .await
            .expect("configure_net ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn configure_net_surfaces_guest_error() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Error {
                    message: "eth0 missing".into(),
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let err = client
            .configure_net("10.107.3.2/30", "10.107.3.1", &[])
            .await
            .expect_err("guest error must surface");
        assert!(matches!(err, AgentError::Guest(m) if m == "eth0 missing"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn get_file_decodes_payload() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            assert!(matches!(req.op, RequestOp::GetFile { .. }));
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::File {
                    data_b64: b64_encode(b"\x00\xffbytes"),
                    mode: 0o644,
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let file = client
            .get_file("/etc/hostname", 1024)
            .await
            .expect("get ok");
        assert_eq!(file.bytes, b"\x00\xffbytes");
        assert_eq!(file.mode, 0o644);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn guest_error_surfaces() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("vsock.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = accept_handshake(&listener).await;
            let req = read_req(&mut conn).await;
            write_resp(
                &mut conn,
                req.id,
                ResponseBody::Error {
                    message: "no such file".into(),
                },
            )
            .await;
        });
        let client = AgentClient::new(&sock);
        let err = client
            .get_file("/nope", 10)
            .await
            .expect_err("guest error must surface");
        assert!(matches!(err, AgentError::Guest(m) if m == "no such file"));
        server.await.unwrap();
    }

    #[test]
    fn stream_capture_from_bytes_caps_and_flags() {
        let cap = StreamCapture::from_bytes(b"hello world", 5);
        assert_eq!(cap.inline, b"hello");
        assert!(cap.truncated);
        assert_eq!(cap.total_bytes, 11);
        assert_eq!(cap.lossy_string(), "hello");

        let small = StreamCapture::from_bytes(b"hi", 5);
        assert_eq!(small.inline, b"hi");
        assert!(!small.truncated);
        assert_eq!(small.total_bytes, 2);
    }
}
