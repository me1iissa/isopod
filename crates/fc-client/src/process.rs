//! Supervision of a Firecracker child process.
//!
//! [`FcProcess::spawn`] launches a Firecracker binary with an API socket,
//! optionally in its own command wrapper (e.g. a future `ip netns exec <ns>`
//! prefix), waits for the API socket to become connectable, and hands back a
//! handle whose [`Drop`] and [`shutdown`](FcProcess::shutdown) tear the whole
//! process group down cleanly.
//!
//! The child is started with `kill_on_drop(true)` and its own process group
//! (`process_group(0)`), so an abandoned handle never leaks a running VM, and
//! [`shutdown`](FcProcess::shutdown) can `SIGKILL` the entire group rather than
//! just the direct child.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::time::Instant;

use crate::client::FcClient;
use crate::error::{Error, Result};
use crate::id::VmId;

/// Default time to wait for the API socket to appear after spawning.
pub const DEFAULT_SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Firecracker log verbosity for the `--level` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and above.
    Warning,
    /// Informational (Firecracker default).
    Info,
    /// Debug and above.
    Debug,
    /// Everything.
    Trace,
    /// Logging off.
    Off,
}

impl LogLevel {
    /// The string Firecracker's `--level` flag expects.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Error => "Error",
            LogLevel::Warning => "Warning",
            LogLevel::Info => "Info",
            LogLevel::Debug => "Debug",
            LogLevel::Trace => "Trace",
            LogLevel::Off => "Off",
        }
    }
}

/// How the child's stdout/stderr are wired.
///
/// The guest serial console is relayed to the Firecracker process stdout, so
/// the choice here also determines where guest serial output goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StdioMode {
    /// Inherit the parent's stdout/stderr (guest serial appears on our console).
    #[default]
    Inherit,
    /// Discard stdout/stderr (`/dev/null`).
    Null,
    /// Capture via pipes (readable through the [`Child`] handle after spawn).
    Piped,
}

impl StdioMode {
    fn to_stdio(self) -> Stdio {
        match self {
            StdioMode::Inherit => Stdio::inherit(),
            StdioMode::Null => Stdio::null(),
            StdioMode::Piped => Stdio::piped(),
        }
    }
}

/// Configuration for launching a Firecracker process.
///
/// Construct with [`FcProcessConfig::new`] then chain the builder methods.
#[derive(Debug, Clone)]
pub struct FcProcessConfig {
    firecracker_bin: PathBuf,
    api_sock: PathBuf,
    id: Option<VmId>,
    log_path: Option<PathBuf>,
    log_level: Option<LogLevel>,
    command_prefix: Vec<String>,
    socket_timeout: Duration,
    stdio: StdioMode,
    extra_args: Vec<String>,
}

impl FcProcessConfig {
    /// Creates a config for `firecracker_bin` listening on `api_sock`.
    pub fn new(firecracker_bin: impl Into<PathBuf>, api_sock: impl Into<PathBuf>) -> Self {
        Self {
            firecracker_bin: firecracker_bin.into(),
            api_sock: api_sock.into(),
            id: None,
            log_path: None,
            log_level: None,
            command_prefix: Vec::new(),
            socket_timeout: DEFAULT_SOCKET_TIMEOUT,
            stdio: StdioMode::default(),
            extra_args: Vec::new(),
        }
    }

    /// Sets the `--id` (validated; avoids the dot-in-id `SIGABRT`).
    #[must_use]
    pub fn id(mut self, id: VmId) -> Self {
        self.id = Some(id);
        self
    }

    /// Sets `--log-path`.
    #[must_use]
    pub fn log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.log_path = Some(path.into());
        self
    }

    /// Sets `--level`.
    #[must_use]
    pub fn log_level(mut self, level: LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Sets a command wrapper prefix, e.g. `["ip", "netns", "exec", "ns0"]`.
    ///
    /// The Firecracker binary and its flags are appended after this prefix.
    /// Plumbed for the M4 networking milestone; empty by default.
    #[must_use]
    pub fn command_prefix(mut self, prefix: Vec<String>) -> Self {
        self.command_prefix = prefix;
        self
    }

    /// Overrides how long [`FcProcess::spawn`] waits for the API socket.
    #[must_use]
    pub fn socket_timeout(mut self, timeout: Duration) -> Self {
        self.socket_timeout = timeout;
        self
    }

    /// Sets how the child's stdout/stderr (and thus guest serial) are wired.
    #[must_use]
    pub fn stdio(mut self, mode: StdioMode) -> Self {
        self.stdio = mode;
        self
    }

    /// Appends extra raw arguments to the Firecracker command line
    /// (e.g. `--no-api` is *not* wanted, but `--boot-timer` might be).
    #[must_use]
    pub fn extra_args(mut self, args: Vec<String>) -> Self {
        self.extra_args = args;
        self
    }

    /// Builds the full argv: `[prefix..., firecracker_bin, flags...]`.
    fn build_argv(&self) -> Vec<String> {
        let mut argv = self.command_prefix.clone();
        argv.push(self.firecracker_bin.to_string_lossy().into_owned());
        argv.push("--api-sock".to_string());
        argv.push(self.api_sock.to_string_lossy().into_owned());
        if let Some(id) = &self.id {
            argv.push("--id".to_string());
            argv.push(id.as_str().to_string());
        }
        if let Some(log_path) = &self.log_path {
            argv.push("--log-path".to_string());
            argv.push(log_path.to_string_lossy().into_owned());
        }
        if let Some(level) = self.log_level {
            argv.push("--level".to_string());
            argv.push(level.as_str().to_string());
        }
        argv.extend(self.extra_args.iter().cloned());
        argv
    }
}

/// A running (or exited) supervised Firecracker process.
#[derive(Debug)]
pub struct FcProcess {
    child: Child,
    config: FcProcessConfig,
}

impl FcProcess {
    /// Spawns Firecracker and waits for its API socket to become connectable.
    ///
    /// A stale socket file at the configured path is removed first. If
    /// Firecracker exits before the socket appears (e.g. a bad `--id`), this
    /// returns [`Error::SocketTimeout`] carrying the exit status rather than
    /// hanging until the timeout.
    ///
    /// # Errors
    /// [`Error::Spawn`] if the process cannot be launched, or
    /// [`Error::SocketTimeout`] if the socket never becomes ready.
    pub async fn spawn(config: FcProcessConfig) -> Result<Self> {
        // Remove a stale socket so bind() succeeds and readiness detection is
        // not fooled by a leftover file.
        if let Err(e) = tokio::fs::remove_file(&config.api_sock).await {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(Error::Io {
                    context: format!("removing stale API socket {}", config.api_sock.display()),
                    source: e,
                });
            }
        }

        let argv = config.build_argv();
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.stdin(Stdio::null());
        cmd.stdout(config.stdio.to_stdio());
        cmd.stderr(config.stdio.to_stdio());
        cmd.kill_on_drop(true);
        // Own process group so shutdown() can signal the whole group.
        cmd.process_group(0);

        let child = cmd.spawn().map_err(|source| Error::Spawn {
            program: argv[0].clone(),
            source,
        })?;

        let mut process = FcProcess { child, config };
        process.wait_for_socket().await?;
        Ok(process)
    }

    /// Polls until the API socket is connectable, the child exits, or timeout.
    async fn wait_for_socket(&mut self) -> Result<()> {
        let deadline = Instant::now() + self.config.socket_timeout;
        let sock = self.config.api_sock.clone();
        loop {
            // If the process already exited, fail fast with its status.
            if let Some(status) = self.try_wait()? {
                return Err(Error::SocketTimeout {
                    path: sock.display().to_string(),
                    timeout_ms: self.config.socket_timeout.as_millis() as u64,
                    exit: Some(status.to_string()),
                });
            }
            // A successful connect means Firecracker has bound and is listening.
            if tokio::net::UnixStream::connect(&sock).await.is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::SocketTimeout {
                    path: sock.display().to_string(),
                    timeout_ms: self.config.socket_timeout.as_millis() as u64,
                    exit: None,
                });
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Returns the API socket path.
    #[must_use]
    pub fn api_socket(&self) -> &Path {
        &self.config.api_sock
    }

    /// Returns the VM id, if one was set.
    #[must_use]
    pub fn id(&self) -> Option<&VmId> {
        self.config.id.as_ref()
    }

    /// Returns the OS process id, if the process has not been reaped.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Mutable access to the underlying tokio [`Child`] (for capturing piped
    /// stdout/stderr, sending signals, etc.).
    pub fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    /// Builds a pre-boot [`FcClient`] bound to this process's API socket.
    ///
    /// # Errors
    /// [`Error::ClientBuild`] if the HTTP client cannot be constructed.
    pub fn client(&self) -> Result<FcClient> {
        FcClient::connect(&self.config.api_sock)
    }

    /// Waits for the process to exit.
    ///
    /// # Errors
    /// [`Error::Io`] if waiting on the child fails.
    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        self.child.wait().await.map_err(|source| Error::Io {
            context: "waiting for Firecracker to exit".to_string(),
            source,
        })
    }

    /// Returns the exit status if the process has already exited, else `None`.
    ///
    /// # Errors
    /// [`Error::Io`] if the wait syscall fails.
    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child.try_wait().map_err(|source| Error::Io {
            context: "polling Firecracker exit status".to_string(),
            source,
        })
    }

    /// Gracefully shuts the VM down, then forcibly if needed.
    ///
    /// Sequence: if still running, attempt a `SendCtrlAltDel` (bounded by
    /// `graceful_timeout`) and wait for a clean exit; if that does not land in
    /// time, `SIGKILL` the whole process group. The API socket file is removed
    /// on the way out.
    ///
    /// # Errors
    /// [`Error::Io`] if reaping the child fails. Failure to send Ctrl+Alt+Del
    /// is not an error (the process may already be gone) and falls through to
    /// the forced kill.
    pub async fn shutdown(
        &mut self,
        graceful_timeout: Duration,
    ) -> Result<std::process::ExitStatus> {
        if let Some(status) = self.try_wait()? {
            self.remove_socket();
            return Ok(status);
        }

        // Best-effort graceful shutdown via the guest reset line.
        if let Ok(client) = FcClient::attach(&self.config.api_sock) {
            let _ = tokio::time::timeout(graceful_timeout, client.send_ctrl_alt_del()).await;
        }

        // Give the guest a moment to halt on its own.
        if let Ok(Ok(status)) = tokio::time::timeout(graceful_timeout, self.child.wait()).await {
            self.remove_socket();
            return Ok(status);
        }

        // Force: SIGKILL the whole group, then reap.
        self.kill_group();
        let status = self.wait().await?;
        self.remove_socket();
        Ok(status)
    }

    /// Sends `SIGKILL` to the process group led by the child, if still alive.
    fn kill_group(&self) {
        if let Some(pid) = self.child.id() {
            // The child leads its own group (process_group(0)); negating the
            // pid targets every member of that group.
            // SAFETY: kill() with a valid pid and signal is always safe to call.
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    }

    fn remove_socket(&self) {
        let _ = std::fs::remove_file(&self.config.api_sock);
    }
}

impl Drop for FcProcess {
    fn drop(&mut self) {
        // kill_on_drop(true) reaps the direct child, but we also flatten the
        // whole group (belt and suspenders for wrapped commands) and unlink the
        // socket so a re-spawn at the same path is clean.
        self.kill_group();
        self.remove_socket();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_minimal() {
        let cfg = FcProcessConfig::new("/usr/bin/firecracker", "/run/vm.sock");
        assert_eq!(
            cfg.build_argv(),
            vec!["/usr/bin/firecracker", "--api-sock", "/run/vm.sock"]
        );
    }

    #[test]
    fn argv_with_id_and_logging() {
        let cfg = FcProcessConfig::new("/usr/bin/firecracker", "/run/vm.sock")
            .id(VmId::new("vm-7").unwrap())
            .log_path("/tmp/vm.log")
            .log_level(LogLevel::Debug);
        assert_eq!(
            cfg.build_argv(),
            vec![
                "/usr/bin/firecracker",
                "--api-sock",
                "/run/vm.sock",
                "--id",
                "vm-7",
                "--log-path",
                "/tmp/vm.log",
                "--level",
                "Debug",
            ]
        );
    }

    #[test]
    fn argv_with_command_prefix() {
        // The M4 netns wrapper shape: prefix precedes the binary.
        let cfg = FcProcessConfig::new("/usr/bin/firecracker", "/run/vm.sock")
            .command_prefix(vec![
                "ip".into(),
                "netns".into(),
                "exec".into(),
                "ns0".into(),
            ])
            .id(VmId::new("vm0").unwrap());
        assert_eq!(
            cfg.build_argv(),
            vec![
                "ip",
                "netns",
                "exec",
                "ns0",
                "/usr/bin/firecracker",
                "--api-sock",
                "/run/vm.sock",
                "--id",
                "vm0",
            ]
        );
    }

    #[tokio::test]
    async fn spawn_reports_exit_when_binary_bad() {
        // `/bin/false` exits 1 immediately and never creates a socket; spawn
        // must surface that as a SocketTimeout carrying the exit status rather
        // than blocking for the full timeout.
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let cfg = FcProcessConfig::new("/bin/false", &sock)
            .socket_timeout(Duration::from_secs(5))
            .stdio(StdioMode::Null);
        let err = FcProcess::spawn(cfg).await.expect_err("should fail");
        match err {
            Error::SocketTimeout { exit: Some(_), .. } => {}
            other => panic!("expected SocketTimeout with exit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spawn_fails_cleanly_for_missing_binary() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("api.sock");
        let cfg = FcProcessConfig::new("/nonexistent/firecracker-xyz", &sock);
        let err = FcProcess::spawn(cfg).await.expect_err("should fail");
        assert!(matches!(err, Error::Spawn { .. }));
    }
}
