//! Typed HTTP client for the Firecracker management API over a unix socket.
//!
//! One [`FcClient`] talks to exactly one Firecracker process via its API
//! socket. A shared client must never be reused across VMs — it is bound to a
//! single socket path at construction, and a stray cross-VM call would silently
//! reconfigure the wrong microVM.
//!
//! ## Transport
//! Built on `reqwest`'s `ClientBuilder::unix_socket` (reqwest 0.13).
//! `unix_socket` is available on all unix targets with no extra Cargo feature.
//! Every request sets `Content-Type: application/json` **explicitly**: the M0
//! spike found that Firecracker `400`s a `PUT` with no content type and then
//! exits the process — so the header is mandatory, not merely conventional.
//!
//! ## Phase safety
//! The Firecracker API has pre-boot-only and post-boot-only endpoints that the
//! swagger does not express in the type system (e.g. `PUT /drives` is pre-boot
//! only, while `PATCH /drives/{id}` is a post-boot media change). This client
//! keeps a lightweight runtime [`Phase`] guard, updated from the calls it
//! issues, and rejects mis-sequenced operations locally with a
//! [`PhaseError`] instead of surfacing Firecracker's
//! terse `400`s. The guard is best-effort convenience, not a security boundary;
//! see [`FcClient::attach`] to bind to an already-running VM.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};

use reqwest::header::CONTENT_TYPE;
use reqwest::Method;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, PhaseError, Result};
use crate::models::{
    ApiErrorBody, Balloon, BalloonStats, BalloonUpdate, BootSource, Drive, FirecrackerVersion,
    FullVmConfiguration, InstanceActionInfo, InstanceInfo, MachineConfig, MmdsConfig,
    NetworkInterface, PartialDrive, SnapshotCreateParams, SnapshotLoadParams, Vm, VmState, Vsock,
};

/// The client's view of the microVM lifecycle.
///
/// Transitions are driven by the calls the client issues:
/// `Configuring` --[`instance_start`]--> `Running`,
/// `Running` <--[`pause`]/[`resume`]--> `Paused`, and
/// `Configuring` --[`load_snapshot`]--> `Running`/`Paused`.
///
/// [`instance_start`]: FcClient::instance_start
/// [`pause`]: FcClient::pause
/// [`resume`]: FcClient::resume
/// [`load_snapshot`]: FcClient::load_snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Phase {
    /// Pre-boot: resources may be configured; the VM is not yet started.
    Configuring = 0,
    /// The VM has been booted (or a snapshot resumed) and vCPUs are running.
    Running = 1,
    /// The VM is booted but its vCPUs are paused.
    Paused = 2,
}

impl Phase {
    fn from_u8(v: u8) -> Phase {
        match v {
            1 => Phase::Running,
            2 => Phase::Paused,
            _ => Phase::Configuring,
        }
    }
}

/// Typed client for a single Firecracker API socket.
///
/// Cheap to construct; holds a `reqwest::Client` bound to the socket and an
/// atomically tracked [`Phase`]. `Send + Sync`, so it may be shared behind an
/// `Arc` — though in practice one client serves one VM from one task.
#[derive(Debug)]
pub struct FcClient {
    http: reqwest::Client,
    base: String,
    socket_path: PathBuf,
    phase: AtomicU8,
}

impl FcClient {
    /// Binds a client to a Firecracker API socket in the **pre-boot** phase.
    ///
    /// Use this for a fresh Firecracker process you are about to configure (or
    /// restore a snapshot into).
    ///
    /// # Errors
    /// Returns [`Error::ClientBuild`] if the underlying HTTP client cannot be
    /// constructed.
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::with_phase(socket_path, Phase::Configuring)
    }

    /// Binds a client to an **already-running** Firecracker VM.
    ///
    /// Starts in the [`Phase::Running`] phase, so post-boot operations
    /// (`pause`, `send_ctrl_alt_del`, …) are permitted immediately. Use this to
    /// reconnect to a supervised process (e.g. for graceful shutdown) rather
    /// than to configure a fresh one.
    ///
    /// # Errors
    /// Returns [`Error::ClientBuild`] if the underlying HTTP client cannot be
    /// constructed.
    pub fn attach(socket_path: impl AsRef<Path>) -> Result<Self> {
        Self::with_phase(socket_path, Phase::Running)
    }

    fn with_phase(socket_path: impl AsRef<Path>, phase: Phase) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_path_buf();
        let http = reqwest::Client::builder()
            .unix_socket(socket_path.as_path())
            .build()
            .map_err(|source| Error::ClientBuild {
                path: socket_path.display().to_string(),
                source,
            })?;
        Ok(Self {
            http,
            // Host is a placeholder: unix_socket ignores DNS. Scheme is http
            // (no TLS over the local socket).
            base: "http://localhost".to_string(),
            socket_path,
            phase: AtomicU8::new(phase as u8),
        })
    }

    /// Returns the API socket path this client is bound to.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the client's current tracked [`Phase`].
    #[must_use]
    pub fn phase(&self) -> Phase {
        Phase::from_u8(self.phase.load(Ordering::SeqCst))
    }

    fn set_phase(&self, phase: Phase) {
        self.phase.store(phase as u8, Ordering::SeqCst);
    }

    // -- phase guards -------------------------------------------------------

    fn ensure_pre_boot(&self, method: &'static str) -> Result<()> {
        match self.phase() {
            Phase::Configuring => Ok(()),
            actual => Err(PhaseError::RequiresPreBoot { method, actual }.into()),
        }
    }

    fn ensure_post_boot(&self, method: &'static str) -> Result<()> {
        match self.phase() {
            Phase::Configuring => Err(PhaseError::RequiresPostBoot {
                method,
                actual: Phase::Configuring,
            }
            .into()),
            _ => Ok(()),
        }
    }

    fn ensure_running(&self, method: &'static str) -> Result<()> {
        match self.phase() {
            Phase::Running => Ok(()),
            actual => Err(PhaseError::RequiresRunning { method, actual }.into()),
        }
    }

    fn ensure_paused(&self, method: &'static str) -> Result<()> {
        match self.phase() {
            Phase::Paused => Ok(()),
            actual => Err(PhaseError::RequiresPaused { method, actual }.into()),
        }
    }

    // -- low-level request helpers -----------------------------------------

    /// Sends a request with a JSON body and expects an empty (2xx) response.
    async fn send_no_content<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: &B,
    ) -> Result<()> {
        let method_name = method.as_str().to_string();
        let resp = self.dispatch(method, path, Some(body)).await?;
        self.check_status(&method_name, path, resp).await?;
        Ok(())
    }

    /// Sends a GET and decodes a JSON response body.
    async fn get_json<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let resp = self.dispatch::<()>(Method::GET, path, None).await?;
        let resp = self.check_status("GET", path, resp).await?;
        resp.json::<R>().await.map_err(|source| Error::Decode {
            path: path.to_string(),
            source,
        })
    }

    async fn dispatch<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.base, path);
        // Content-Type is set on every request, including GETs: Firecracker
        // rejects PUTs without it (and then exits), and an explicit type on a
        // bodyless GET is harmless.
        let mut req = self
            .http
            .request(method, url)
            .header(CONTENT_TYPE, "application/json");
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body).map_err(|e| Error::Io {
                context: format!("serializing request body for {path}"),
                source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
            })?;
            req = req.body(bytes);
        }
        req.send().await.map_err(|source| Error::Transport {
            path: path.to_string(),
            source,
        })
    }

    /// Turns a non-2xx response into an [`Error::Api`], preserving Firecracker's
    /// `fault_message`.
    async fn check_status(
        &self,
        method: &str,
        path: &str,
        resp: reqwest::Response,
    ) -> Result<reqwest::Response> {
        if resp.status().is_success() {
            return Ok(resp);
        }
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let fault_message = serde_json::from_str::<ApiErrorBody>(&body)
            .ok()
            .and_then(|e| e.fault_message)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if body.is_empty() {
                    "<empty body>".to_string()
                } else {
                    body
                }
            });
        Err(Error::Api {
            method: method.to_string(),
            path: path.to_string(),
            status,
            fault_message,
        })
    }

    // -- pre-boot configuration --------------------------------------------

    /// `PUT /machine-config` — set vCPU count, memory size, etc. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if the VM is already started, or an
    /// [`Error::Api`]/[`Error::Transport`] on request failure.
    pub async fn put_machine_config(&self, cfg: &MachineConfig) -> Result<()> {
        self.ensure_pre_boot("put_machine_config")?;
        self.send_no_content(Method::PUT, "/machine-config", cfg)
            .await
    }

    /// `PUT /boot-source` — set the kernel image and command line. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_boot_source(&self, src: &BootSource) -> Result<()> {
        self.ensure_pre_boot("put_boot_source")?;
        self.send_no_content(Method::PUT, "/boot-source", src).await
    }

    /// `PUT /drives/{drive_id}` — attach or update a block device. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_drive(&self, drive: &Drive) -> Result<()> {
        self.ensure_pre_boot("put_drive")?;
        let path = format!("/drives/{}", drive.drive_id);
        self.send_no_content(Method::PUT, &path, drive).await
    }

    /// `PATCH /drives/{drive_id}` — media change / rate-limiter update. **Post-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPostBoot`] if the VM has not booted, else a request error.
    pub async fn patch_drive(&self, drive: &PartialDrive) -> Result<()> {
        self.ensure_post_boot("patch_drive")?;
        let path = format!("/drives/{}", drive.drive_id);
        self.send_no_content(Method::PATCH, &path, drive).await
    }

    /// `PUT /network-interfaces/{iface_id}` — attach a network interface. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        self.ensure_pre_boot("put_network_interface")?;
        let path = format!("/network-interfaces/{}", iface.iface_id);
        self.send_no_content(Method::PUT, &path, iface).await
    }

    /// `PUT /vsock` — configure the (single) vsock device. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_vsock(&self, vsock: &Vsock) -> Result<()> {
        self.ensure_pre_boot("put_vsock")?;
        self.send_no_content(Method::PUT, "/vsock", vsock).await
    }

    /// `PUT /balloon` — configure the memory balloon device. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_balloon(&self, balloon: &Balloon) -> Result<()> {
        self.ensure_pre_boot("put_balloon")?;
        self.send_no_content(Method::PUT, "/balloon", balloon).await
    }

    /// `PUT /mmds/config` — configure the MMDS network stack. **Pre-boot only.**
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn put_mmds_config(&self, cfg: &MmdsConfig) -> Result<()> {
        self.ensure_pre_boot("put_mmds_config")?;
        self.send_no_content(Method::PUT, "/mmds/config", cfg).await
    }

    // -- any-phase configuration -------------------------------------------

    /// `PATCH /balloon` — resize the balloon. Valid before or after boot.
    ///
    /// # Errors
    /// An [`Error::Api`]/[`Error::Transport`] on request failure.
    pub async fn patch_balloon(&self, update: &BalloonUpdate) -> Result<()> {
        self.send_no_content(Method::PATCH, "/balloon", update)
            .await
    }

    /// `PUT /mmds` — replace the MMDS data store with arbitrary JSON.
    ///
    /// # Errors
    /// An [`Error::Api`]/[`Error::Transport`] on request failure.
    pub async fn put_mmds(&self, data: &serde_json::Value) -> Result<()> {
        self.send_no_content(Method::PUT, "/mmds", data).await
    }

    // -- reads --------------------------------------------------------------

    /// `GET /balloon/statistics` — latest balloon stats (must have been enabled pre-boot).
    ///
    /// # Errors
    /// [`Error::Api`] `400` if statistics were not enabled, else a request error.
    pub async fn get_balloon_stats(&self) -> Result<BalloonStats> {
        self.get_json("/balloon/statistics").await
    }

    /// `GET /` — general instance information (id, state, version).
    ///
    /// # Errors
    /// An [`Error::Api`]/[`Error::Transport`]/[`Error::Decode`] on failure.
    pub async fn get_instance_info(&self) -> Result<InstanceInfo> {
        self.get_json("/").await
    }

    /// `GET /vm/config` — the full VM configuration.
    ///
    /// # Errors
    /// An [`Error::Api`]/[`Error::Transport`]/[`Error::Decode`] on failure.
    pub async fn get_full_config(&self) -> Result<FullVmConfiguration> {
        self.get_json("/vm/config").await
    }

    /// `GET /version` — the Firecracker build version.
    ///
    /// # Errors
    /// An [`Error::Api`]/[`Error::Transport`]/[`Error::Decode`] on failure.
    pub async fn get_version(&self) -> Result<FirecrackerVersion> {
        self.get_json("/version").await
    }

    // -- lifecycle / actions ------------------------------------------------

    /// `PUT /actions {InstanceStart}` — boot the configured microVM.
    ///
    /// On success the tracked phase advances to [`Phase::Running`].
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if already started, else a request error.
    pub async fn instance_start(&self) -> Result<()> {
        self.ensure_pre_boot("instance_start")?;
        self.send_no_content(
            Method::PUT,
            "/actions",
            &InstanceActionInfo::instance_start(),
        )
        .await?;
        self.set_phase(Phase::Running);
        Ok(())
    }

    /// `PUT /actions {SendCtrlAltDel}` — request an orderly guest shutdown (x86 reset line).
    ///
    /// # Errors
    /// [`PhaseError::RequiresRunning`] if the VM is not running, else a request error.
    pub async fn send_ctrl_alt_del(&self) -> Result<()> {
        self.ensure_running("send_ctrl_alt_del")?;
        self.send_no_content(
            Method::PUT,
            "/actions",
            &InstanceActionInfo::send_ctrl_alt_del(),
        )
        .await
    }

    /// `PATCH /vm {Paused}` — pause the vCPUs (prerequisite for a snapshot).
    ///
    /// On success the tracked phase becomes [`Phase::Paused`].
    ///
    /// # Errors
    /// [`PhaseError::RequiresRunning`] if the VM is not running, else a request error.
    pub async fn pause(&self) -> Result<()> {
        self.ensure_running("pause")?;
        self.send_no_content(
            Method::PATCH,
            "/vm",
            &Vm {
                state: VmState::Paused,
            },
        )
        .await?;
        self.set_phase(Phase::Paused);
        Ok(())
    }

    /// `PATCH /vm {Resumed}` — resume paused vCPUs.
    ///
    /// On success the tracked phase becomes [`Phase::Running`].
    ///
    /// # Errors
    /// [`PhaseError::RequiresPaused`] if the VM is not paused, else a request error.
    pub async fn resume(&self) -> Result<()> {
        self.ensure_paused("resume")?;
        self.send_no_content(
            Method::PATCH,
            "/vm",
            &Vm {
                state: VmState::Resumed,
            },
        )
        .await?;
        self.set_phase(Phase::Running);
        Ok(())
    }

    /// `PUT /snapshot/create` — write a snapshot. The VM must be **Paused**.
    ///
    /// # Errors
    /// [`PhaseError::RequiresPaused`] if the VM is not paused, else a request error.
    pub async fn create_snapshot(&self, params: &SnapshotCreateParams) -> Result<()> {
        self.ensure_paused("create_snapshot")?;
        self.send_no_content(Method::PUT, "/snapshot/create", params)
            .await
    }

    /// `PUT /snapshot/load` — restore a snapshot into this **fresh** process.
    ///
    /// Only valid on a newly-started Firecracker process before any other
    /// resource is configured. On success the tracked phase advances to
    /// [`Phase::Running`] if `resume_vm` was set, otherwise [`Phase::Paused`].
    ///
    /// # Errors
    /// [`PhaseError::RequiresPreBoot`] if the process is not fresh, else a request error.
    pub async fn load_snapshot(&self, params: &SnapshotLoadParams) -> Result<()> {
        self.ensure_pre_boot("load_snapshot")?;
        self.send_no_content(Method::PUT, "/snapshot/load", params)
            .await?;
        // resume_vm defaults to false when omitted.
        if params.resume_vm.unwrap_or(false) {
            self.set_phase(Phase::Running);
        } else {
            self.set_phase(Phase::Paused);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the phase guard purely locally — no socket required. The
    // client is bound to a non-existent socket; guards reject before any I/O.
    fn client_in(phase: Phase) -> FcClient {
        let path = std::env::temp_dir().join("isopod-fc-nonexistent.sock");
        FcClient::with_phase(path, phase).expect("client builds")
    }

    #[tokio::test]
    async fn pre_boot_guard_rejects_after_boot() {
        let c = client_in(Phase::Running);
        let err = c
            .put_machine_config(&MachineConfig::new(1, 128))
            .await
            .expect_err("should be rejected");
        assert!(matches!(
            err,
            Error::Phase(PhaseError::RequiresPreBoot {
                method: "put_machine_config",
                actual: Phase::Running
            })
        ));
    }

    #[tokio::test]
    async fn post_boot_guard_rejects_before_boot() {
        let c = client_in(Phase::Configuring);
        let err = c
            .patch_drive(&PartialDrive {
                drive_id: "rootfs".into(),
                path_on_host: Some("/x".into()),
                rate_limiter: None,
            })
            .await
            .expect_err("should be rejected");
        assert!(matches!(
            err,
            Error::Phase(PhaseError::RequiresPostBoot {
                method: "patch_drive",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn pause_requires_running_resume_requires_paused() {
        let configuring = client_in(Phase::Configuring);
        assert!(matches!(
            configuring.pause().await,
            Err(Error::Phase(PhaseError::RequiresRunning { .. }))
        ));

        let running = client_in(Phase::Running);
        assert!(matches!(
            running.resume().await,
            Err(Error::Phase(PhaseError::RequiresPaused { .. }))
        ));
    }

    #[tokio::test]
    async fn create_snapshot_requires_paused() {
        let c = client_in(Phase::Running);
        assert!(matches!(
            c.create_snapshot(&SnapshotCreateParams::full("/s", "/m"))
                .await,
            Err(Error::Phase(PhaseError::RequiresPaused { .. }))
        ));
    }

    #[test]
    fn phase_accessor_reflects_construction() {
        assert_eq!(client_in(Phase::Configuring).phase(), Phase::Configuring);
        assert_eq!(client_in(Phase::Running).phase(), Phase::Running);
    }
}
