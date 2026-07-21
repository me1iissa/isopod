//! Serde models for the Firecracker management API.
//!
//! These are hand-written and pinned to the Firecracker **v1.16.1** Swagger 2.0
//! definition (`firecracker.yaml`). Field names, casing and enum spellings are
//! taken verbatim from that document — the JSON wire format is what matters, so
//! the Rust type names occasionally differ from the swagger `definitions` names
//! for readability (e.g. [`MachineConfig`] ↔ `MachineConfiguration`).
//!
//! Every optional field on a request body is annotated
//! `#[serde(skip_serializing_if = "Option::is_none")]` so a `PUT`/`PATCH` sends
//! only the fields the caller actually set — Firecracker treats an omitted
//! optional as "use the default", but rejects some explicit `null`s.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// machine-config
// ---------------------------------------------------------------------------

/// Machine configuration (`MachineConfiguration`): vCPU count, memory size and
/// related knobs. Body of `PUT /machine-config` (pre-boot only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineConfig {
    /// Number of vCPUs. Must be 1 or an even number in `[1, 32]`.
    pub vcpu_count: u32,
    /// Guest memory size in MiB.
    pub mem_size_mib: u64,
    /// Enable simultaneous multithreading (x86 only). Defaults to `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smt: Option<bool>,
    /// Deprecated CPU template. Defaults to `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_template: Option<CpuTemplate>,
    /// Enable dirty-page tracking (required to create diff snapshots).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_dirty_pages: Option<bool>,
    /// Huge-page backing for guest memory. Defaults to `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub huge_pages: Option<HugePages>,
}

impl MachineConfig {
    /// Convenience constructor for the common case (no SMT, no template).
    #[must_use]
    pub fn new(vcpu_count: u32, mem_size_mib: u64) -> Self {
        Self {
            vcpu_count,
            mem_size_mib,
            smt: None,
            cpu_template: None,
            track_dirty_pages: None,
            huge_pages: None,
        }
    }

    /// Sets dirty-page tracking (needed before a diff snapshot can be taken).
    #[must_use]
    pub fn with_track_dirty_pages(mut self, track: bool) -> Self {
        self.track_dirty_pages = Some(track);
        self
    }
}

/// Deprecated CPU template (`CpuTemplate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuTemplate {
    /// Intel C3 template.
    C3,
    /// Intel T2 template.
    T2,
    /// Intel T2S template.
    T2S,
    /// Intel T2CL template.
    T2CL,
    /// Intel T2A template.
    T2A,
    /// ARM V1N1 template.
    V1N1,
    /// No template (default).
    None,
}

/// Huge-page configuration for guest memory (`MachineConfiguration.huge_pages`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HugePages {
    /// Back guest memory with normal 4 KiB pages (default).
    None,
    /// Back guest memory with 2 MiB huge pages.
    #[serde(rename = "2M")]
    Hp2M,
}

// ---------------------------------------------------------------------------
// boot-source
// ---------------------------------------------------------------------------

/// Boot source (`BootSource`): kernel image and command line. Body of
/// `PUT /boot-source` (pre-boot only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootSource {
    /// Host path to the uncompressed ELF `vmlinux` kernel image.
    pub kernel_image_path: String,
    /// Kernel command line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_args: Option<String>,
    /// Host path to an optional initrd image.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
}

impl BootSource {
    /// Constructs a boot source with a kernel path and command line.
    #[must_use]
    pub fn new(kernel_image_path: impl Into<String>, boot_args: impl Into<String>) -> Self {
        Self {
            kernel_image_path: kernel_image_path.into(),
            boot_args: Some(boot_args.into()),
            initrd_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// drives
// ---------------------------------------------------------------------------

/// Block device (`Drive`). Body of `PUT /drives/{drive_id}` (pre-boot only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drive {
    /// Unique drive id (also the `{drive_id}` path parameter).
    pub drive_id: String,
    /// Whether this drive is the root device.
    pub is_root_device: bool,
    /// Boot partition UUID; only honoured when `is_root_device` is true.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partuuid: Option<String>,
    /// Block-device caching strategy. Defaults to `Unsafe`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_type: Option<CacheType>,
    /// Whether the block device is read-only (virtio-block only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_read_only: Option<bool>,
    /// Host path to the backing file (virtio-block only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_on_host: Option<String>,
    /// Optional IO rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
    /// IO engine. `Async` requires host kernel > 5.10.51. Defaults to `Sync`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_engine: Option<IoEngine>,
    /// vhost-user-block backend socket (mutually exclusive with `path_on_host`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<String>,
}

impl Drive {
    /// Constructs a virtio-block drive backed by a host file.
    #[must_use]
    pub fn virtio(
        drive_id: impl Into<String>,
        path_on_host: impl Into<String>,
        is_root_device: bool,
        is_read_only: bool,
    ) -> Self {
        Self {
            drive_id: drive_id.into(),
            is_root_device,
            partuuid: None,
            cache_type: None,
            is_read_only: Some(is_read_only),
            path_on_host: Some(path_on_host.into()),
            rate_limiter: None,
            io_engine: None,
            socket: None,
        }
    }
}

/// Block-device caching strategy (`Drive.cache_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CacheType {
    /// No explicit flushing (default).
    Unsafe,
    /// Writeback caching (issues flushes on guest request).
    Writeback,
}

/// Block-device IO engine (`Drive.io_engine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IoEngine {
    /// Synchronous IO (default).
    Sync,
    /// Asynchronous IO (`io_uring`; host kernel > 5.10.51).
    Async,
}

/// Partial drive (`PartialDrive`). Body of `PATCH /drives/{drive_id}`
/// (post-boot media change / rate-limiter update).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialDrive {
    /// Drive id to update (also the `{drive_id}` path parameter).
    pub drive_id: String,
    /// New backing file path (media change).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_on_host: Option<String>,
    /// Updated rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

// ---------------------------------------------------------------------------
// network interfaces
// ---------------------------------------------------------------------------

/// Network interface (`NetworkInterface`). Body of
/// `PUT /network-interfaces/{iface_id}` (pre-boot only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    /// Interface id (also the `{iface_id}` path parameter).
    pub iface_id: String,
    /// Host tap device name.
    pub host_dev_name: String,
    /// Guest-visible MAC address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<String>,
    /// MTU advertised to the guest via `VIRTIO_NET_F_MTU` (68..=65535).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    /// Receive-direction rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limiter: Option<RateLimiter>,
    /// Transmit-direction rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limiter: Option<RateLimiter>,
}

impl NetworkInterface {
    /// Constructs an interface binding `iface_id` to host tap `host_dev_name`.
    #[must_use]
    pub fn new(iface_id: impl Into<String>, host_dev_name: impl Into<String>) -> Self {
        Self {
            iface_id: iface_id.into(),
            host_dev_name: host_dev_name.into(),
            guest_mac: None,
            mtu: None,
            rx_rate_limiter: None,
            tx_rate_limiter: None,
        }
    }
}

/// Partial network interface (`PartialNetworkInterface`). Body of
/// `PATCH /network-interfaces/{iface_id}` (post-boot rate-limiter update).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialNetworkInterface {
    /// Interface id to update.
    pub iface_id: String,
    /// Updated receive rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_rate_limiter: Option<RateLimiter>,
    /// Updated transmit rate limiter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_rate_limiter: Option<RateLimiter>,
}

// ---------------------------------------------------------------------------
// vsock
// ---------------------------------------------------------------------------

/// Vsock device (`Vsock`). Body of `PUT /vsock` (pre-boot only).
///
/// On the host, Firecracker exposes a hybrid vsock: it listens on `uds_path`
/// for host-initiated connections (issue `CONNECT <port>\n`), and expects the
/// host to be listening on `uds_path_<PORT>` for guest-initiated connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vsock {
    /// Guest context id (>= 3).
    pub guest_cid: u32,
    /// Host path to the backing unix domain socket.
    pub uds_path: String,
    /// Deprecated device id; retained for wire compatibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock_id: Option<String>,
}

impl Vsock {
    /// Constructs a vsock device with the given guest CID and host socket path.
    #[must_use]
    pub fn new(guest_cid: u32, uds_path: impl Into<String>) -> Self {
        Self {
            guest_cid,
            uds_path: uds_path.into(),
            vsock_id: None,
        }
    }
}

// ---------------------------------------------------------------------------
// balloon
// ---------------------------------------------------------------------------

/// Balloon device (`Balloon`). Body of `PUT /balloon` (pre-boot only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balloon {
    /// Target balloon size in MiB.
    pub amount_mib: u32,
    /// Whether the balloon deflates under guest memory pressure.
    pub deflate_on_oom: bool,
    /// Statistics polling interval in seconds. Non-zero enables statistics.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_polling_interval_s: Option<u32>,
    /// Whether free-page hinting is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_page_hinting: Option<bool>,
    /// Whether free-page reporting is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_page_reporting: Option<bool>,
}

/// Balloon update (`BalloonUpdate`). Body of `PATCH /balloon`
/// (before or after boot).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonUpdate {
    /// New target balloon size in MiB.
    pub amount_mib: u32,
}

/// Balloon statistics (`BalloonStats`). Returned by `GET /balloon/statistics`.
///
/// Only available if `stats_polling_interval_s` was non-zero at configuration
/// time. All counters are `i64` to mirror the swagger's `int64` fields and to
/// robustly accept whatever the guest driver reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalloonStats {
    /// Target number of pages the device aims to hold.
    pub target_pages: i64,
    /// Actual number of pages the device is holding.
    pub actual_pages: i64,
    /// Target amount of memory (MiB) the device aims to hold.
    pub target_mib: i64,
    /// Actual amount of memory (MiB) the device is holding.
    pub actual_mib: i64,
    /// Memory swapped in (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_in: Option<i64>,
    /// Memory swapped out to disk (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_out: Option<i64>,
    /// Major page faults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major_faults: Option<i64>,
    /// Minor page faults.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor_faults: Option<i64>,
    /// Memory not used for any purpose (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub free_memory: Option<i64>,
    /// Total memory available (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_memory: Option<i64>,
    /// Estimated available memory (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_memory: Option<i64>,
    /// Reclaimable disk-cache memory (bytes).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_caches: Option<i64>,
    /// Successful hugetlb allocations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_allocations: Option<i64>,
    /// Failed hugetlb allocations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hugetlb_failures: Option<i64>,
    /// OOM-killer invocations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill: Option<i64>,
    /// Allocation slow-path stalls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alloc_stall: Option<i64>,
    /// Memory scanned asynchronously.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub async_scan: Option<i64>,
    /// Memory scanned directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_scan: Option<i64>,
    /// Memory reclaimed asynchronously.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub async_reclaim: Option<i64>,
    /// Memory reclaimed directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_reclaim: Option<i64>,
}

// ---------------------------------------------------------------------------
// rate limiting
// ---------------------------------------------------------------------------

/// IO rate limiter (`RateLimiter`) with independent bandwidth and ops buckets.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RateLimiter {
    /// Token bucket measured in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucket>,
    /// Token bucket measured in operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucket>,
}

/// Token bucket (`TokenBucket`) for a rate limiter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenBucket {
    /// Total number of tokens the bucket can hold.
    pub size: u64,
    /// Milliseconds it takes for the bucket to refill.
    pub refill_time: u64,
    /// Initial one-time burst budget.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub one_time_burst: Option<u64>,
}

// ---------------------------------------------------------------------------
// snapshots
// ---------------------------------------------------------------------------

/// Snapshot creation parameters (`SnapshotCreateParams`). Body of
/// `PUT /snapshot/create` (VM must be `Paused`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    /// Host path for the guest-memory file to be written.
    pub mem_file_path: String,
    /// Host path for the microVM state file to be written.
    pub snapshot_path: String,
    /// Snapshot type. Defaults to `Full` when omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_type: Option<SnapshotType>,
}

impl SnapshotCreateParams {
    /// Full snapshot (self-contained memory + state).
    #[must_use]
    pub fn full(snapshot_path: impl Into<String>, mem_file_path: impl Into<String>) -> Self {
        Self {
            mem_file_path: mem_file_path.into(),
            snapshot_path: snapshot_path.into(),
            snapshot_type: Some(SnapshotType::Full),
        }
    }

    /// Diff snapshot (only pages dirtied since the base; requires
    /// `track_dirty_pages`).
    #[must_use]
    pub fn diff(snapshot_path: impl Into<String>, mem_file_path: impl Into<String>) -> Self {
        Self {
            mem_file_path: mem_file_path.into(),
            snapshot_path: snapshot_path.into(),
            snapshot_type: Some(SnapshotType::Diff),
        }
    }
}

/// Snapshot type (`SnapshotCreateParams.snapshot_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotType {
    /// Full snapshot: a complete copy of guest memory.
    Full,
    /// Diff snapshot: only pages dirtied since the previous snapshot.
    Diff,
}

/// Snapshot load parameters (`SnapshotLoadParams`). Body of
/// `PUT /snapshot/load` (only on a fresh, pre-boot Firecracker process).
///
/// Exactly one of [`mem_backend`](Self::mem_backend) (preferred) or the
/// deprecated `mem_file_path` must be present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLoadParams {
    /// Host path to the microVM state file to load.
    pub snapshot_path: String,
    /// Memory backend (File or Uffd). Preferred over `mem_file_path`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_backend: Option<MemoryBackend>,
    /// Deprecated: direct path to the memory file (use `mem_backend` instead).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_file_path: Option<String>,
    /// Resume the vCPUs immediately after a successful load.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_vm: Option<bool>,
    /// Enable dirty-page tracking on the restored VM (for later diff snapshots).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_dirty_pages: Option<bool>,
    /// Deprecated alias of `track_dirty_pages`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_diff_snapshots: Option<bool>,
    /// Override the host tap device of one or more interfaces on restore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_overrides: Option<Vec<NetworkOverride>>,
    /// Override the vsock backing socket path on restore.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vsock_override: Option<VsockOverride>,
    /// x86_64 only: advance kvmclock by wall-clock elapsed since the snapshot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clock_realtime: Option<bool>,
}

impl SnapshotLoadParams {
    /// Loads from a `File`-backed memory snapshot, resuming the VM.
    ///
    /// This is the fast warm-pool restore path: the memory file is `mmap`ed
    /// `MAP_PRIVATE`, so paging is lazy and the load API returns quickly.
    #[must_use]
    pub fn file_backed(
        snapshot_path: impl Into<String>,
        mem_file_path: impl Into<String>,
        resume_vm: bool,
    ) -> Self {
        Self {
            snapshot_path: snapshot_path.into(),
            mem_backend: Some(MemoryBackend {
                backend_type: BackendType::File,
                backend_path: mem_file_path.into(),
            }),
            mem_file_path: None,
            resume_vm: Some(resume_vm),
            track_dirty_pages: None,
            enable_diff_snapshots: None,
            network_overrides: None,
            vsock_override: None,
            clock_realtime: None,
        }
    }

    /// Adds network host-device overrides (for restoring into a fresh netns slot).
    #[must_use]
    pub fn with_network_overrides(mut self, overrides: Vec<NetworkOverride>) -> Self {
        self.network_overrides = Some(overrides);
        self
    }

    /// Overrides the vsock backing socket path on restore.
    #[must_use]
    pub fn with_vsock_override(mut self, uds_path: impl Into<String>) -> Self {
        self.vsock_override = Some(VsockOverride {
            uds_path: uds_path.into(),
        });
        self
    }
}

/// Memory backend for snapshot restore (`MemoryBackend`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryBackend {
    /// Whether the memory is served from a file or a UFFD handler.
    pub backend_type: BackendType,
    /// File path (File) or UDS path of the UFFD handler (Uffd).
    pub backend_path: String,
}

/// Snapshot memory backend type (`MemoryBackend.backend_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    /// Memory served directly from a file (`mmap`).
    File,
    /// Memory served lazily by a userfaultfd handler process.
    Uffd,
}

/// Network override on restore (`NetworkOverride`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkOverride {
    /// Id of the interface to rebind.
    pub iface_id: String,
    /// New host tap device name.
    pub host_dev_name: String,
}

/// Vsock override on restore (`VsockOverride`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockOverride {
    /// New host path for the backing unix domain socket.
    pub uds_path: String,
}

// ---------------------------------------------------------------------------
// vm state
// ---------------------------------------------------------------------------

/// microVM run-state target (`Vm`). Body of `PATCH /vm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vm {
    /// Desired state.
    pub state: VmState,
}

/// Desired microVM run state (`Vm.state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmState {
    /// Pause the vCPUs.
    Paused,
    /// Resume the vCPUs.
    Resumed,
}

// ---------------------------------------------------------------------------
// actions
// ---------------------------------------------------------------------------

/// Instance action (`InstanceActionInfo`). Body of `PUT /actions`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceActionInfo {
    /// The action to perform.
    pub action_type: ActionType,
}

impl InstanceActionInfo {
    /// Boots the configured microVM (pre-boot only).
    #[must_use]
    pub fn instance_start() -> Self {
        Self {
            action_type: ActionType::InstanceStart,
        }
    }

    /// Sends a Ctrl+Alt+Del to the guest (post-boot; x86 reset line).
    #[must_use]
    pub fn send_ctrl_alt_del() -> Self {
        Self {
            action_type: ActionType::SendCtrlAltDel,
        }
    }

    /// Flushes the metrics.
    #[must_use]
    pub fn flush_metrics() -> Self {
        Self {
            action_type: ActionType::FlushMetrics,
        }
    }
}

/// Action type (`InstanceActionInfo.action_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Flush the metrics to the configured sink.
    FlushMetrics,
    /// Boot the configured microVM.
    InstanceStart,
    /// Send a Ctrl+Alt+Del to the guest.
    SendCtrlAltDel,
}

// ---------------------------------------------------------------------------
// instance info / version / full config
// ---------------------------------------------------------------------------

/// Instance information (`InstanceInfo`). Returned by `GET /`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInfo {
    /// Application name (`Firecracker`).
    pub app_name: String,
    /// microVM / instance id.
    pub id: String,
    /// Current lifecycle state.
    pub state: InstanceState,
    /// Hypervisor build version.
    pub vmm_version: String,
}

/// Firecracker's own view of the instance state (`InstanceInfo.state`).
///
/// Note this is Firecracker's read-only report; it is distinct from the
/// client-side [`Phase`](crate::client::Phase) guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstanceState {
    /// The VM has not been started yet.
    #[serde(rename = "Not started")]
    NotStarted,
    /// The VM is running.
    Running,
    /// The VM is paused.
    Paused,
}

impl InstanceState {
    /// Returns true if Firecracker reports the VM as `Running`.
    #[must_use]
    pub fn is_running(self) -> bool {
        matches!(self, InstanceState::Running)
    }
}

/// Firecracker version (`FirecrackerVersion`). Returned by `GET /version`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirecrackerVersion {
    /// Build version string (e.g. `1.16.1`).
    pub firecracker_version: String,
}

/// Full VM configuration (`FullVmConfiguration`). Returned by `GET /vm/config`.
///
/// The devices isopod models directly are typed; the remaining device
/// configurations (logger, metrics, cpu-config, mmds-config, memory-hotplug,
/// pmem, entropy) are surfaced as raw [`serde_json::Value`] so the client stays
/// forward-compatible without modelling every device.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FullVmConfiguration {
    /// Balloon device configuration, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balloon: Option<Balloon>,
    /// All block devices.
    #[serde(default)]
    pub drives: Vec<Drive>,
    /// Boot source (empty when restored from a snapshot).
    #[serde(
        default,
        rename = "boot-source",
        skip_serializing_if = "Option::is_none"
    )]
    pub boot_source: Option<BootSource>,
    /// Machine configuration.
    #[serde(
        default,
        rename = "machine-config",
        skip_serializing_if = "Option::is_none"
    )]
    pub machine_config: Option<MachineConfig>,
    /// All network interfaces.
    #[serde(default, rename = "network-interfaces")]
    pub network_interfaces: Vec<NetworkInterface>,
    /// Vsock device configuration, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vsock: Option<Vsock>,
    /// Raw MMDS configuration.
    #[serde(
        default,
        rename = "mmds-config",
        skip_serializing_if = "Option::is_none"
    )]
    pub mmds_config: Option<serde_json::Value>,
    /// Raw CPU configuration.
    #[serde(
        default,
        rename = "cpu-config",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_config: Option<serde_json::Value>,
    /// Raw logger configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logger: Option<serde_json::Value>,
    /// Raw metrics configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<serde_json::Value>,
    /// Raw hotpluggable-memory configuration.
    #[serde(
        default,
        rename = "memory-hotplug",
        skip_serializing_if = "Option::is_none"
    )]
    pub memory_hotplug: Option<serde_json::Value>,
    /// Raw pmem device configurations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pmem: Vec<serde_json::Value>,
    /// Raw entropy device configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// mmds
// ---------------------------------------------------------------------------

/// MMDS network configuration (`MmdsConfig`). Body of `PUT /mmds/config`
/// (pre-boot only). Minimal: covers the fields isopod needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdsConfig {
    /// Ids of the network interfaces allowed to reach the MMDS.
    pub network_interfaces: Vec<String>,
    /// MMDS version. Defaults to `V1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<MmdsVersion>,
    /// Link-local IPv4 address of the MMDS. Defaults to `169.254.169.254`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    /// Operate compatibly with EC2 IMDS (`text/plain` responses).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imds_compat: Option<bool>,
}

/// MMDS version (`MmdsConfig.version`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MmdsVersion {
    /// MMDS version 1.
    V1,
    /// MMDS version 2 (token-authenticated).
    V2,
}

// ---------------------------------------------------------------------------
// error body
// ---------------------------------------------------------------------------

/// The API error body (`Error`) returned by Firecracker on failure.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ApiErrorBody {
    /// Human-readable description of the error condition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Round-trips a value through JSON and asserts it equals `expected_json`.
    fn assert_serializes<T: Serialize>(value: &T, expected: serde_json::Value) {
        let got = serde_json::to_value(value).expect("serialize");
        assert_eq!(got, expected);
    }

    #[test]
    fn machine_config_omits_unset_optionals() {
        // Matches the swagger example / M0 PUT body.
        assert_serializes(
            &MachineConfig::new(1, 256),
            json!({"vcpu_count": 1, "mem_size_mib": 256}),
        );
    }

    #[test]
    fn machine_config_full_roundtrip() {
        let cfg = MachineConfig {
            vcpu_count: 2,
            mem_size_mib: 1024,
            smt: Some(false),
            cpu_template: Some(CpuTemplate::None),
            track_dirty_pages: Some(true),
            huge_pages: Some(HugePages::Hp2M),
        };
        let v = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            v,
            json!({
                "vcpu_count": 2,
                "mem_size_mib": 1024,
                "smt": false,
                "cpu_template": "None",
                "track_dirty_pages": true,
                "huge_pages": "2M"
            })
        );
        let back: MachineConfig = serde_json::from_value(v).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn boot_source_matches_m0_body() {
        assert_serializes(
            &BootSource::new("/img/vmlinux-6.18.36", "console=ttyS0 quiet"),
            json!({
                "kernel_image_path": "/img/vmlinux-6.18.36",
                "boot_args": "console=ttyS0 quiet"
            }),
        );
    }

    #[test]
    fn drive_matches_m0_rootfs_body() {
        // Exactly the M0 rootfs PUT body.
        assert_serializes(
            &Drive::virtio("rootfs", "/img/rootfs.ext4", true, true),
            json!({
                "drive_id": "rootfs",
                "is_root_device": true,
                "is_read_only": true,
                "path_on_host": "/img/rootfs.ext4"
            }),
        );
    }

    #[test]
    fn drive_with_cache_io_and_rate_limiter() {
        let d = Drive {
            drive_id: "scratch".into(),
            is_root_device: false,
            partuuid: None,
            cache_type: Some(CacheType::Writeback),
            is_read_only: Some(false),
            path_on_host: Some("/img/scratch.ext4".into()),
            rate_limiter: Some(RateLimiter {
                bandwidth: Some(TokenBucket {
                    size: 1_048_576,
                    refill_time: 1000,
                    one_time_burst: Some(524_288),
                }),
                ops: None,
            }),
            io_engine: Some(IoEngine::Async),
            socket: None,
        };
        let v = serde_json::to_value(&d).unwrap();
        assert_eq!(
            v,
            json!({
                "drive_id": "scratch",
                "is_root_device": false,
                "cache_type": "Writeback",
                "is_read_only": false,
                "path_on_host": "/img/scratch.ext4",
                "rate_limiter": {
                    "bandwidth": {"size": 1048576, "refill_time": 1000, "one_time_burst": 524288}
                },
                "io_engine": "Async"
            })
        );
        let back: Drive = serde_json::from_value(v).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn partial_drive_media_change() {
        assert_serializes(
            &PartialDrive {
                drive_id: "rootfs".into(),
                path_on_host: Some("/img/new.ext4".into()),
                rate_limiter: None,
            },
            json!({"drive_id": "rootfs", "path_on_host": "/img/new.ext4"}),
        );
    }

    #[test]
    fn network_interface_roundtrip() {
        assert_serializes(
            &NetworkInterface::new("eth0", "isopod-tap0"),
            json!({"iface_id": "eth0", "host_dev_name": "isopod-tap0"}),
        );
    }

    #[test]
    fn vsock_roundtrip() {
        assert_serializes(
            &Vsock::new(3, "/run/vm/vsock.sock"),
            json!({"guest_cid": 3, "uds_path": "/run/vm/vsock.sock"}),
        );
    }

    #[test]
    fn balloon_and_update() {
        assert_serializes(
            &Balloon {
                amount_mib: 128,
                deflate_on_oom: true,
                stats_polling_interval_s: Some(1),
                free_page_hinting: None,
                free_page_reporting: None,
            },
            json!({"amount_mib": 128, "deflate_on_oom": true, "stats_polling_interval_s": 1}),
        );
        assert_serializes(&BalloonUpdate { amount_mib: 64 }, json!({"amount_mib": 64}));
    }

    #[test]
    fn balloon_stats_deserialize_partial() {
        // Guest drivers may omit the extended int64 counters.
        let v = json!({
            "target_pages": 65536,
            "actual_pages": 65536,
            "target_mib": 256,
            "actual_mib": 256,
            "free_memory": 12345678
        });
        let stats: BalloonStats = serde_json::from_value(v).unwrap();
        assert_eq!(stats.actual_mib, 256);
        assert_eq!(stats.free_memory, Some(12_345_678));
        assert_eq!(stats.swap_in, None);
    }

    #[test]
    fn snapshot_create_full_and_diff() {
        assert_serializes(
            &SnapshotCreateParams::full("/snap/vm.state", "/snap/vm.mem"),
            json!({
                "mem_file_path": "/snap/vm.mem",
                "snapshot_path": "/snap/vm.state",
                "snapshot_type": "Full"
            }),
        );
        assert_serializes(
            &SnapshotCreateParams::diff("/snap/vm.state", "/snap/vm.diff"),
            json!({
                "mem_file_path": "/snap/vm.diff",
                "snapshot_path": "/snap/vm.state",
                "snapshot_type": "Diff"
            }),
        );
    }

    #[test]
    fn snapshot_load_file_backend() {
        // The warm-pool restore body.
        assert_serializes(
            &SnapshotLoadParams::file_backed("/snap/vm.state", "/snap/vm.mem", true),
            json!({
                "snapshot_path": "/snap/vm.state",
                "mem_backend": {"backend_type": "File", "backend_path": "/snap/vm.mem"},
                "resume_vm": true
            }),
        );
    }

    #[test]
    fn snapshot_load_with_overrides() {
        let params = SnapshotLoadParams::file_backed("/s/state", "/s/mem", true)
            .with_network_overrides(vec![NetworkOverride {
                iface_id: "eth0".into(),
                host_dev_name: "isopod-tap7".into(),
            }])
            .with_vsock_override("/run/slot7/vsock.sock");
        let v = serde_json::to_value(&params).unwrap();
        assert_eq!(
            v,
            json!({
                "snapshot_path": "/s/state",
                "mem_backend": {"backend_type": "File", "backend_path": "/s/mem"},
                "resume_vm": true,
                "network_overrides": [{"iface_id": "eth0", "host_dev_name": "isopod-tap7"}],
                "vsock_override": {"uds_path": "/run/slot7/vsock.sock"}
            })
        );
    }

    #[test]
    fn vm_state_patch() {
        assert_serializes(
            &Vm {
                state: VmState::Paused,
            },
            json!({"state": "Paused"}),
        );
        assert_serializes(
            &Vm {
                state: VmState::Resumed,
            },
            json!({"state": "Resumed"}),
        );
    }

    #[test]
    fn action_bodies() {
        assert_serializes(
            &InstanceActionInfo::instance_start(),
            json!({"action_type": "InstanceStart"}),
        );
        assert_serializes(
            &InstanceActionInfo::send_ctrl_alt_del(),
            json!({"action_type": "SendCtrlAltDel"}),
        );
    }

    #[test]
    fn instance_info_deserialize() {
        let v = json!({
            "app_name": "Firecracker",
            "id": "vm-1",
            "state": "Not started",
            "vmm_version": "1.16.1"
        });
        let info: InstanceInfo = serde_json::from_value(v).unwrap();
        assert_eq!(info.state, InstanceState::NotStarted);
        assert!(!info.state.is_running());

        let running: InstanceInfo = serde_json::from_value(json!({
            "app_name": "Firecracker", "id": "vm-1", "state": "Running", "vmm_version": "1.16.1"
        }))
        .unwrap();
        assert!(running.state.is_running());
    }

    #[test]
    fn version_deserialize() {
        let v: FirecrackerVersion =
            serde_json::from_value(json!({"firecracker_version": "1.16.1"})).unwrap();
        assert_eq!(v.firecracker_version, "1.16.1");
    }

    #[test]
    fn full_vm_config_partial_deserialize() {
        // GET /vm/config with only some devices present.
        let v = json!({
            "machine-config": {"vcpu_count": 1, "mem_size_mib": 256, "smt": false},
            "boot-source": {"kernel_image_path": "/img/vmlinux", "boot_args": "quiet"},
            "drives": [{"drive_id": "rootfs", "is_root_device": true, "is_read_only": true, "path_on_host": "/img/rootfs.ext4"}],
            "network-interfaces": [],
            "logger": {"level": "Info"}
        });
        let cfg: FullVmConfiguration = serde_json::from_value(v).unwrap();
        assert_eq!(cfg.machine_config.as_ref().unwrap().vcpu_count, 1);
        assert_eq!(cfg.drives.len(), 1);
        assert!(cfg.network_interfaces.is_empty());
        assert!(cfg.vsock.is_none());
        assert!(cfg.logger.is_some());
    }

    #[test]
    fn mmds_config_serialize() {
        assert_serializes(
            &MmdsConfig {
                network_interfaces: vec!["eth0".into()],
                version: Some(MmdsVersion::V2),
                ipv4_address: None,
                imds_compat: None,
            },
            json!({"network_interfaces": ["eth0"], "version": "V2"}),
        );
    }

    #[test]
    fn error_body_deserialize() {
        let e: ApiErrorBody = serde_json::from_value(json!({"fault_message": "boom"})).unwrap();
        assert_eq!(e.fault_message.as_deref(), Some("boom"));
    }
}
