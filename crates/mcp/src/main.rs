//! isopod MCP server — an rmcp 2.2 stdio server exposing isopod's ephemeral
//! microVM sandbox to Claude Code (and any MCP client) over JSON-RPC.
//!
//! Convention (see PLAN.md): isopod's persistence model is *stages*, not
//! long-lived sandboxes, so v1 has no live-session tools. [`Isopod::sandbox_run`]
//! is the core primitive — boot an ephemeral Firecracker microVM, exec one
//! command over vsock, optionally commit the result as a content-addressed
//! stage, and destroy the VM. The remaining tools inspect and prune the stage
//! store ([`Isopod::stage_list`]/[`Isopod::stage_info`]/[`Isopod::stage_rm`]) and
//! the recorded VM directories ([`Isopod::vm_list`]/[`Isopod::vm_gc`]).
//!
//! Each tool is a thin async shim over a synchronous `isopod_core` function.
//! Because [`isopod_core::vm::run_ephemeral`] builds its own tokio runtime
//! internally, it is invoked from [`tokio::task::spawn_blocking`]; calling it
//! directly on the async executor would panic (runtime-in-runtime).
//!
//! The MCP transport is line-delimited JSON-RPC on stdout, so all diagnostics go
//! to **stderr** — writing logs to stdout would corrupt the protocol stream.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    Implementation, Meta, ProgressNotificationParam, ServerCapabilities, ServerInfo,
};
use rmcp::{
    tool, tool_handler, tool_router, ErrorData, Json, Peer, RoleServer, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use isopod_core::image::RootfsFlavor;
use isopod_core::stage::{self, StageMeta};
use isopod_core::vm::{self, RunOptions, RunReport};

/// Server instructions surfaced to the MCP client at initialize time. Kept under
/// 2 KiB and front-loaded with trigger phrases (tool-search reads this to decide
/// when to reach for isopod).
const INSTRUCTIONS: &str = "\
Use isopod to run or experiment with shell commands and code inside a disposable, \
hardware-isolated Firecracker microVM — a fast (~0.4 s boot) sandbox that is destroyed after \
each call. Reach for `sandbox_run` whenever you want to execute code without touching the \
host: trying a snippet, running a build or a test, installing packages, or running \
untrusted/experimental commands.\n\n\
Persistence works through STAGES, not long-lived sandboxes. Every `sandbox_run` is ephemeral \
(boot -> exec -> destroy). To keep state (installed packages, built artifacts, a prepared \
project), pass `commit_as: \"<label>\"`; on a clean exit (code 0) it freezes the sandbox's \
filesystem changes as an immutable, content-addressed stage. Later calls FORK that stage by \
passing `stage: \"<label-or-name-or-id>\"`, starting on top of it — the parent stage is never \
mutated, so you can branch freely. Omit `stage` to start from the fresh toolchain base \
(Python/Node/git/gcc). Build reusable environments layer by layer: run+commit, then \
fork+run+commit again.\n\n\
Networking is on by default (NAT egress); pass `network: false` for untrusted code. Inspect \
and prune stages with `stage_list`/`stage_info`/`stage_rm`, and review or clean recent VM \
records with `vm_list`/`vm_gc`. Prefer ephemeral `sandbox_run`; commit a stage only when \
state must survive the call.";

/// Inline output-size hint advertised on `sandbox_run` via the tool's `_meta`
/// (`anthropic/maxResultSizeChars`): `stdout`/`stderr` are each head-capped at
/// 64 KiB by core, so a single result stays well under this ceiling; the full,
/// uncapped output is always on disk at the returned log paths.
const MAX_RESULT_SIZE_CHARS: u64 = 100_000;

/// The `_meta` map attached to the `sandbox_run` tool definition, declaring the
/// Anthropic max-result-size hint. Referenced by the `#[tool(meta = …)]`
/// attribute on [`Isopod::sandbox_run`].
fn sandbox_run_meta() -> Meta {
    let mut meta = Meta::new();
    meta.insert(
        "anthropic/maxResultSizeChars".to_string(),
        serde_json::json!(MAX_RESULT_SIZE_CHARS),
    );
    meta
}

// ===========================================================================
// Tool parameter types (JSON-schema-derived; doc comments become descriptions).
// ===========================================================================

/// Parameters for [`Isopod::sandbox_run`].
#[derive(Debug, Deserialize, JsonSchema)]
struct SandboxRunParams {
    /// Shell command to run in the sandbox (executed via `/bin/sh -c`).
    cmd: String,
    /// Stage to fork by id, vanity name, or unique label prefix. The word
    /// `base` (the default when omitted) starts fresh from the toolchain base
    /// image with no committed layers.
    #[serde(default)]
    stage: Option<String>,
    /// Squashfs base image for a fresh (`stage: "base"`) run: `base-alpine`
    /// (Python/Node/git/gcc toolchain, the default) or `base-sqfs` (busybox).
    /// Ignored when forking an existing stage (it reuses the recorded base).
    #[serde(default)]
    base: Option<String>,
    /// Attach a NAT-egress network interface. Default `true`; set `false` to run
    /// untrusted code with no network at all (exec still works over vsock).
    #[serde(default)]
    network: Option<bool>,
    /// Outer wall-clock budget in seconds, covering **boot + exec** (boot costs
    /// ~0.4 s of the budget). Default 120, max 3600.
    #[serde(default)]
    timeout_s: Option<u64>,
    /// Working directory inside the guest (default `/root`).
    #[serde(default)]
    cwd: Option<String>,
    /// Extra environment variables (`KEY` -> `VALUE`) for the command.
    #[serde(default)]
    env: Option<HashMap<String, String>>,
    /// If set and the command exits 0, commit the sandbox's filesystem changes
    /// as a new stage with this label (persist for later `stage`/fork).
    #[serde(default)]
    commit_as: Option<String>,
    /// Text piped to the command's stdin (then closed). Use for feeding a script
    /// or data to the command instead of embedding it in `cmd`. For payloads
    /// beyond a few KiB prefer `stdin_file` — inline text transits the model's
    /// context twice.
    #[serde(default)]
    stdin: Option<String>,
    /// HOST-side file whose bytes are piped to the command's stdin (then
    /// closed). The server reads the file, so large payloads never transit the
    /// model context (dogfood finding #21). Mutually exclusive with `stdin`;
    /// `"-"` is rejected (the server's stdin is the MCP transport itself).
    #[serde(default)]
    stdin_file: Option<String>,
    /// Guest vCPU count (default 1). Must be 1 or an even number, at most the
    /// host CPU count; an over-cap value errors without booting.
    #[serde(default)]
    vcpus: Option<u32>,
    /// Guest memory in MiB (default 512). Bounded 128..=host-free-RAM; an
    /// over-cap value errors without booting.
    #[serde(default)]
    mem_mib: Option<u32>,
    /// Writable scratch size in MiB for the overlay upper (the ext4 scratch
    /// drive). Default ~1024; bounded 128..=65536. Sparse (costs little host disk
    /// until written). Raise it for build workloads that outgrow ~1 GiB. Ignored
    /// by warm resumes (which use a RAM upper); passing it forces the disk path.
    #[serde(default)]
    scratch_mib: Option<u32>,
    /// Guest files to stream to HOST paths after the command finishes — the
    /// artifact-extraction channel (16 GiB per-file ceiling, binary-safe; use
    /// instead of base64-over-stdout). Attempted only when the exec completed without
    /// timing out; a copy failure fails the call. Written files are listed in
    /// the result's `copied`.
    #[serde(default)]
    copy_out: Option<Vec<CopyOutParam>>,
}

/// One `copy_out` mapping for [`Isopod::sandbox_run`].
#[derive(Debug, Deserialize, JsonSchema)]
struct CopyOutParam {
    /// Absolute source path in the guest.
    guest: String,
    /// Host destination path (parent directories are created).
    host: String,
}

/// Parameters for [`Isopod::stage_info`] and [`Isopod::stage_rm`].
#[derive(Debug, Deserialize, JsonSchema)]
struct StageRefParams {
    /// Stage id, vanity name, or unique label prefix.
    reference: String,
}

/// Parameters for [`Isopod::vm_gc`].
#[derive(Debug, Deserialize, JsonSchema)]
struct VmGcParams {
    /// Number of the newest VM records to keep (default 20). Anything younger
    /// than a minute is always kept regardless.
    #[serde(default)]
    keep_last: Option<usize>,
}

// ===========================================================================
// Tool result types (structured output; each derives its own output schema).
// ===========================================================================

/// Structured result of a [`Isopod::sandbox_run`] call.
#[derive(Debug, Serialize, JsonSchema)]
struct SandboxRunResult {
    /// Process exit code (`null` if the command was killed by a signal).
    exit_code: Option<i32>,
    /// Terminating signal number, if the command was killed by one.
    signal: Option<i32>,
    /// `true` if the `timeout_s` budget fired.
    timed_out: bool,
    /// Captured stdout head (lossy UTF-8, capped at 64 KiB).
    stdout: String,
    /// Captured stderr head (lossy UTF-8, capped at 64 KiB).
    stderr: String,
    /// `true` if stdout exceeded the 64 KiB inline cap (full output on disk).
    stdout_truncated: bool,
    /// `true` if stderr exceeded the 64 KiB inline cap (full output on disk).
    stderr_truncated: bool,
    /// Total stdout bytes produced, regardless of the inline cap.
    stdout_bytes: u64,
    /// Total stderr bytes produced, regardless of the inline cap.
    stderr_bytes: u64,
    /// Command exec duration in milliseconds (guest-reported).
    duration_ms: u64,
    /// Total wall time of the whole run (boot + exec + teardown) in ms.
    total_ms: u64,
    /// Which boot path served this run: `"warm"` (snapshot resume) or `"cold"`
    /// (full boot — not warm-eligible, or the resume fell back).
    path: String,
    /// Snapshot-resume duration in ms; present only on the `"warm"` path.
    #[serde(skip_serializing_if = "Option::is_none")]
    resume_ms: Option<u64>,
    /// `true` iff this run built the warm-pool snapshot as a side effect (first
    /// use of a warm-eligible shape) — that one-time build cost (~seconds) is
    /// inside `total_ms` even though the run itself then resumed warm.
    snapshot_built: bool,
    /// Stage-commit duration in ms; present only when `commit_as` committed a
    /// stage this run (roughly seconds per GiB of layer, inside `total_ms`).
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_ms: Option<u64>,
    /// Guest vCPU count the sandbox booted with (host-validated).
    vcpus: u32,
    /// Guest memory in MiB the sandbox booted with (host-validated).
    mem_mib: u32,
    /// The ephemeral VM id (`dev-<8 hex>`).
    vm_id: String,
    /// Human-memorable vanity name for this run's VM.
    vm_name: String,
    /// Rootfs flavor / base the sandbox booted.
    rootfs_flavor: String,
    /// Committed stage id, present only when `commit_as` persisted a stage.
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_id: Option<String>,
    /// Committed stage vanity name (alongside `stage_id`).
    #[serde(skip_serializing_if = "Option::is_none")]
    stage_name: Option<String>,
    /// Network slot index, present only when networking was on.
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<usize>,
    /// Guest IP for this run, present only when networking was on.
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_ip: Option<String>,
    /// Absolute path to the full (uncapped) stdout log on the host.
    stdout_log_path: String,
    /// Absolute path to the full (uncapped) stderr log on the host.
    stderr_log_path: String,
    /// Absolute path to the retained guest serial console log on the host.
    serial_log_path: String,
    /// Files streamed out of the guest via `copy_out` (omitted when none).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    copied: Vec<CopiedFileResult>,
}

/// One file `copy_out` wrote to the host, as listed in [`SandboxRunResult`].
#[derive(Debug, Serialize, JsonSchema)]
struct CopiedFileResult {
    /// Absolute guest source path.
    guest: String,
    /// Host destination path the bytes were written to.
    host: String,
    /// Raw bytes written (the guest file's size).
    bytes: u64,
}

impl From<RunReport> for SandboxRunResult {
    fn from(r: RunReport) -> Self {
        Self {
            exit_code: r.exit_code,
            signal: r.signal,
            timed_out: r.timed_out,
            stdout: r.stdout,
            stderr: r.stderr,
            stdout_truncated: r.stdout_truncated,
            stderr_truncated: r.stderr_truncated,
            stdout_bytes: r.stdout_bytes,
            stderr_bytes: r.stderr_bytes,
            duration_ms: r.exec_ms,
            total_ms: r.total_ms,
            path: match r.path {
                vm::RunPath::Warm => "warm".to_string(),
                vm::RunPath::Cold => "cold".to_string(),
            },
            resume_ms: r.resume_ms,
            snapshot_built: r.snapshot_built,
            commit_ms: r.commit_ms,
            vcpus: r.vcpus,
            mem_mib: r.mem_mib,
            vm_id: r.vm_id,
            vm_name: r.name,
            rootfs_flavor: r.rootfs_flavor,
            stage_id: r.stage_id,
            stage_name: r.stage_name,
            slot: r.slot,
            guest_ip: r.guest_ip,
            stdout_log_path: r.stdout_log_path.to_string_lossy().into_owned(),
            stderr_log_path: r.stderr_log_path.to_string_lossy().into_owned(),
            serial_log_path: r.serial_log_path.to_string_lossy().into_owned(),
            copied: r
                .copied
                .into_iter()
                .map(|c| CopiedFileResult {
                    guest: c.guest,
                    host: c.host.to_string_lossy().into_owned(),
                    bytes: c.bytes,
                })
                .collect(),
        }
    }
}

/// One committed stage, as surfaced by `stage_list` / `stage_info`.
#[derive(Debug, Serialize, JsonSchema)]
struct StageEntry {
    /// Content-addressed id (`st-<16 hex>`).
    stage_id: String,
    /// Human-memorable vanity name.
    name: String,
    /// User-supplied label passed to `commit_as`.
    label: String,
    /// The stage this one was forked from (`null` for a base-rooted stage).
    parent: Option<String>,
    /// Full lineage, root-first, ending with `stage_id` itself.
    chain: Vec<String>,
    /// Base image identifier the chain was built on (`base-alpine`/`base-sqfs`).
    base: String,
    /// Creation time (Unix seconds).
    created_unix: u64,
    /// Apparent (logical) size of the layer artifact, bytes.
    bytes_apparent: u64,
    /// Allocated (on-disk, sparse) size of the layer artifact, bytes.
    bytes_allocated: u64,
}

impl From<StageMeta> for StageEntry {
    fn from(m: StageMeta) -> Self {
        Self {
            stage_id: m.stage_id,
            name: m.name,
            label: m.label,
            parent: m.parent,
            chain: m.chain,
            base: m.base,
            created_unix: m.created_unix,
            bytes_apparent: m.bytes_apparent,
            bytes_allocated: m.bytes_allocated,
        }
    }
}

/// Result of [`Isopod::stage_list`].
#[derive(Debug, Serialize, JsonSchema)]
struct StageListResult {
    /// Committed stages, oldest-first.
    stages: Vec<StageEntry>,
}

/// Result of [`Isopod::stage_info`]: full stage metadata plus its layer chain on
/// disk (overlay-lowerdir order, root-first).
#[derive(Debug, Serialize, JsonSchema)]
struct StageInfoResult {
    /// The resolved stage.
    stage: StageEntry,
    /// Absolute `layer.ext4` paths for each stage in the chain, root-first.
    layer_paths: Vec<String>,
}

/// Result of [`Isopod::stage_rm`].
#[derive(Debug, Serialize, JsonSchema)]
struct StageRmResult {
    /// The removed stage's id.
    removed: String,
    /// The removed stage's label.
    label: String,
    /// The removed stage's vanity name.
    name: String,
}

/// One recorded VM directory, as surfaced by `vm_list`.
#[derive(Debug, Serialize, JsonSchema)]
struct VmEntry {
    /// The stable VM id (`dev-<8 hex>`), also the directory name.
    vm_id: String,
    /// Human-memorable vanity name.
    name: String,
    /// Rootfs flavor the VM booted.
    flavor: String,
    /// Creation time (Unix seconds).
    created_unix: u64,
    /// Total bytes currently held by the VM directory (logs, sockets, copies).
    dir_bytes: u64,
}

/// Result of [`Isopod::vm_list`].
#[derive(Debug, Serialize, JsonSchema)]
struct VmListResult {
    /// Recorded VMs, newest-first.
    vms: Vec<VmEntry>,
}

/// Result of [`Isopod::vm_gc`].
#[derive(Debug, Serialize, JsonSchema)]
struct VmGcResult {
    /// VM ids removed by this pass.
    removed: Vec<String>,
    /// Number of records kept.
    kept: usize,
    /// Bytes freed by the removals.
    freed_bytes: u64,
}

// ===========================================================================
// Server.
// ===========================================================================

/// The isopod MCP server: a near-stateless shim holding the generated tool
/// router and a run counter for the periodic auto-GC sweep. All durable state
/// lives under `~/.isopod` (file-locked), so a crashed server leaves nothing to
/// clean up beyond a `vm_gc` sweep.
#[derive(Debug, Clone)]
struct Isopod {
    tool_router: ToolRouter<Self>,
    /// Total `sandbox_run` calls served — drives the every-Nth auto-GC.
    runs: Arc<AtomicU64>,
}

/// How many newest VM record dirs the automatic sweeps keep (matches the
/// `vm_gc` tool's default).
const AUTO_GC_KEEP_LAST: usize = 20;
/// Auto-GC cadence: sweep after every Nth `sandbox_run`.
const AUTO_GC_EVERY: u64 = 20;

/// Fire-and-forget GC sweep on the blocking pool: reap orphaned firecracker
/// processes and prune old VM record dirs (keeping [`AUTO_GC_KEEP_LAST`] plus
/// anything under a minute old). A long-lived server otherwise accretes VM dirs
/// and exec logs without bound; note this means `*_log_path` values from runs
/// older than the newest ~20 eventually dangle.
fn spawn_auto_gc(trigger: &'static str) {
    tokio::task::spawn_blocking(move || {
        match vm::vm_gc(AUTO_GC_KEEP_LAST, Duration::from_secs(60)) {
            Ok(r) => tracing::info!(
                trigger,
                removed = r.removed.len(),
                kept = r.kept,
                freed_bytes = r.freed_bytes,
                "auto vm_gc"
            ),
            Err(e) => tracing::warn!(trigger, "auto vm_gc failed: {e:#}"),
        }
    });
}

#[tool_router(router = tool_router)]
impl Isopod {
    /// Construct the server with its tool router wired up.
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
            runs: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Run a shell command in a fresh, disposable Firecracker microVM (boot,
    /// exec, destroy). Use for executing code, builds, tests, package installs,
    /// or untrusted/experimental commands in isolation from the host. `cmd` runs
    /// via `/bin/sh -c`. By default starts from the toolchain base
    /// (Python/Node/git/gcc); pass `stage` to fork a committed stage, or
    /// `commit_as` to persist the result as a new stage (only when the command
    /// exits 0). A non-zero exit code is returned normally, not as an error.
    /// Networking is on by default; set `network=false` for untrusted code.
    /// `timeout_s` covers boot + exec (default 120, max 3600). Size the VM with
    /// `vcpus` (default 1) and `mem_mib` (default 512); both are host-capped.
    #[tool(
        name = "sandbox_run",
        description = "Run a shell command in a fresh, disposable Firecracker microVM (boot, exec, \
destroy). Use for executing code, builds, tests, package installs, or untrusted/experimental \
commands isolated from the host. `cmd` runs via /bin/sh -c. Defaults to the toolchain base \
(Python/Node/git/gcc); pass `stage` to fork a committed stage, `commit_as` to persist the result \
as a new stage (only on exit 0). Non-zero exit codes are returned normally, not as errors. \
Networking on by default (network=false for untrusted code). timeout_s covers boot + exec \
(default 120, max 3600). Size the VM with vcpus (default 1) and mem_mib (default 512), both \
host-capped. \
For large stdin payloads pass stdin_file (a host path) instead of stdin; to extract build \
artifacts pass copy_out (guest->host file mappings, binary-safe, 16 GiB per-file ceiling). NOTE: \
parallel sandbox_run calls batched in one message execute serially; for concurrent sandboxes, \
issue calls from separate agents.",
        meta = crate::sandbox_run_meta()
    )]
    async fn sandbox_run(
        &self,
        params: Parameters<SandboxRunParams>,
        meta: Meta,
        peer: Peer<RoleServer>,
    ) -> Result<Json<SandboxRunResult>, ErrorData> {
        let p = params.0;

        // Resolve the base flavor (only used for a fresh `base` run; forks reuse
        // the stage's recorded base). Default to the toolchain image via MCP.
        let base = match p.base.as_deref() {
            None => RootfsFlavor::BaseAlpine,
            Some(slug) => {
                let flavor = RootfsFlavor::from_slug(slug).map_err(|e| {
                    ErrorData::invalid_params(format!("invalid base {slug:?}: {e}"), None)
                })?;
                if !flavor.is_squashfs_base() {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "base {slug:?} is not a squashfs base (use base-alpine or base-sqfs)"
                        ),
                        None,
                    ));
                }
                flavor
            }
        };

        // The MCP surface is stage-first: an omitted `stage` means "fresh from
        // the toolchain base", never the legacy no-overlay dev-agent topology.
        let stage = Some(p.stage.unwrap_or_else(|| "base".to_string()));
        let env: Vec<(String, String)> = p.env.unwrap_or_default().into_iter().collect();

        // Resolve stdin: inline text, or a host-side file read here so large
        // payloads never round-trip through the model context (finding #21).
        let stdin = match (p.stdin, p.stdin_file) {
            (Some(_), Some(_)) => {
                return Err(ErrorData::invalid_params(
                    "pass either `stdin` or `stdin_file`, not both",
                    None,
                ));
            }
            (Some(text), None) => Some(text.into_bytes()),
            (None, Some(path)) => {
                if path == "-" {
                    return Err(ErrorData::invalid_params(
                        "stdin_file \"-\" is not supported over MCP: the server's own stdin is \
                         the JSON-RPC transport; pass a regular file path",
                        None,
                    ));
                }
                let bytes = tokio::fs::read(&path).await.map_err(|e| {
                    ErrorData::invalid_params(format!("reading stdin_file {path:?}: {e}"), None)
                })?;
                Some(bytes)
            }
            (None, None) => None,
        };

        let opts = RunOptions {
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), p.cmd],
            env,
            cwd: p.cwd,
            timeout_s: p.timeout_s.unwrap_or(120),
            flavor: RootfsFlavor::DevAgent,
            keep: false,
            network: p.network.unwrap_or(true),
            stage,
            commit_as: p.commit_as,
            base,
            stdin,
            // Defaults resolved by the core resolver, which also host-validates.
            vcpus: p.vcpus.unwrap_or(vm::DEFAULT_VCPUS),
            mem_mib: p.mem_mib.unwrap_or(vm::DEFAULT_MEM_MIB),
            scratch_mib: p.scratch_mib,
            copy_out: p
                .copy_out
                .unwrap_or_default()
                .into_iter()
                .map(|c| vm::CopyOutSpec {
                    guest: c.guest,
                    host: std::path::PathBuf::from(c.host),
                })
                .collect(),
        };

        // Best-effort idle-timeout keepalive: if the client sent a progressToken,
        // emit a progress notification every ~10 s while the (blocking) run is in
        // flight. Claude Code does not render these; they only keep the request
        // from being reaped as idle. Any error is ignored, and the task is
        // aborted the moment the run returns.
        let keepalive = meta.get_progress_token().map(|token| {
            let peer = peer.clone();
            tokio::spawn(async move {
                let mut ticks = 0.0_f64;
                let mut interval = tokio::time::interval(Duration::from_secs(10));
                interval.tick().await; // first tick is immediate — skip it
                loop {
                    interval.tick().await;
                    ticks += 1.0;
                    let _ = peer
                        .notify_progress(
                            ProgressNotificationParam::new(token.clone(), ticks)
                                .with_message("sandbox_run in progress"),
                        )
                        .await;
                }
            })
        });

        // `run_ephemeral` builds its own tokio runtime, so it MUST run on the
        // blocking pool — calling it inline would panic (runtime-in-runtime).
        let outcome = tokio::task::spawn_blocking(move || vm::run_ephemeral(opts)).await;

        if let Some(handle) = keepalive {
            handle.abort();
        }

        // Periodic background retention sweep (see `spawn_auto_gc`); counted per
        // attempt so failed runs still advance the cadence.
        let served = self.runs.fetch_add(1, Ordering::Relaxed) + 1;
        if served.is_multiple_of(AUTO_GC_EVERY) {
            spawn_auto_gc("periodic");
        }

        match outcome {
            Ok(Ok(report)) => Ok(Json(SandboxRunResult::from(report))),
            // A run that failed to boot/exec/commit is an infra fault -> McpError.
            Ok(Err(e)) => Err(ErrorData::internal_error(
                format!("sandbox_run failed: {e:#}"),
                None,
            )),
            Err(join) => Err(ErrorData::internal_error(
                format!("sandbox_run task panicked: {join}"),
                None,
            )),
        }
    }

    /// List every committed stage (oldest-first) with its lineage, base, and
    /// on-disk size. Stages are the persistent, forkable filesystem layers left
    /// behind by `sandbox_run … commit_as`.
    #[tool(
        name = "stage_list",
        description = "List committed stages (oldest-first): id, vanity name, label, parent, base, \
size, chain. Stages are the persistent, forkable filesystem layers a `sandbox_run` with \
`commit_as` leaves behind."
    )]
    async fn stage_list(&self) -> Result<Json<StageListResult>, ErrorData> {
        let stages = tokio::task::spawn_blocking(stage::list)
            .await
            .map_err(|join| {
                ErrorData::internal_error(format!("stage_list task panicked: {join}"), None)
            })?
            .map_err(|e| ErrorData::internal_error(format!("stage_list failed: {e:#}"), None))?;
        Ok(Json(StageListResult {
            stages: stages.into_iter().map(StageEntry::from).collect(),
        }))
    }

    /// Show one stage's full metadata plus its layer chain on disk (root-first
    /// overlay-lowerdir order). Accepts a stage id, vanity name, or unique label
    /// prefix.
    #[tool(
        name = "stage_info",
        description = "Show a stage's full metadata and its on-disk layer chain (root-first). \
`reference` is a stage id, vanity name, or unique label prefix."
    )]
    async fn stage_info(
        &self,
        params: Parameters<StageRefParams>,
    ) -> Result<Json<StageInfoResult>, ErrorData> {
        let reference = params.0.reference;
        let info = tokio::task::spawn_blocking(move || -> anyhow::Result<StageInfoResult> {
            let meta = stage::resolve(&reference)?;
            let layer_paths = stage::chain_paths(&meta)?
                .into_iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect();
            Ok(StageInfoResult {
                stage: StageEntry::from(meta),
                layer_paths,
            })
        })
        .await
        .map_err(|join| {
            ErrorData::internal_error(format!("stage_info task panicked: {join}"), None)
        })?
        .map_err(|e| ErrorData::internal_error(format!("stage_info failed: {e:#}"), None))?;
        Ok(Json(info))
    }

    /// Remove a committed stage. Refused (returns an error) if another stage's
    /// chain still references it. Accepts a stage id, vanity name, or unique
    /// label prefix.
    #[tool(
        name = "stage_rm",
        description = "Remove a committed stage. Errors if another stage's chain still references \
it. `reference` is a stage id, vanity name, or unique label prefix."
    )]
    async fn stage_rm(
        &self,
        params: Parameters<StageRefParams>,
    ) -> Result<Json<StageRmResult>, ErrorData> {
        let reference = params.0.reference;
        let removed = tokio::task::spawn_blocking(move || stage::remove(&reference))
            .await
            .map_err(|join| {
                ErrorData::internal_error(format!("stage_rm task panicked: {join}"), None)
            })?
            .map_err(|e| ErrorData::internal_error(format!("stage_rm failed: {e:#}"), None))?;
        Ok(Json(StageRmResult {
            removed: removed.stage_id,
            label: removed.label,
            name: removed.name,
        }))
    }

    /// List recent VM records (newest-first) — the per-run directories under
    /// `~/.isopod/vms` holding serial/exec logs. Useful for looking up a vanity
    /// name or reviewing disk usage before `vm_gc`.
    #[tool(
        name = "vm_list",
        description = "List recent VM records (newest-first): id, vanity name, flavor, created, dir \
bytes. These are the per-run directories holding serial and exec logs."
    )]
    async fn vm_list(&self) -> Result<Json<VmListResult>, ErrorData> {
        let vms = tokio::task::spawn_blocking(vm::vm_list)
            .await
            .map_err(|join| {
                ErrorData::internal_error(format!("vm_list task panicked: {join}"), None)
            })?
            .map_err(|e| ErrorData::internal_error(format!("vm_list failed: {e:#}"), None))?;
        Ok(Json(VmListResult {
            vms: vms
                .into_iter()
                .map(|r| VmEntry {
                    vm_id: r.vm_id,
                    name: r.name,
                    flavor: r.flavor,
                    created_unix: r.created_unix,
                    dir_bytes: r.dir_bytes,
                })
                .collect(),
        }))
    }

    /// Garbage-collect old VM directories: reap any orphaned firecracker
    /// processes, then keep the newest `keep_last` records (and anything younger
    /// than a minute) and prune the rest.
    #[tool(
        name = "vm_gc",
        description = "Reap orphaned firecracker processes and prune old VM directories, keeping the \
newest `keep_last` (default 20) and anything under a minute old. The server also runs this \
sweep automatically (at startup and every 20 sandbox runs), so *_log_path files from old runs \
eventually disappear — read logs you care about promptly."
    )]
    async fn vm_gc(&self, params: Parameters<VmGcParams>) -> Result<Json<VmGcResult>, ErrorData> {
        let keep_last = params.0.keep_last.unwrap_or(20);
        let report =
            tokio::task::spawn_blocking(move || vm::vm_gc(keep_last, Duration::from_secs(60)))
                .await
                .map_err(|join| {
                    ErrorData::internal_error(format!("vm_gc task panicked: {join}"), None)
                })?
                .map_err(|e| ErrorData::internal_error(format!("vm_gc failed: {e:#}"), None))?;
        Ok(Json(VmGcResult {
            removed: report.removed,
            kept: report.kept,
            freed_bytes: report.freed_bytes,
        }))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Isopod {
    /// Advertise tool support and the usage instructions (front-loaded trigger
    /// phrases) to the connecting MCP client.
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(INSTRUCTIONS)
            .with_server_info(
                Implementation::new("isopod", env!("CARGO_PKG_VERSION"))
                    .with_title("isopod microVM sandbox"),
            )
    }
}

/// Serve the isopod MCP server over stdio until the client disconnects.
///
/// Diagnostics are directed to stderr so they never corrupt the JSON-RPC stream
/// on stdout.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();

    tracing::info!("isopod-mcp starting (rmcp stdio transport)");
    // Sweep leftovers from previous sessions (orphaned firecrackers, old VM
    // dirs) without delaying server readiness.
    spawn_auto_gc("startup");
    let service = Isopod::new().serve(rmcp::transport::stdio()).await?;
    let reason = service.waiting().await?;
    tracing::info!(?reason, "isopod-mcp shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The router exposes exactly the six agreed tools, by name.
    #[test]
    fn exposes_the_six_tools() {
        let server = Isopod::new();
        let mut names: Vec<String> = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "sandbox_run".to_string(),
                "stage_info".to_string(),
                "stage_list".to_string(),
                "stage_rm".to_string(),
                "vm_gc".to_string(),
                "vm_list".to_string(),
            ]
        );
    }

    /// `sandbox_run` carries the Anthropic max-result-size hint in its `_meta`,
    /// and advertises a structured output schema.
    #[test]
    fn sandbox_run_has_meta_and_output_schema() {
        let server = Isopod::new();
        let tools = server.tool_router.list_all();
        let run = tools
            .iter()
            .find(|t| t.name == "sandbox_run")
            .expect("sandbox_run present");
        let meta = run.meta.as_ref().expect("sandbox_run has _meta");
        assert_eq!(
            meta.get("anthropic/maxResultSizeChars"),
            Some(&serde_json::json!(MAX_RESULT_SIZE_CHARS))
        );
        assert!(
            run.output_schema.is_some(),
            "sandbox_run advertises a structured output schema"
        );
    }

    /// The server instructions stay under the 2 KiB budget.
    #[test]
    fn instructions_within_budget() {
        assert!(
            INSTRUCTIONS.len() < 2048,
            "instructions must be < 2 KiB, got {}",
            INSTRUCTIONS.len()
        );
    }
}
