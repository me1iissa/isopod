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

use isopod_core::image::{self, RootfsFlavor};
use isopod_core::stage::{self, StageMeta};
use isopod_core::vm::{self, RunOptions, RunReport};

mod hostio;
use hostio::{Access, HostIo};

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

/// Ceiling on a `stdin_file` payload.
///
/// The bytes cross the vsock as one framed message, and the frame limit is 8 MiB
/// before base64 expansion — so anything much above this could not reach the guest
/// anyway, and refusing up front names a limit instead of failing later with a
/// framing error.
const MAX_STDIN_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// Read a `stdin_file`, with the guards a host-path argument needs.
///
/// `tokio::fs::read` on a caller-supplied path is not enough on either count:
///
/// - **Regular files only.** A FIFO blocks inside `open` until someone writes,
///   parking a blocking-pool thread for the life of the process; a character
///   device like `/dev/zero` never reaches EOF, so the read grows a `Vec` until
///   the host is out of memory. The credential loader already refuses non-regular
///   sources for exactly these two reasons; this path had none of it.
/// - **A size ceiling, enforced on the read.** The stat is a hint — a file can
///   grow between stat and read — so the limit is applied by reading through
///   `take`, and the stat only exists to refuse early with a clear message.
///
/// `symlink_metadata`, not `metadata`: the path arriving here has already been
/// resolved by [`HostIo::check`], so a symlink at this point is one that appeared
/// after the check, and following it is the thing the check ruled out.
async fn read_stdin_file(path: &std::path::Path) -> Result<Vec<u8>, String> {
    read_stdin_file_limited(path, MAX_STDIN_FILE_BYTES).await
}

/// [`read_stdin_file`] with the ceiling as a parameter, so the guards can be
/// tested without writing megabytes to a temp directory.
async fn read_stdin_file_limited(path: &std::path::Path, limit: u64) -> Result<Vec<u8>, String> {
    use tokio::io::AsyncReadExt as _;

    let meta = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "{} is not a regular file. A FIFO would block the read until something \
             wrote to it, and a device is unbounded",
            path.display()
        ));
    }
    if meta.len() > limit {
        return Err(format!(
            "{} is {} bytes, over the {limit}-byte stdin_file limit (the payload \
             crosses the vsock as one frame). Copy it into a stage instead, or split it",
            path.display(),
            meta.len(),
        ));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    // One byte past the limit, so growth between the stat and the read is caught
    // here rather than silently truncated.
    tokio::io::AsyncReadExt::take(file, limit + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| format!("reading {}: {e}", path.display()))?;
    if bytes.len() as u64 > limit {
        return Err(format!(
            "{} grew past the {limit}-byte stdin_file limit while it was being read",
            path.display()
        ));
    }
    Ok(bytes)
}

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
    /// Permit egress ONLY to these hosts (default-deny everything else). Setting
    /// this — even to `[]` — switches the run to filtered egress: a slot that
    /// forwards nothing, plus a host-side broker that enforces this list and
    /// records every allowed and denied attempt in `egress`. Accepts exact names
    /// (`pypi.org`) or one leading wildcard label (`*.pythonhosted.org`, which
    /// does NOT match the apex). `[]` denies all egress while still recording
    /// what the workload tried to reach. Cannot be combined with
    /// `network: false`, which attaches no interface at all.
    #[serde(default)]
    allow_hosts: Option<Vec<String>>,
    /// Permit egress to literal IP addresses in these CIDRs, for tools that dial
    /// an address rather than a name. Also switches the run to filtered egress. A
    /// literal address is never matched against `allow_hosts` patterns.
    #[serde(default)]
    allow_cidrs: Option<Vec<String>>,
    /// Credential aliases to inject, e.g. `["github"]`. The sandbox can spend
    /// the credential without ever holding it: it calls
    /// `$ISOPOD_CREDENTIAL_ENDPOINT/<alias>/<path>` and the host attaches the
    /// token, but only for the exact methods and paths the operator declared.
    /// Everything about the credential — which secret, which host, which
    /// requests — is declared host-side in `~/.isopod/credentials.json`; there
    /// is no way to name a secret or a destination from here. An alias the
    /// operator has not marked `"mcp": true` is refused, and every refusal
    /// reads identically so probing reveals nothing. Also switches the run to
    /// filtered egress.
    #[serde(default)]
    inject: Option<Vec<String>>,
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
    /// Why `commit_as` did not produce a stage, when it was asked for and failed
    /// (a label already in use, a base mismatch, no space). The command itself
    /// still ran — its exit code and output above are the real ones — so this is
    /// the field to read before assuming a stage exists to fork from.
    #[serde(skip_serializing_if = "Option::is_none")]
    commit_error: Option<String>,
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
    /// The egress flight recorder: every destination this run reached and every
    /// one it was refused. Present only when `allow_hosts`/`allow_cidrs` put the
    /// run in filtered-egress mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    egress: Option<EgressResult>,
}

/// The egress record for a filtered run, as returned by `sandbox_run`.
///
/// Host names here originate in untrusted guest code and are validated before
/// recording: anything that is not a well-formed host name appears as
/// `<invalid:N>` — the rejected byte count and nothing else — so a workload
/// cannot inject text into the model's context through a destination name.
#[derive(Debug, Serialize, JsonSchema)]
struct EgressResult {
    /// Always `"filtered"` when present.
    mode: String,
    /// The allowlist this run enforced, normalised.
    allowed_rules: Vec<String>,
    /// Connections the broker permitted (capped; see `truncated`).
    allowed: Vec<EgressConnResult>,
    /// Connections the broker refused, with a machine-readable `reason`.
    denied: Vec<EgressDeniedResult>,
    /// Names the workload asked to resolve, deduplicated. A name here that is
    /// also in `denied` is a lookup that was refused — the signal that
    /// something tried to reach a destination you did not allow.
    dns_queries: Vec<String>,
    /// Credentials injected into this run and exactly what each may authorise.
    /// Never the secret itself, which never leaves the host.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    injected: Vec<InjectedCredentialResult>,
    /// Where the sandbox reached the credential endpoint, when one was offered.
    #[serde(skip_serializing_if = "Option::is_none")]
    credential_endpoint: Option<String>,
    /// Total decisions the broker made, including any beyond the inline caps.
    total_events: u64,
    /// `true` when a list above was capped; the full record is at
    /// `egress_log_path`.
    truncated: bool,
    /// HOST path to the complete JSON Lines record for this run.
    egress_log_path: String,
}

/// One permitted connection in [`EgressResult`].
#[derive(Debug, Serialize, JsonSchema)]
struct EgressConnResult {
    /// Destination host or address.
    host: String,
    /// Destination port.
    port: u16,
    /// Bytes the workload sent to this destination. Volume is the signal a
    /// destination allowlist cannot give on its own — an allowed host that
    /// received gigabytes is the exfiltration tell.
    bytes_up: u64,
    /// Bytes this destination returned to the workload.
    bytes_down: u64,
    /// Milliseconds after the broker started listening.
    ts_ms: u64,
}

/// One refused connection or lookup in [`EgressResult`].
#[derive(Debug, Serialize, JsonSchema)]
struct EgressDeniedResult {
    /// Destination the workload asked for.
    host: String,
    /// Destination port (0 for a DNS lookup, which names no port).
    port: u16,
    /// Why it was refused: `not_allowed`, `literal_address`, `empty_allowlist`,
    /// `malformed`, `pinned_credential_host` (the destination belongs to an
    /// injected credential and must be reached through the credential endpoint,
    /// not dialled directly), or `credential_refused` (the endpoint itself
    /// refused — see `note`).
    reason: String,
    /// A short machine-readable detail when the broker had one, e.g.
    /// `inject-not-permitted` (the credential exists but does not authorise
    /// that method and path) or `dial-failed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// Milliseconds after the broker started listening.
    ts_ms: u64,
}

/// One credential injected into a run, as listed in [`EgressResult`].
#[derive(Debug, Serialize, JsonSchema)]
struct InjectedCredentialResult {
    /// The alias, and the first path segment at the credential endpoint.
    alias: String,
    /// The only host this credential is ever sent to.
    host: String,
    /// The request shapes it may authorise, e.g. `GET|HEAD /**`. A request
    /// outside these is refused before any token is attached.
    allow: Vec<String>,
}

impl From<vm::EgressReport> for EgressResult {
    fn from(e: vm::EgressReport) -> Self {
        Self {
            mode: match e.mode {
                vm::EgressMode::Filtered => "filtered".to_string(),
                vm::EgressMode::Public => "public".to_string(),
            },
            allowed_rules: e.allowed_rules,
            allowed: e
                .allowed
                .into_iter()
                .map(|c| EgressConnResult {
                    host: c.host,
                    port: c.port,
                    bytes_up: c.bytes_up,
                    bytes_down: c.bytes_down,
                    ts_ms: c.ts_ms,
                })
                .collect(),
            denied: e
                .denied
                .into_iter()
                .map(|d| EgressDeniedResult {
                    host: d.host,
                    port: d.port,
                    // Reuse the serde spelling so CLI and MCP agree.
                    reason: serde_json::to_value(d.reason)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_string))
                        .unwrap_or_else(|| "not_allowed".to_string()),
                    note: d.note.map(str::to_string),
                    ts_ms: d.ts_ms,
                })
                .collect(),
            dns_queries: e.dns_queries,
            injected: e
                .injected
                .into_iter()
                .map(|c| InjectedCredentialResult {
                    alias: c.alias,
                    host: c.host,
                    allow: c.allow,
                })
                .collect(),
            credential_endpoint: e.credential_endpoint,
            total_events: e.total_events,
            truncated: e.truncated,
            egress_log_path: e.egress_log_path.to_string_lossy().into_owned(),
        }
    }
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
            egress: r.egress.map(EgressResult::from),
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
            commit_error: r.commit_error,
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
    /// Content id (sha256) of the base image build the layers were made
    /// against. `null` for a stage committed before stamping existed, or on an
    /// image with no build sidecar — those fork unchecked. A fork is refused
    /// when this disagrees with the base image on the host.
    base_sha256: Option<String>,
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
            base_sha256: m.base_sha256,
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
    /// Whether the run that owns this directory is still going. `vm_gc` refuses
    /// to touch these; surfacing it here is what lets a caller tell "leftovers I
    /// can prune" from "a run in flight" before asking for a collection.
    live: bool,
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
    /// Policy for the two arguments that name a **host** path. Resolved once at
    /// startup, so a mid-session environment change cannot widen it.
    host_io: HostIo,
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
        let host_io = HostIo::from_env();
        // Logged at boot, not on first use: a confinement an operator cannot see
        // is one they will not notice is wrong until a call fails.
        tracing::info!("host file I/O: {}", host_io.describe());
        Self {
            tool_router: Self::tool_router(),
            runs: Arc::new(AtomicU64::new(0)),
            host_io,
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
Networking on by default; pass network=false for no network at all, or \
allow_hosts=['host', ...] for DEFAULT-DENY egress that reaches only those hosts \
(host-enforced, outside the sandbox) and returns an `egress` record of every \
allowed and denied destination. timeout_s covers boot + exec \
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
            None => image::BaseRef::Builtin(RootfsFlavor::BaseAlpine),
            Some(slug) => {
                let base = image::BaseRef::parse(slug).map_err(|e| {
                    ErrorData::invalid_params(format!("invalid base {slug:?}: {e}"), None)
                })?;
                if !base.is_squashfs_base() {
                    return Err(ErrorData::invalid_params(
                        format!(
                            "base {slug:?} is not a squashfs base (use base-alpine, \
                             base-sqfs, or an imported `oci:<name>`)"
                        ),
                        None,
                    ));
                }
                base
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
                // Confined, and the *resolved* path is what gets opened — so the
                // path that was validated is the path that is read, with no
                // window between the two. Unconstrained, this argument was an
                // arbitrary host-file read whose contents come back to the
                // caller in `stdout`; see the `hostio` module docs.
                let checked = self
                    .host_io
                    .check(&path, Access::Read)
                    .map_err(|e| ErrorData::invalid_params(e, None))?;
                let bytes = read_stdin_file(&checked).await.map_err(|e| {
                    ErrorData::invalid_params(format!("stdin_file {path:?}: {e}"), None)
                })?;
                Some(bytes)
            }
            (None, None) => None,
        };

        // Any of the three present — even as an empty list — means "filtered".
        // All absent is the unfiltered default, byte-identical to 0.8.1.
        //
        // `inject` belongs in this tuple rather than beside it: a credential
        // that did not imply a filtered slot would arrive on a public one, with
        // full NAT egress and no broker to enforce its `allow` list.
        let egress = match (&p.allow_hosts, &p.allow_cidrs, &p.inject) {
            (None, None, None) => None,
            (hosts, cidrs, inject) => Some(isopod_core::vm::EgressPolicy {
                hosts: hosts.clone().unwrap_or_default(),
                cidrs: cidrs.clone().unwrap_or_default(),
                inject: inject.clone().unwrap_or_default(),
                // Every MCP caller is a model whose context the sandboxed code
                // may have written. Credential refusals render identically so
                // probing cannot enumerate the operator's aliases; the specific
                // reason goes to the server's stderr instead.
                caller: isopod_core::vm::Caller::Model,
            }),
        };
        if egress.is_some() && p.network == Some(false) {
            return Err(ErrorData::invalid_params(
                "allow_hosts/allow_cidrs/inject ask for a filtered network interface \
                 while network=false attaches none at all. Pass allow_hosts for \
                 default-deny egress, or network=false for no network."
                    .to_string(),
                None,
            ));
        }

        let opts = RunOptions {
            argv: vec!["/bin/sh".to_string(), "-c".to_string(), p.cmd],
            env,
            cwd: p.cwd,
            timeout_s: p.timeout_s.unwrap_or(120),
            flavor: RootfsFlavor::DevAgent,
            keep: false,
            network: p.network.unwrap_or(true),
            egress,
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
                .map(|c| {
                    // Same confinement, opposite direction — and this one writes
                    // guest-authored bytes, creating parent directories on the
                    // way. Unconstrained it was a host-persistence primitive
                    // (an `authorized_keys`, a shell rc, or isopod's own
                    // credential store) driven by whatever the sandbox produced.
                    let host = self
                        .host_io
                        .check(&c.host, Access::Write)
                        .map_err(|e| ErrorData::invalid_params(e, None))?;
                    Ok(vm::CopyOutSpec {
                        guest: c.guest,
                        host,
                    })
                })
                .collect::<Result<Vec<_>, ErrorData>>()?,
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
bytes, and whether the run is still live. These are the per-run directories holding serial and \
exec logs. `vm_gc` never collects a live one."
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
                    live: r.live,
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

    #[tokio::test]
    async fn stdin_file_reads_only_bounded_regular_files() {
        let dir = tempfile::tempdir().expect("tempdir");

        // The ordinary case still works, byte for byte.
        let ok = dir.path().join("payload");
        std::fs::write(&ok, b"hello stdin").expect("write");
        assert_eq!(
            read_stdin_file_limited(&ok, 1024).await.expect("read"),
            b"hello stdin".to_vec()
        );

        // A directory is not a regular file. Neither is a character device: reading
        // /dev/zero to EOF never terminates, and the buffer grows until the host is
        // out of memory — the argument was a one-line host OOM.
        let err = read_stdin_file_limited(dir.path(), 1024)
            .await
            .expect_err("a directory must be refused");
        assert!(err.contains("not a regular file"), "{err}");
        let zero = std::path::Path::new("/dev/zero");
        if zero.exists() {
            let err = read_stdin_file_limited(zero, 1024)
                .await
                .expect_err("/dev/zero must be refused");
            assert!(err.contains("not a regular file"), "{err}");
            assert!(
                err.contains("unbounded"),
                "the why is in the message: {err}"
            );
        }

        // Over the ceiling: refused by the stat, naming the limit.
        let big = dir.path().join("big");
        std::fs::write(&big, vec![b'x'; 64]).expect("write");
        let err = read_stdin_file_limited(&big, 8)
            .await
            .expect_err("an oversized file must be refused");
        assert!(err.contains("over the 8-byte stdin_file limit"), "{err}");

        // Exactly at the ceiling is allowed — the check is `>`, not `>=`, and an
        // off-by-one here would reject a payload the vsock frame can carry.
        let exact = dir.path().join("exact");
        std::fs::write(&exact, vec![b'y'; 8]).expect("write");
        assert_eq!(
            read_stdin_file_limited(&exact, 8)
                .await
                .expect("read")
                .len(),
            8
        );
    }

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
