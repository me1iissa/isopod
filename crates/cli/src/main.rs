//! isopod — one-shot argv + JSON CLI.
//!
//! Convention (binding, see PLAN.md): every subcommand is non-interactive,
//! prints exactly one JSON object to stdout (human logs to stderr), and
//! persists any cross-invocation state under ~/.isopod so any caller
//! (Claude Code, human shell, CI) can resume.

use std::time::Duration;

use anyhow::Context as _;
use clap::{Args, Parser, Subcommand};
use isopod_core::image::{self, RootfsFlavor};
use isopod_core::stage;
use isopod_core::vm::{
    self, DevBootOptions, RunOptions, DEFAULT_MEM_MIB, DEFAULT_RUN_FLAVOR, DEFAULT_VCPUS,
};
use serde::Serialize;

#[derive(Parser)]
#[command(name = "isopod", version, about = "Firecracker-based agentic sandbox")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Guest image pipeline (fetch-kernel, build-rootfs)
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Developer utilities (boot, build-fc)
    Dev {
        #[command(subcommand)]
        command: DevCommand,
    },
    /// Boot an ephemeral VM, run a command over vsock, and destroy it
    Run(RunArgs),
    /// Manage the persistent stage store (list, info, rm)
    Stage {
        #[command(subcommand)]
        command: StageCommand,
    },
    /// Browse and prune recorded VM directories (ls, gc)
    Vm {
        #[command(subcommand)]
        command: VmCommand,
    },
    /// Warm-pool snapshots (build, list, rm)
    Warmpool {
        #[command(subcommand)]
        command: WarmpoolCommand,
    },
    /// Provision host networking (run once as root via sudo); `--remove` tears it down
    Setup(SetupArgs),
}

#[derive(Args)]
struct SetupArgs {
    /// Number of network slots (taps `isopod-tap0..N-1`) to provision.
    #[arg(long, default_value_t = isopod_core::net::DEFAULT_SLOT_COUNT)]
    slots: usize,
    /// Tear down all isopod networking (taps, nftables table, sysctl file).
    #[arg(long)]
    remove: bool,
    /// Override the auto-detected default-route egress interface to NAT out of.
    #[arg(long)]
    iface: Option<String>,
    /// Permit guest egress to RFC1918 / CGNAT / link-local destinations (the
    /// host LAN and cloud metadata). INSECURE: allows lateral movement / SSRF
    /// from untrusted guests. Default off (public-only egress).
    #[arg(long = "allow-lan-egress")]
    allow_lan_egress: bool,
}

#[derive(Subcommand)]
enum VmCommand {
    /// List recorded VMs newest-first (id, vanity name, flavor, created, bytes)
    Ls,
    /// Remove old VM directories (keeps the newest N and anything under a minute old)
    Gc {
        /// How many of the newest VM records to keep.
        #[arg(long = "keep-last", default_value_t = 20)]
        keep_last: usize,
    },
}

#[derive(Args)]
struct RunArgs {
    /// Outer wall-clock budget in seconds (covers boot + exec).
    #[arg(long = "timeout-s", default_value_t = 120)]
    timeout_s: u64,
    /// Guest vCPU count (default 1). Must be 1 or an even number, and at most the
    /// host CPU count; an over-cap value errors without booting a VM.
    #[arg(long, default_value_t = DEFAULT_VCPUS)]
    vcpus: u32,
    /// Guest memory in MiB (default 512). Bounded below at 128 MiB and above by
    /// the host's free RAM (headroom reserved); an over-cap value errors without
    /// booting a VM.
    #[arg(long = "mem-mib", default_value_t = DEFAULT_MEM_MIB)]
    mem_mib: u32,
    /// Writable scratch size in MiB for a `--stage` run's overlay upper (the ext4
    /// scratch drive). Default ~1024; bounded 128..=65536. The image is sparse
    /// (costs little host disk until written). Ignored by the legacy topology and
    /// by warm resumes; passing it forces the cold ext4 path.
    #[arg(long = "scratch-mib")]
    scratch_mib: Option<u32>,
    /// Rootfs flavor to boot.
    #[arg(long, default_value = DEFAULT_RUN_FLAVOR)]
    flavor: String,
    /// Keep the VM directory's throwaway rootfs copy instead of deleting it.
    #[arg(long)]
    keep: bool,
    /// Boot without any network interface (default: attach a NAT-egress NIC,
    /// which requires `sudo isopod setup` to have run once). Exec works either
    /// way — control RPC is vsock, not the network.
    #[arg(long = "no-network")]
    no_network: bool,
    /// Working directory inside the guest (default `/root`).
    #[arg(long)]
    cwd: Option<String>,
    /// Environment variable to set (repeatable): `--env KEY=VALUE`.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Fork from a committed stage: its id, vanity name, or unique label prefix.
    /// The reserved word `base` starts fresh from the squashfs base with zero
    /// layers. Omit to keep the legacy dev-agent ext4 topology.
    #[arg(long)]
    stage: Option<String>,
    /// After a clean run, commit the scratch as a new stage with this label
    /// (requires `--stage`).
    #[arg(long = "commit-as", value_name = "LABEL")]
    commit_as: Option<String>,
    /// Squashfs base for the overlay topology: `base-sqfs` (busybox, the
    /// default) or `base-alpine` (python/node/git/gcc toolchain). Requires
    /// `--stage` — without it the run boots the legacy `--flavor` topology,
    /// which has no base, so a lone `--base` is a hard error (finding #16).
    #[arg(long)]
    base: Option<String>,
    /// Feed the command's stdin from a file (`-` for the host's stdin).
    #[arg(long = "stdin-file", value_name = "PATH")]
    stdin_file: Option<String>,
    /// Command to run, after `--`, e.g. `isopod run -- /bin/sh -c "echo hi"`.
    #[arg(last = true, required = true)]
    argv: Vec<String>,
}

#[derive(Subcommand)]
enum WarmpoolCommand {
    /// Force-build (or reuse) the warm-pool snapshot for a config
    Build {
        /// Squashfs base flavor to snapshot (`base-alpine` or `base-sqfs`).
        #[arg(long, default_value = "base-alpine")]
        base: String,
        /// Guest vCPU count the snapshot is captured at (must match runs that
        /// will resume it).
        #[arg(long, default_value_t = DEFAULT_VCPUS)]
        vcpus: u32,
        /// Guest memory in MiB the snapshot is captured at (a snapshot is bound
        /// to its exact memory size).
        #[arg(long = "mem-mib", default_value_t = DEFAULT_MEM_MIB)]
        mem_mib: u32,
    },
    /// List cached snapshots (key summary, sizes, created), newest first
    List,
    /// Remove a cached snapshot by keyhash (or `--all`)
    Rm {
        /// Snapshot keyhash (or a unique prefix). Omit with `--all`.
        keyhash: Option<String>,
        /// Remove every cached snapshot.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum StageCommand {
    /// List committed stages (oldest-first)
    List,
    /// Show a stage's full metadata and layer chain
    Info {
        /// Stage id, vanity name, or unique label prefix.
        reference: String,
    },
    /// Remove a stage (refused if another stage's chain references it)
    Rm {
        /// Stage id, vanity name, or unique label prefix.
        reference: String,
    },
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Fetch a prebuilt CI guest kernel (enumerates S3 prefixes; layout is date-stamped)
    FetchKernel {
        /// Kernel series (major.minor) to fetch.
        #[arg(long, default_value = "6.18")]
        series: String,
        /// Re-download even if a matching kernel is already present.
        #[arg(long)]
        force: bool,
    },
    /// Build the dev rootfs unprivileged (mkfs.ext4 -d)
    BuildRootfs {
        /// Rootfs flavor to build.
        #[arg(long, default_value = "dev-busybox")]
        flavor: String,
        /// Rebuild even if the image is already present.
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum DevCommand {
    /// Boot a throwaway dev VM, measure boot latency, verify liveness (M1 exit test)
    Boot {
        /// Keep the VM directory's throwaway rootfs copy instead of deleting it.
        #[arg(long)]
        keep: bool,
        /// Seconds to wait for the boot + liveness markers.
        #[arg(long = "timeout-s", default_value_t = 15)]
        timeout_s: u64,
        /// Rootfs flavor to boot (the liveness markers only fit `dev-busybox`).
        #[arg(long, default_value = "dev-busybox")]
        flavor: String,
    },
    /// Build the vendored Firecracker (v1.16.1) and install it to ~/.isopod/bin
    BuildFc,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Image { command } => run_image(command),
        Command::Dev { command } => run_dev(command),
        Command::Run(args) => run_run(args),
        Command::Stage { command } => run_stage(command),
        Command::Vm { command } => run_vm(command),
        Command::Warmpool { command } => run_warmpool(command),
        Command::Setup(args) => run_setup(args),
    };
    std::process::exit(code);
}

/// `isopod setup [--slots N] [--iface NAME] [--remove]` — the one-time
/// privileged host provisioning (run as root via sudo).
fn run_setup(args: SetupArgs) -> i32 {
    emit(isopod_core::net::setup::run(
        isopod_core::net::setup::SetupOptions {
            slots: args.slots,
            remove: args.remove,
            iface: args.iface,
            allow_lan_egress: args.allow_lan_egress,
        },
    ))
}

fn run_vm(cmd: VmCommand) -> i32 {
    match cmd {
        VmCommand::Ls => emit(
            isopod_core::vm::vm_list().map(|vms| serde_json::json!({ "ok": true, "vms": vms })),
        ),
        VmCommand::Gc { keep_last } => emit(isopod_core::vm::vm_gc(
            keep_last,
            std::time::Duration::from_secs(60),
        )),
    }
}

/// `isopod warmpool {build,list,rm}` — warm-pool snapshot management. Each
/// subcommand emits exactly one JSON object.
fn run_warmpool(cmd: WarmpoolCommand) -> i32 {
    match cmd {
        WarmpoolCommand::Build {
            base,
            vcpus,
            mem_mib,
        } => {
            emit(RootfsFlavor::from_slug(&base).and_then(|b| vm::warmpool_build(b, vcpus, mem_mib)))
        }
        WarmpoolCommand::List => emit(
            isopod_core::snapshot::list()
                .map(|snapshots| serde_json::json!({ "ok": true, "snapshots": snapshots })),
        ),
        WarmpoolCommand::Rm { keyhash, all } => {
            if all {
                emit(
                    isopod_core::snapshot::remove_all()
                        .map(|removed| serde_json::json!({ "ok": true, "removed": removed })),
                )
            } else if let Some(kh) = keyhash {
                emit(isopod_core::snapshot::remove(&kh).map(|m| {
                    serde_json::json!({ "ok": true, "removed": m.keyhash, "summary": m.summary })
                }))
            } else {
                emit::<()>(Err(anyhow::anyhow!(
                    "warmpool rm requires a <keyhash> argument or --all"
                )))
            }
        }
    }
}

fn run_image(cmd: ImageCommand) -> i32 {
    match cmd {
        ImageCommand::FetchKernel { series, force } => emit(image::fetch_kernel(&series, force)),
        ImageCommand::BuildRootfs { flavor, force } => {
            emit(RootfsFlavor::from_slug(&flavor).and_then(|f| image::build_rootfs(f, force)))
        }
    }
}

fn run_dev(cmd: DevCommand) -> i32 {
    match cmd {
        DevCommand::Boot {
            keep,
            timeout_s,
            flavor,
        } => emit(RootfsFlavor::from_slug(&flavor).and_then(|flavor| {
            vm::dev_boot(DevBootOptions {
                keep,
                timeout: Duration::from_secs(timeout_s),
                flavor,
            })
        })),
        // build-fc captures environment failures into a `{ok:false,…,findings}`
        // outcome, so route the exit code off the outcome's own `ok` flag rather
        // than treating a reportable build failure as an emit() error.
        DevCommand::BuildFc => match vm::build_fc() {
            Ok(outcome) => {
                let ok = outcome.ok;
                print_json(&outcome);
                if ok {
                    0
                } else {
                    1
                }
            }
            Err(e) => emit::<()>(Err(e)),
        },
    }
}

fn run_run(args: RunArgs) -> i32 {
    let result = (|| -> anyhow::Result<vm::RunReport> {
        let flavor = RootfsFlavor::from_slug(&args.flavor)?;
        // `--base` only means something on the stage/overlay topology; silently
        // booting the legacy dev-agent rootfs instead was dogfood finding #16.
        if args.base.is_some() && args.stage.is_none() {
            anyhow::bail!(
                "--base is only meaningful with --stage; pass `--stage base` to boot the \
                 squashfs/overlay topology, or drop --base to keep the legacy --flavor topology"
            );
        }
        let base_slug = args.base.as_deref().unwrap_or("base-sqfs");
        let base = RootfsFlavor::from_slug(base_slug)?;
        if !base.is_squashfs_base() {
            anyhow::bail!(
                "--base {base_slug} is not a squashfs base (use base-sqfs or base-alpine)"
            );
        }
        let env = vm::parse_env_kv(&args.env)?;
        let stdin = match &args.stdin_file {
            Some(p) if p == "-" => {
                use std::io::Read as _;
                let mut buf = Vec::new();
                std::io::stdin()
                    .read_to_end(&mut buf)
                    .context("reading stdin for --stdin-file -")?;
                Some(buf)
            }
            Some(p) => Some(std::fs::read(p).with_context(|| format!("reading {p}"))?),
            None => None,
        };
        vm::run_ephemeral(RunOptions {
            argv: args.argv,
            env,
            cwd: args.cwd,
            timeout_s: args.timeout_s,
            flavor,
            keep: args.keep,
            network: !args.no_network,
            stage: args.stage,
            commit_as: args.commit_as,
            base,
            stdin,
            vcpus: args.vcpus,
            mem_mib: args.mem_mib,
            scratch_mib: args.scratch_mib,
        })
    })();
    emit(result)
}

/// `isopod stage {list,info,rm}` — stage-store management. Each subcommand emits
/// exactly one JSON object.
fn run_stage(cmd: StageCommand) -> i32 {
    match cmd {
        StageCommand::List => {
            emit(stage::list().map(|stages| serde_json::json!({ "ok": true, "stages": stages })))
        }
        StageCommand::Info { reference } => emit((|| -> anyhow::Result<serde_json::Value> {
            let meta = stage::resolve(&reference)?;
            let layer_paths = stage::chain_paths(&meta)?;
            Ok(serde_json::json!({ "ok": true, "stage": meta, "layer_paths": layer_paths }))
        })()),
        StageCommand::Rm { reference } => {
            emit(stage::remove(&reference).map(
                |m| serde_json::json!({ "ok": true, "removed": m.stage_id, "label": m.label }),
            ))
        }
    }
}

/// Serialize `value` as the single stdout JSON line, falling back to a
/// `{ok:false,…}` object if serialization itself fails.
fn print_json<T: Serialize>(value: &T) {
    match serde_json::to_string(value) {
        Ok(json) => println!("{json}"),
        Err(e) => println!(
            "{}",
            serde_json::json!({"ok": false, "error": format!("serialize: {e}")})
        ),
    }
}

/// Print a success outcome (which itself carries `ok:true`) or a `{ok:false,…}`
/// error object as the single stdout JSON line; return the process exit code.
fn emit<T: Serialize>(result: anyhow::Result<T>) -> i32 {
    match result {
        Ok(value) => {
            print_json(&value);
            0
        }
        Err(e) => {
            eprintln!("error: {e:#}");
            println!(
                "{}",
                serde_json::json!({"ok": false, "error": format!("{e:#}")})
            );
            1
        }
    }
}
