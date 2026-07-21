//! isopod — one-shot argv + JSON CLI.
//!
//! Convention (binding, see PLAN.md): every subcommand is non-interactive,
//! prints exactly one JSON object to stdout (human logs to stderr), and
//! persists any cross-invocation state under ~/.isopod so any caller
//! (Claude Code, human shell, CI) can resume.

use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use isopod_core::image::{self, RootfsFlavor};
use isopod_core::vm::{self, DevBootOptions, RunOptions, DEFAULT_RUN_FLAVOR};
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
}

#[derive(Args)]
struct RunArgs {
    /// Outer wall-clock budget in seconds (covers boot + exec).
    #[arg(long = "timeout-s", default_value_t = 120)]
    timeout_s: u64,
    /// Rootfs flavor to boot.
    #[arg(long, default_value = DEFAULT_RUN_FLAVOR)]
    flavor: String,
    /// Keep the VM directory's throwaway rootfs copy instead of deleting it.
    #[arg(long)]
    keep: bool,
    /// Working directory inside the guest (default `/root`).
    #[arg(long)]
    cwd: Option<String>,
    /// Environment variable to set (repeatable): `--env KEY=VALUE`.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    env: Vec<String>,
    /// Command to run, after `--`, e.g. `isopod run -- /bin/sh -c "echo hi"`.
    #[arg(last = true, required = true)]
    argv: Vec<String>,
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
    };
    std::process::exit(code);
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
        let env = vm::parse_env_kv(&args.env)?;
        vm::run_ephemeral(RunOptions {
            argv: args.argv,
            env,
            cwd: args.cwd,
            timeout_s: args.timeout_s,
            flavor,
            keep: args.keep,
            network: true,
        })
    })();
    emit(result)
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
