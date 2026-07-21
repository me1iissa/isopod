//! isopod — one-shot argv + JSON CLI.
//!
//! Convention (binding, see PLAN.md): every subcommand is non-interactive,
//! prints exactly one JSON object to stdout (human logs to stderr), and
//! persists any cross-invocation state under ~/.isopod so any caller
//! (Claude Code, human shell, CI) can resume.

use std::time::Duration;

use clap::{Parser, Subcommand};
use isopod_core::image::{self, RootfsFlavor};
use isopod_core::vm::{self, DevBootOptions};
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
    },
    /// Build the vendored Firecracker (v1.16.1) and install it to ~/.isopod/bin
    BuildFc,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Image { command } => run_image(command),
        Command::Dev { command } => run_dev(command),
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
        DevCommand::Boot { keep, timeout_s } => emit(vm::dev_boot(DevBootOptions {
            keep,
            timeout: Duration::from_secs(timeout_s),
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
