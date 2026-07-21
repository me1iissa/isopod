//! isopod — one-shot argv + JSON CLI.
//!
//! Convention (binding, see PLAN.md): every subcommand is non-interactive,
//! prints exactly one JSON object to stdout (human logs to stderr), and
//! persists any cross-invocation state under ~/.isopod so any caller
//! (Claude Code, human shell, CI) can resume.

use clap::{Parser, Subcommand};
use isopod_core::image::{self, RootfsFlavor};
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
    /// Boot a dev VM and stream its serial banner (M1 exit test)
    Boot,
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
        DevCommand::Boot => {
            println!(
                "{}",
                serde_json::json!({"ok": false, "error": "unimplemented (M1 in progress)"})
            );
            2
        }
    }
}

/// Print a success outcome (which itself carries `ok:true`) or a `{ok:false,…}`
/// error object as the single stdout JSON line; return the process exit code.
fn emit<T: Serialize>(result: anyhow::Result<T>) -> i32 {
    match result {
        Ok(value) => match serde_json::to_string(&value) {
            Ok(json) => {
                println!("{json}");
                0
            }
            Err(e) => {
                println!(
                    "{}",
                    serde_json::json!({"ok": false, "error": format!("serialize: {e}")})
                );
                1
            }
        },
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
