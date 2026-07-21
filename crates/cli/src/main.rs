//! isopod — one-shot argv + JSON CLI.
//!
//! Convention (binding, see PLAN.md): every subcommand is non-interactive,
//! prints exactly one JSON object to stdout (human logs to stderr), and
//! persists any cross-invocation state under ~/.isopod so any caller
//! (Claude Code, human shell, CI) can resume.

use clap::{Parser, Subcommand};

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
    FetchKernel,
    /// Build the dev rootfs unprivileged (mkfs.ext4 -d)
    BuildRootfs,
}

#[derive(Subcommand)]
enum DevCommand {
    /// Boot a dev VM and stream its serial banner (M1 exit test)
    Boot,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Image { .. } | Command::Dev { .. } => {
            println!("{}", serde_json::json!({"ok": false, "error": "unimplemented (M1 in progress)"}));
            std::process::exit(2);
        }
    }
}
