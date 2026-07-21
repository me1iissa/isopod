//! isopod-guest-agent — PID 1 inside the isopod guest microVM.
//!
//! A std-only, statically-linked musl binary that Firecracker runs as `/sbin/init`.
//! Its duties, in order:
//!
//! 1. Mount the pseudo-filesystems (`devtmpfs`, `proc`, `sysfs`), tolerating the
//!    kernel having auto-mounted them.
//! 2. If the kernel command line requests the stage topology
//!    (`isopod.layers=<N>`), assemble the overlay root over the squashfs base +
//!    committed stage layers + writable scratch and `pivot_root` into it
//!    ([`overlay`]); otherwise boot the writable ext4 root as before.
//! 3. Emit the boot markers the host console parser keys on: `ISOPOD-INIT-START`
//!    then `ISOPOD-BOOT-COMPLETE uptime=<s>`.
//! 4. Start a 1 Hz `TICK <uptime>` liveness loop (restore-continuity proof).
//! 5. Start the single zombie-reaping thread (PID-1 duty).
//! 6. Serve the [`isopod_proto`] RPC on vsock port [`isopod_proto::VSOCK_PORT`]
//!    forever.
//!
//! `unsafe` is unavoidable for the libc calls PID 1 must make; it is confined to
//! [`sys`], which exposes safe wrappers to the rest of the crate.

mod conn;
mod exec;
mod overlay;
mod reaper;
mod server;
mod sys;

use std::time::Duration;

/// Pseudo-filesystems to mount at boot: `(source, target, fstype)`.
const PSEUDO_MOUNTS: &[(&str, &str, &str)] = &[
    ("devtmpfs", "/dev", "devtmpfs"),
    ("proc", "/proc", "proc"),
    ("sysfs", "/sys", "sysfs"),
];

fn main() {
    // PID 1 must not die on a write to a hung-up connection.
    sys::ignore_sigpipe();

    mount_pseudo_filesystems();

    // With the stage topology (`isopod.layers=<N>` on the cmdline) this builds
    // the overlay root over the squashfs base + committed layers + scratch and
    // pivots into it; without it, the ext4 root is used unchanged.
    overlay::assemble_if_requested();

    server::print_marker("ISOPOD-INIT-START");
    server::print_marker(&format!(
        "ISOPOD-BOOT-COMPLETE uptime={:.2}",
        server::read_uptime()
    ));
    if sys::getpid() != 1 {
        server::log(&format!(
            "warning: not running as PID 1 (pid={}); reaping semantics assume PID 1",
            sys::getpid()
        ));
    }

    spawn_tick_thread();

    let reaper = reaper::Reaper::new();
    reaper.spawn();

    // Serves forever; never returns.
    server::serve(reaper);
}

/// Mount `devtmpfs`, `proc`, and `sysfs`. `EBUSY` (already mounted by the kernel)
/// is expected and ignored; any other error is logged but non-fatal — the agent
/// still comes up so it can report the problem over RPC.
///
/// Called once on the base root at boot, and again by [`overlay`] on the new
/// root after `pivot_root` (the base-root mounts leave with the old root).
pub(crate) fn mount_pseudo_filesystems() {
    for (source, target, fstype) in PSEUDO_MOUNTS {
        match sys::mount(source, target, fstype) {
            Ok(_) => {}
            Err(e) => server::log(&format!("mount {fstype} on {target} failed: {e}")),
        }
    }
}

/// Emit `TICK <uptime>` every second on serial — the same liveness shape as the
/// busybox flavor, and the proof a restored VM resumed rather than rebooted.
fn spawn_tick_thread() {
    let _ = std::thread::Builder::new()
        .name("tick".to_string())
        .spawn(|| loop {
            server::print_marker(&format!("TICK {:.2}", server::read_uptime()));
            std::thread::sleep(Duration::from_secs(1));
        });
}
