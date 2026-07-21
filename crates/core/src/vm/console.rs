//! Guest serial console handling: marker parsing and the async pump that tees
//! Firecracker's piped stdout into `console.log` while surfacing timestamped
//! lines for boot-liveness detection.
//!
//! The `dev-busybox` rootfs init (see [`crate::image`]) emits two markers on the
//! serial console that `isopod dev boot` keys on:
//!
//! * `ISOPOD-BOOT-COMPLETE uptime=…` — printed once, right after the guest has
//!   mounted its pseudo-filesystems; the boot-latency stopwatch stops here.
//! * `TICK <uptime>` — printed every second by a respawned liveness loop; two of
//!   these prove the guest kept running past the boot marker.

use std::time::Instant;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdout;
use tokio::sync::mpsc::UnboundedSender;

/// A classified serial-console line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Marker {
    /// The one-shot `ISOPOD-BOOT-COMPLETE` boot marker.
    BootComplete,
    /// A `TICK <uptime>` liveness line.
    Tick,
    /// Any other output (kernel messages, sysinit banners, …).
    Other,
}

/// Classify a single serial line, tolerating a trailing `\r` (serial consoles
/// emit CRLF) and leading/trailing whitespace.
pub(crate) fn classify_line(line: &str) -> Marker {
    let l = line.trim();
    if l.contains("ISOPOD-BOOT-COMPLETE") {
        Marker::BootComplete
    } else if l.starts_with("TICK ") {
        Marker::Tick
    } else {
        Marker::Other
    }
}

/// Aggregate marker counts scanned from a block of console text. Used by the
/// offline fixture test; the live path uses [`classify_line`] incrementally.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MarkerScan {
    /// Whether an `ISOPOD-BOOT-COMPLETE` line was seen.
    pub boot_complete: bool,
    /// Number of `TICK` lines seen.
    pub ticks: u32,
}

/// Scan a whole console-log blob for boot/liveness markers.
#[cfg(test)]
pub(crate) fn scan_lines(text: &str) -> MarkerScan {
    let mut scan = MarkerScan::default();
    for line in text.lines() {
        match classify_line(line) {
            Marker::BootComplete => scan.boot_complete = true,
            Marker::Tick => scan.ticks += 1,
            Marker::Other => {}
        }
    }
    scan
}

/// Drain Firecracker's piped stdout (the relayed guest serial console): persist
/// every line to `log`, and forward each line — stamped with the instant it was
/// read — over `tx` for marker detection. Returns when the pipe reaches EOF
/// (i.e. the VMM has exited).
///
/// fc-client's `StdioMode` has no direct file-redirect variant, so the pump is
/// how serial output reaches `console.log`.
pub(crate) async fn drain_serial(
    stdout: ChildStdout,
    mut log: tokio::fs::File,
    tx: UnboundedSender<(Instant, String)>,
) {
    let mut lines = BufReader::new(stdout).lines();
    // Loop ends on EOF (VMM exited) or a read error — both leave the `Ok(Some)`
    // pattern, so `while let` is the right shape.
    while let Ok(Some(line)) = lines.next_line().await {
        // Persist the raw line verbatim (plus the newline lines() stripped).
        let _ = log.write_all(line.as_bytes()).await;
        let _ = log.write_all(b"\n").await;
        // A send error just means the boot watcher already gave up.
        let _ = tx.send((Instant::now(), line));
    }
    let _ = log.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_boot_complete_with_uptime() {
        assert_eq!(
            classify_line("ISOPOD-BOOT-COMPLETE uptime=1.23 4.56"),
            Marker::BootComplete
        );
        // Tolerates the CRLF a serial console appends.
        assert_eq!(
            classify_line("ISOPOD-BOOT-COMPLETE uptime=1.23\r"),
            Marker::BootComplete
        );
    }

    #[test]
    fn classifies_tick() {
        assert_eq!(classify_line("TICK 3.14 2.71"), Marker::Tick);
        assert_eq!(classify_line("  TICK 9.0\r"), Marker::Tick);
        // "TICK" without an uptime payload is not a liveness tick.
        assert_eq!(classify_line("TICKER"), Marker::Other);
    }

    #[test]
    fn classifies_other_lines_as_other() {
        for line in [
            "ISOPOD-INIT-START",
            "ISOPOD-SYSINIT",
            "[    0.123456] Run /init as init process",
            "",
        ] {
            assert_eq!(classify_line(line), Marker::Other, "line was {line:?}");
        }
    }

    #[test]
    fn scans_fixture_console_log() {
        // A representative slice of dev-busybox serial output (CRLF included).
        let fixture = "[    0.101] Linux version 6.18.36\r\n\
             ISOPOD-INIT-START\r\n\
             ISOPOD-BOOT-COMPLETE uptime=0.42 1.90\r\n\
             ISOPOD-SYSINIT\r\n\
             TICK 0.55 1.90\r\n\
             TICK 1.56 3.80\r\n\
             TICK 2.57 5.70\r\n";
        let scan = scan_lines(fixture);
        assert!(scan.boot_complete, "boot marker must be detected");
        assert_eq!(scan.ticks, 3, "should count exactly three TICK lines");
    }

    #[test]
    fn scan_without_boot_marker() {
        let scan = scan_lines("kernel panic - not syncing\nTICK 1.0 2.0\n");
        assert!(!scan.boot_complete);
        assert_eq!(scan.ticks, 1);
    }
}
