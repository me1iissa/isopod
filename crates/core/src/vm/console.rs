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

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc::UnboundedSender;

/// Ceiling on bytes persisted to a serial console log. Serial output is fully
/// guest-controlled, so an uncapped tee is a host-disk DoS (F3); beyond the cap
/// the pipe is still drained (the VMM must never block on a full stdout pipe)
/// but the bytes are discarded.
pub(crate) const SERIAL_LOG_CAP: u64 = 16 * 1024 * 1024;

/// Marker appended to a console log when [`SERIAL_LOG_CAP`] trips.
const SERIAL_TRUNCATED_MARKER: &[u8] =
    b"\n[isopod: serial log cap reached; further output was not persisted]\n";

/// Longest single serial line buffered for marker detection; a guest emitting
/// an endless line without newlines must not grow host memory (F3). Bytes past
/// the cap are dropped from the buffered line (the head is enough to classify).
const MAX_LINE_LEN: usize = 64 * 1024;

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

/// Persist one serial line (newline restored) to `log`, respecting the
/// [`SERIAL_LOG_CAP`] byte budget in `written`. Returns the truncation state.
async fn persist_line(
    log: &mut tokio::fs::File,
    written: &mut u64,
    truncated: bool,
    line: &str,
) -> bool {
    if truncated {
        return true;
    }
    if *written >= SERIAL_LOG_CAP {
        let _ = log.write_all(SERIAL_TRUNCATED_MARKER).await;
        return true;
    }
    let _ = log.write_all(line.as_bytes()).await;
    let _ = log.write_all(b"\n").await;
    *written = written.saturating_add(line.len() as u64 + 1);
    false
}

/// Drain Firecracker's piped stdout (the relayed guest serial console): persist
/// every line to `log` (up to [`SERIAL_LOG_CAP`]; F3), and forward each line —
/// stamped with the instant it was read — over `tx` for marker detection.
/// Returns when the pipe reaches EOF (i.e. the VMM has exited).
///
/// fc-client's `StdioMode` has no direct file-redirect variant, so the pump is
/// how serial output reaches `console.log`. Lines are split manually (rather
/// than with a growable line reader) so a guest emitting an endless unbroken
/// line cannot grow host memory: only the first [`MAX_LINE_LEN`] bytes of a
/// line are buffered, the rest is dropped.
pub(crate) async fn drain_serial<R: AsyncRead + Unpin>(
    mut stdout: R,
    mut log: tokio::fs::File,
    tx: UnboundedSender<(Instant, String)>,
) {
    let mut buf = [0u8; 8192];
    let mut line_buf: Vec<u8> = Vec::new();
    let mut written: u64 = 0;
    let mut truncated = false;
    loop {
        match stdout.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                for &byte in &buf[..n] {
                    if byte == b'\n' {
                        let line = String::from_utf8_lossy(&line_buf).into_owned();
                        line_buf.clear();
                        truncated = persist_line(&mut log, &mut written, truncated, &line).await;
                        // A send error just means the boot watcher already gave up.
                        let _ = tx.send((Instant::now(), line));
                    } else if line_buf.len() < MAX_LINE_LEN {
                        line_buf.push(byte);
                    }
                }
            }
        }
    }
    // A trailing partial line (EOF without a newline) still counts.
    if !line_buf.is_empty() {
        let line = String::from_utf8_lossy(&line_buf).into_owned();
        let _ = persist_line(&mut log, &mut written, truncated, &line).await;
        let _ = tx.send((Instant::now(), line));
    }
    let _ = log.flush().await;
}

/// Tee Firecracker's piped stdout (the relayed guest serial console) verbatim
/// into `log` — up to [`SERIAL_LOG_CAP`] bytes (F3); the pipe keeps draining
/// beyond the cap so the VMM never blocks, but the bytes are discarded — until
/// the pipe reaches EOF (the VMM exited). Unlike [`drain_serial`], no marker
/// channel is involved — the ephemeral run flow keys readiness off the vsock
/// ping, so serial is retained purely for inspection.
pub(crate) async fn drain_to_log<R: AsyncRead + Unpin>(mut stdout: R, mut log: tokio::fs::File) {
    let mut buf = [0u8; 8192];
    let mut written: u64 = 0;
    let mut truncated = false;
    loop {
        match stdout.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if truncated {
                    continue; // keep draining; discard beyond the cap
                }
                let room = SERIAL_LOG_CAP.saturating_sub(written);
                let take = (n as u64).min(room) as usize;
                if log.write_all(&buf[..take]).await.is_err() {
                    break;
                }
                written = written.saturating_add(take as u64);
                if take < n {
                    let _ = log.write_all(SERIAL_TRUNCATED_MARKER).await;
                    truncated = true;
                }
            }
        }
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

    #[tokio::test]
    async fn drain_to_log_caps_persisted_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let log = tokio::fs::File::create(&path).await.unwrap();
        // 100 bytes past the cap: the tail must be drained but not persisted.
        let input = vec![b'x'; SERIAL_LOG_CAP as usize + 100];
        drain_to_log(input.as_slice(), log).await;
        let written = std::fs::read(&path).unwrap();
        assert_eq!(
            written.len(),
            SERIAL_LOG_CAP as usize + SERIAL_TRUNCATED_MARKER.len()
        );
        assert!(written.ends_with(SERIAL_TRUNCATED_MARKER));
    }

    #[tokio::test]
    async fn drain_serial_bounds_an_endless_line_and_flushes_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console.log");
        let log = tokio::fs::File::create(&path).await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        // One normal marker line, then an unbroken flood twice the line cap
        // ending at EOF without a newline.
        let mut input = b"ISOPOD-BOOT-COMPLETE uptime=1.0\n".to_vec();
        input.extend(std::iter::repeat_n(b'y', MAX_LINE_LEN * 2));
        drain_serial(input.as_slice(), log, tx).await;

        let (_, first) = rx.recv().await.unwrap();
        assert_eq!(classify_line(&first), Marker::BootComplete);
        // The flood arrives as one line, capped at MAX_LINE_LEN.
        let (_, flood) = rx.recv().await.unwrap();
        assert_eq!(flood.len(), MAX_LINE_LEN);
        assert!(rx.recv().await.is_none());
        // Both lines were persisted (well under the serial byte cap).
        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.starts_with("ISOPOD-BOOT-COMPLETE"));
        assert_eq!(
            written.len(),
            first.len() + 1 + MAX_LINE_LEN + 1,
            "persisted bytes must match the two capped lines"
        );
    }
}
