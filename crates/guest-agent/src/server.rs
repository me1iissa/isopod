//! The vsock RPC server: accept loop, per-connection dispatch, and the
//! non-exec operations (ping, clock sync, file transfer, halt).

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use isopod_proto::{
    b64_decode, b64_encode, Request, RequestOp, Response, ResponseBody, PROTO_VERSION, VSOCK_PORT,
};

use crate::conn::Conn;
use crate::exec;
use crate::reaper::Reaper;
use crate::sys;

/// Give a `Halt` acknowledgement time to drain to the host over vsock before the
/// device is torn down by power-off.
const HALT_DRAIN: Duration = Duration::from_millis(100);

/// Bind the vsock listener and serve connections forever. Never returns: if the
/// listener cannot be created, PID 1 parks rather than exiting (a PID-1 exit
/// panics the kernel).
pub fn serve(reaper: Reaper) -> ! {
    let listener = match sys::vsock_listener(VSOCK_PORT) {
        Ok(l) => l,
        Err(e) => {
            log(&format!(
                "FATAL: could not listen on vsock port {VSOCK_PORT}: {e}"
            ));
            park_forever();
        }
    };
    log(&format!("vsock server listening on port {VSOCK_PORT}"));
    let listener_fd = listener.as_raw_fd();

    loop {
        match sys::accept(listener_fd) {
            Ok(fd) => {
                let conn = Conn::from_fd(fd);
                let reaper = reaper.clone();
                let _ = std::thread::Builder::new()
                    .name("vsock-conn".to_string())
                    .spawn(move || serve_connection(conn, &reaper));
            }
            Err(e) => {
                log(&format!("vsock accept failed: {e}"));
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Handle one connection: dispatch request frames until EOF or a framing error.
fn serve_connection(conn: Conn, reaper: &Reaper) {
    loop {
        match conn.read_request() {
            Ok(Some(req)) => dispatch(&conn, req, reaper),
            Ok(None) => break, // clean EOF: peer closed the connection
            Err(e) => {
                log(&format!("connection dropped on frame error: {e}"));
                break;
            }
        }
    }
}

fn dispatch(conn: &Conn, req: Request, reaper: &Reaper) {
    let id = req.id;
    match req.op {
        RequestOp::Ping => {
            let _ = conn.send(&Response {
                id,
                body: ResponseBody::Pong {
                    agent_version: env!("CARGO_PKG_VERSION").to_string(),
                    proto_version: PROTO_VERSION,
                    uptime_s: read_uptime(),
                },
            });
        }
        RequestOp::Exec(exec_req) => exec::handle_exec(conn, id, exec_req, reaper),
        RequestOp::SyncClock { unix_secs, nanos } => {
            let res = sys::set_realtime(unix_secs as i64, nanos as i64);
            reply(conn, id, res.map(|()| ResponseBody::Ok));
        }
        RequestOp::PutFile {
            path,
            mode,
            data_b64,
        } => {
            reply(
                conn,
                id,
                put_file(&path, mode, &data_b64).map(|()| ResponseBody::Ok),
            );
        }
        RequestOp::GetFile { path, max_bytes } => {
            reply(conn, id, get_file(&path, max_bytes));
        }
        RequestOp::Halt { sync } => halt(conn, id, sync),
    }
}

/// Send `body` on success, or an `Error` frame carrying the failure message.
fn reply(conn: &Conn, id: u64, res: io::Result<ResponseBody>) {
    let body = res.unwrap_or_else(|e| ResponseBody::Error {
        message: e.to_string(),
    });
    let _ = conn.send(&Response { id, body });
}

fn put_file(path: &str, mode: u32, data_b64: &str) -> io::Result<()> {
    let bytes = b64_decode(data_b64).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(p, &bytes)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn get_file(path: &str, max_bytes: u64) -> io::Result<ResponseBody> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "file {path} is {} bytes, exceeds max_bytes {max_bytes}",
                meta.len()
            ),
        ));
    }
    let bytes = std::fs::read(path)?;
    Ok(ResponseBody::File {
        data_b64: b64_encode(&bytes),
        mode: meta.permissions().mode(),
    })
}

/// Acknowledge, let the reply drain, then sync + stop the VM. Does not return on
/// success (Firecracker tears the microVM down on the guest reset).
fn halt(conn: &Conn, id: u64, sync: bool) {
    let _ = conn.send(&Response {
        id,
        body: ResponseBody::Ok,
    });
    // The Ok frame was flushed by `send`; give the vsock device a moment to push
    // it to the host before we tear the machine down.
    std::thread::sleep(HALT_DRAIN);
    if sync {
        sys::sync();
    }
    let e = sys::stop_vm();
    // Only reached if the reboot syscall failed (e.g. missing CAP_SYS_BOOT).
    log(&format!("stop_vm returned unexpectedly: {e}"));
}

/// Guest uptime in seconds, read from `/proc/uptime` (monotonic across snapshot
/// restore — the restore-continuity signal). Returns 0.0 if unreadable.
pub fn read_uptime() -> f64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next().map(str::to_owned))
        .and_then(|t| t.parse::<f64>().ok())
        .unwrap_or(0.0)
}

/// Print a boot/liveness marker line to serial (stdout), flushed immediately.
/// The host console parser keys on these exact prefixes.
pub fn print_marker(line: &str) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

/// Log a diagnostic to serial (stderr). Prefixed so it never collides with the
/// `ISOPOD-*` / `TICK ` markers the host parses.
pub fn log(msg: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "[isopod-agent] {msg}");
    let _ = err.flush();
}

/// Park the current thread forever without exiting (used when the server cannot
/// start — PID 1 must never return).
fn park_forever() -> ! {
    loop {
        std::thread::park();
    }
}
