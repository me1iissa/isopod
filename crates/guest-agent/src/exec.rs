//! Command execution with streamed output, in-guest timeout, and PID-1-safe
//! reaping (statuses come from the [`Reaper`], never `Child::wait`).

use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use isopod_proto::{
    b64_decode, b64_encode, ExecRequest, ExecStreamKind, Response, ResponseBody, EXEC_CHUNK_LEN,
};

use crate::conn::Conn;
use crate::reaper::Reaper;
use crate::sys::{self, WaitResult};

/// Baseline environment every exec starts from; the request's `env` is applied
/// on top and may override these.
const BASE_ENV: &[(&str, &str)] = &[
    ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
    ("HOME", "/root"),
    ("TERM", "linux"),
];

/// Default working directory when the request does not specify one.
const DEFAULT_CWD: &str = "/root";

/// Handle an `Exec` request end-to-end: stream `ExecStream` frames, then exactly
/// one terminal `ExecDone` frame.
///
/// A spawn failure (command not found, not executable, bad cwd) is a *command*
/// outcome, not an infrastructure fault: it reports shell convention
/// `exit_code: 127` with the reason on stderr, so callers can distinguish "your
/// command is wrong" from "the sandbox broke" (dogfood finding #3). `Error`
/// frames are reserved for malformed requests (e.g. empty argv).
pub fn handle_exec(conn: &Conn, id: u64, req: ExecRequest, reaper: &Reaper) {
    if let Err(e) = run_exec(conn, id, &req, reaper) {
        if req.argv.is_empty() {
            let _ = conn.send(&Response {
                id,
                body: ResponseBody::Error {
                    message: format!("exec: {e}"),
                },
            });
            return;
        }
        let reason = format!("isopod-exec: {}: {e}\n", req.argv[0]);
        let _ = conn.send(&Response {
            id,
            body: ResponseBody::ExecStream {
                stream: ExecStreamKind::Stderr,
                data_b64: isopod_proto::b64_encode(reason.as_bytes()),
            },
        });
        let _ = conn.send(&Response {
            id,
            body: ResponseBody::ExecDone {
                exit_code: Some(127),
                signal: None,
                duration_ms: 0,
                timed_out: false,
            },
        });
    }
}

fn run_exec(conn: &Conn, id: u64, req: &ExecRequest, reaper: &Reaper) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let start = Instant::now();
    let (program, args) = req
        .argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty argv"))?;

    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.env_clear();
    for (k, v) in BASE_ENV {
        cmd.env(k, v);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    cmd.current_dir(req.cwd.as_deref().unwrap_or(DEFAULT_CWD));

    let has_stdin = req.stdin_b64.is_some();
    cmd.stdin(if has_stdin {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    // Own process group so a timeout can SIGKILL the whole tree with kill(-pgid).
    cmd.process_group(0);

    let mut child = cmd.spawn()?;
    let pid = child.id() as i32;
    // Register with the reaper *immediately* after spawn, before we do anything
    // slower; the reaper's stash closes the residual race for instant exits.
    let exit_rx = reaper.register(pid);

    // Feed stdin from a detached thread so a large payload cannot deadlock us
    // against a child that is slow to read it.
    if let (Some(mut stdin), Some(b64)) = (child.stdin.take(), req.stdin_b64.clone()) {
        std::thread::spawn(move || {
            if let Ok(bytes) = b64_decode(&b64) {
                let _ = stdin.write_all(&bytes);
            }
            // Dropping `stdin` closes the pipe, signalling EOF to the child.
        });
    }

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // We must never wait on `child`; the reaper owns its status. Dropping a
    // `std::process::Child` neither waits nor kills, so this is safe — the pipes
    // we still need were already taken above.
    drop(child);

    let out_thread = stdout.map(|s| {
        let c = conn.clone_handle();
        std::thread::spawn(move || stream_reader(s, &c, id, ExecStreamKind::Stdout))
    });
    let err_thread = stderr.map(|s| {
        let c = conn.clone_handle();
        std::thread::spawn(move || stream_reader(s, &c, id, ExecStreamKind::Stderr))
    });

    let mut timed_out = false;
    let exit = match req.timeout_ms {
        Some(ms) => match exit_rx.recv_timeout(Duration::from_millis(ms)) {
            Ok(res) => res,
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                let _ = sys::kill_group(pid);
                // Wait for the real reaped status now that the group is dying.
                exit_rx.recv().unwrap_or(WaitResult {
                    pid,
                    exit_code: None,
                    signal: Some(sys::SIGKILL),
                })
            }
            Err(RecvTimeoutError::Disconnected) => WaitResult {
                pid,
                exit_code: None,
                signal: None,
            },
        },
        None => exit_rx.recv().unwrap_or(WaitResult {
            pid,
            exit_code: None,
            signal: None,
        }),
    };

    // Join the output pumps so every `ExecStream` frame precedes `ExecDone`.
    if let Some(t) = out_thread {
        let _ = t.join();
    }
    if let Some(t) = err_thread {
        let _ = t.join();
    }

    let duration_ms = start.elapsed().as_millis() as u64;
    conn.send(&Response {
        id,
        body: ResponseBody::ExecDone {
            exit_code: exit.exit_code,
            signal: exit.signal,
            duration_ms,
            timed_out,
        },
    })
    .map_err(io::Error::other)?;
    Ok(())
}

/// Pump one output stream: read raw bytes (≤ [`EXEC_CHUNK_LEN`] per read) and
/// forward each non-empty chunk as a base64 `ExecStream` frame. Stops on EOF or
/// the first send failure (dead connection).
fn stream_reader<R: Read>(mut r: R, conn: &Conn, id: u64, stream: ExecStreamKind) {
    let mut buf = [0u8; EXEC_CHUNK_LEN];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let resp = Response {
                    id,
                    body: ResponseBody::ExecStream {
                        stream,
                        data_b64: b64_encode(&buf[..n]),
                    },
                };
                if conn.send(&resp).is_err() {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}
