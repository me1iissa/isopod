//! Safe wrappers over the handful of raw `libc` calls the agent needs as PID 1.
//!
//! Every `unsafe` block in the whole crate lives in this module. Each wrapper
//! documents why its call is sound; callers elsewhere in the agent never touch
//! `libc` directly and never write `unsafe`.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

/// The `SIGKILL` signal number (the only signal the agent ever raises).
pub const SIGKILL: i32 = libc::SIGKILL;

/// Outcome of a single `waitpid(-1)` reap.
#[derive(Debug, Clone, Copy)]
pub struct WaitResult {
    /// Pid that changed state.
    pub pid: i32,
    /// Exit code if the child exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal if the child was killed by a signal.
    pub signal: Option<i32>,
}

/// Result of a blocking wait for any child.
#[derive(Debug, Clone, Copy)]
pub enum Reap {
    /// A child changed state and was reaped.
    Child(WaitResult),
    /// No children exist right now (`ECHILD`); caller should back off.
    NoChildren,
    /// The wait was interrupted by a signal (`EINTR`); caller should retry.
    Interrupted,
}

fn cstr(s: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Set `SIGPIPE` to `SIG_IGN` so a write to a hung-up vsock connection returns
/// `EPIPE` instead of killing PID 1 (whose default `SIGPIPE` action is fatal).
///
/// Rust's std already installs this at startup, but PID 1 cannot afford to rely
/// on that implementation detail, so the agent sets it explicitly.
pub fn ignore_sigpipe() {
    // SAFETY: installing `SIG_IGN` for `SIGPIPE` is always valid and has no
    // memory-safety preconditions.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Mount `fstype` at `target`.
///
/// Returns `Ok(true)` if the mount happened, `Ok(false)` if `target` was already
/// mounted (`EBUSY` — e.g. the kernel auto-mounted devtmpfs via
/// `CONFIG_DEVTMPFS_MOUNT`), and `Err` for any other failure.
pub fn mount(source: &str, target: &str, fstype: &str) -> io::Result<bool> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = cstr(fstype)?;
    // SAFETY: the three pointers reference NUL-terminated C strings that outlive
    // the call; flags are 0 and the fs-options pointer is NULL (no per-fs data),
    // both valid for these virtual filesystems.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EBUSY) {
        Ok(false)
    } else {
        Err(err)
    }
}

/// Flush all filesystem buffers to disk (`sync(2)`).
pub fn sync() {
    // SAFETY: `sync` takes no arguments, has no failure mode, and cannot violate
    // memory safety.
    unsafe { libc::sync() }
}

/// Stop the microVM from inside the guest so Firecracker exits.
///
/// Firecracker implements no guest power-management: `RB_POWER_OFF` finds no
/// `pm_power_off` handler and the kernel merely halts the CPU ("Power off not
/// available: System halted instead"), leaving the VMM running. Firecracker
/// instead terminates the microVM on a guest **reset**, so we request a restart
/// (`RB_AUTOBOOT`); with the `reboot=k` boot arg the kernel drives the i8042
/// reset line, which Firecracker traps and then exits.
///
/// On success this call does not return (the VM is torn down). A returned
/// [`io::Error`] means the syscall itself failed (e.g. missing `CAP_SYS_BOOT`).
pub fn stop_vm() -> io::Error {
    // SAFETY: `RB_AUTOBOOT` is a valid reboot command constant; the libc wrapper
    // supplies the required magic numbers. No pointers are involved.
    unsafe {
        libc::reboot(libc::RB_AUTOBOOT);
    }
    io::Error::last_os_error()
}

/// Set the system real-time clock (`clock_settime(CLOCK_REALTIME, …)`).
pub fn set_realtime(secs: i64, nanos: i64) -> io::Result<()> {
    // `as _` lets the struct-field types drive the cast, avoiding the
    // musl-deprecated `libc::time_t` / `libc::c_long` alias names directly.
    let ts = libc::timespec {
        tv_sec: secs as _,
        tv_nsec: nanos as _,
    };
    // SAFETY: `&ts` points to a fully initialized `timespec` that outlives the
    // call; `CLOCK_REALTIME` is a valid clock id.
    let rc = unsafe { libc::clock_settime(libc::CLOCK_REALTIME, &ts) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Create, bind, and listen an `AF_VSOCK` stream socket on `port`, bound to
/// `VMADDR_CID_ANY` so it accepts host-initiated connections.
pub fn vsock_listener(port: u32) -> io::Result<OwnedFd> {
    // SAFETY: a `socket` call with a valid domain/type/protocol triple; it
    // returns a new fd or -1, checked below.
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor we exclusively own; wrapping it in an
    // `OwnedFd` now guarantees it is closed on every early return below.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };

    // SAFETY: `sockaddr_vm` is a plain-old-data struct; an all-zero bit pattern
    // is a valid (empty) value that we immediately fill in.
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    addr.svm_port = port;
    addr.svm_cid = libc::VMADDR_CID_ANY;

    use std::os::fd::AsRawFd;
    // SAFETY: `addr` is a fully initialized `sockaddr_vm`; we pass a pointer to
    // it and its exact size, as `bind` requires.
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `owned` holds a valid bound socket; the backlog is positive.
    let rc = unsafe { libc::listen(owned.as_raw_fd(), 128) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(owned)
}

/// Accept the next connection on a listening socket, returning an owned fd.
pub fn accept(listener: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: `listener` is a valid listening socket for the duration of the
    // call; passing NULL addr/len is valid and means "don't report the peer".
    let fd = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a fresh descriptor we now exclusively own.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

/// Block until any child changes state and reap it (`waitpid(-1, …, 0)`).
pub fn wait_any_blocking() -> Reap {
    let mut status: libc::c_int = 0;
    // SAFETY: `-1` waits for any child; `&mut status` is a valid, writable int
    // pointer for the call; flags 0 requests a blocking wait.
    let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
    if pid > 0 {
        return Reap::Child(decode_status(pid, status));
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ECHILD) => Reap::NoChildren,
        Some(libc::EINTR) => Reap::Interrupted,
        // Any other error is unexpected; treat it as "no children" so the reaper
        // backs off rather than spinning.
        _ => Reap::NoChildren,
    }
}

/// Decode a raw `waitpid` status word into exit code / terminating signal.
fn decode_status(pid: i32, status: libc::c_int) -> WaitResult {
    // The `WIF*` helpers are safe const fns operating on the status integer.
    let (exit_code, signal) = if libc::WIFEXITED(status) {
        (Some(libc::WEXITSTATUS(status)), None)
    } else if libc::WIFSIGNALED(status) {
        (None, Some(libc::WTERMSIG(status)))
    } else {
        (None, None)
    };
    WaitResult {
        pid,
        exit_code,
        signal,
    }
}

/// Send `SIGKILL` to the entire process group led by `pgid` (`kill(-pgid, …)`).
///
/// A missing group (`ESRCH`, already exited) is treated as success.
pub fn kill_group(pgid: i32) -> io::Result<()> {
    // SAFETY: `kill` with a negative pid targets the process group `|pid|`; no
    // pointers are involved. `pgid` is a real pid we spawned into its own group.
    let rc = unsafe { libc::kill(-pgid, SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(err)
    }
}

/// This process's pid (`getpid`); PID 1 in the guest.
pub fn getpid() -> i32 {
    // SAFETY: `getpid` takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}
