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

/// Mount flag: mount (or bind) read-only (`MS_RDONLY`).
pub const MS_RDONLY: u64 = libc::MS_RDONLY;
/// Mount flag: never update inode access times (`MS_NOATIME`).
pub const MS_NOATIME: u64 = libc::MS_NOATIME;

/// Mount `fstype` at `target` from `source` with raw `flags` and an optional
/// filesystem-specific `data` string (e.g. the overlayfs `lowerdir=…` options).
///
/// Unlike [`mount`], every non-zero return — including `EBUSY` — is surfaced as
/// an error: the stacked stage mounts (scratch ext4, layer ext4, merged overlay)
/// have no "already mounted, ignore it" fast path.
pub fn mount_with_data(
    source: &str,
    target: &str,
    fstype: &str,
    flags: u64,
    data: Option<&str>,
) -> io::Result<()> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = cstr(fstype)?;
    let data_c = match data {
        Some(d) => Some(cstr(d)?),
        None => None,
    };
    let data_ptr = data_c
        .as_ref()
        .map_or(std::ptr::null(), |c| c.as_ptr().cast());
    // SAFETY: `source`/`target`/`fstype` are NUL-terminated C strings that
    // outlive the call; `data_ptr` is either NULL or a NUL-terminated string
    // owned by `data_c` (also alive for the call); `flags` is a valid MS_* mask.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags as libc::c_ulong,
            data_ptr,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Make the whole mount tree rooted at `/` private and recursive
/// (`mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`), so `pivot_root` is not
/// rejected by shared mount propagation. A minimal (no-systemd) guest usually
/// boots with private mounts already; this is belt-and-braces.
pub fn make_root_private() -> io::Result<()> {
    let root = cstr("/")?;
    // SAFETY: changing propagation needs only a valid `target` path; `source`,
    // `fstype` and `data` are ignored for `MS_PRIVATE` and passed as NULL.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Change the process working directory (`chdir(2)`).
pub fn chdir(path: &str) -> io::Result<()> {
    let path = cstr(path)?;
    // SAFETY: `path` is a NUL-terminated C string valid for the call.
    let rc = unsafe { libc::chdir(path.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `pivot_root(2)`: make `new_root` the process root, mounting the old root at
/// `put_old`. There is no libc function wrapper, so the raw syscall is used.
///
/// The agent drives this with the `pivot_root(".", ".")` idiom (documented in
/// `pivot_root(2)` NOTES): with the merged overlay as the working directory, the
/// old root is stacked over the new root at `/`, and a subsequent
/// [`umount_detach`] of `.` removes it — leaving no `put_old` directory behind
/// in the overlay upper.
pub fn pivot_root(new_root: &str, put_old: &str) -> io::Result<()> {
    let new_root = cstr(new_root)?;
    let put_old = cstr(put_old)?;
    // SAFETY: both arguments are NUL-terminated C strings valid for the call;
    // `SYS_pivot_root` consumes exactly these two path pointers and returns 0 or
    // -1 with `errno` set.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Lazily detach the mount at `target` (`umount2(target, MNT_DETACH)`): the
/// mount leaves the namespace immediately but its superblock stays alive while
/// still referenced (here, by the overlay that pins the old root's layers).
pub fn umount_detach(target: &str) -> io::Result<()> {
    let target = cstr(target)?;
    // SAFETY: `target` is a NUL-terminated C string valid for the call.
    let rc = unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ===========================================================================
// IPv4 interface configuration (classic SIOC* ioctls; no netlink, no shelling
// out — the guest agent stays std + libc only).
// ===========================================================================

/// Linux `IFNAMSIZ`: interface names are at most 15 bytes plus a NUL terminator.
const IFNAMSIZ: usize = 16;

/// A `struct ifreq` sized to the kernel ABI: the 16-byte interface name followed
/// by the 24-byte `ifr_ifru` union (whose largest member, `struct ifmap`, is 24
/// bytes on 64-bit). The union is treated as an opaque buffer into which the wire
/// image of the member the ioctl needs is written — a `sockaddr` for address ops
/// or a `short` for flags.
///
/// The exact 40-byte size is load-bearing: the kernel copies `sizeof(struct
/// ifreq)` bytes from our pointer, so a short struct would let it read past our
/// allocation. A compile-time assertion below pins the size.
#[repr(C)]
struct Ifreq {
    name: [u8; IFNAMSIZ],
    ifru: [u8; 24],
}

const _: () = assert!(std::mem::size_of::<Ifreq>() == 40);

impl Ifreq {
    /// A zeroed `ifreq` with `ifr_name` set to `ifname`.
    fn new(ifname: &str) -> io::Result<Self> {
        let bytes = ifname.as_bytes();
        if bytes.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("interface name {ifname:?} exceeds IFNAMSIZ-1"),
            ));
        }
        let mut name = [0u8; IFNAMSIZ];
        name[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            name,
            ifru: [0u8; 24],
        })
    }
}

/// The 16-byte wire image of a `sockaddr_in` for IPv4 `addr`: `sin_family`
/// (native-endian `AF_INET`), `sin_port` 0, `sin_addr` in network byte order
/// (the natural `a.b.c.d` octet order), and zero padding.
fn sockaddr_in_bytes(addr: [u8; 4]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
    // b[2..4] = sin_port (0); b[4..8] = sin_addr; b[8..16] = sin_zero (0).
    b[4..8].copy_from_slice(&addr);
    b
}

/// Build a `sockaddr` holding IPv4 `addr` (family `AF_INET`).
fn sockaddr_v4(addr: [u8; 4]) -> libc::sockaddr {
    // SAFETY: `libc::sockaddr` and the 16-byte `sockaddr_in` wire image are both
    // 16 bytes of plain-old-data; reinterpreting the image as a `sockaddr` is a
    // valid, size-checked transmute.
    unsafe { std::mem::transmute::<[u8; 16], libc::sockaddr>(sockaddr_in_bytes(addr)) }
}

/// Create an `AF_INET` / `SOCK_DGRAM` socket to issue configuration ioctls on.
fn inet_dgram_socket() -> io::Result<OwnedFd> {
    // SAFETY: a `socket` call with a valid domain/type/protocol triple; returns a
    // new fd or -1, checked below.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor we now exclusively own.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Issue an `ifreq`-shaped ioctl (`request`) on a fresh configuration socket.
fn ioctl_ifreq(request: libc::Ioctl, req: &mut Ifreq) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let sock = inet_dgram_socket()?;
    // SAFETY: `req` is a live, correctly sized (40-byte) `ifreq`; `request` is a
    // valid `SIOC*` interface ioctl that reads/writes exactly that struct through
    // the pointer; `sock` is a valid `AF_INET` datagram socket held for the call.
    let rc = unsafe { libc::ioctl(sock.as_raw_fd(), request, req as *mut Ifreq) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Set interface `ifname`'s IPv4 address (`SIOCSIFADDR`).
///
/// Returns an `ENODEV` [`io::Error`] if the interface does not exist (e.g. no
/// NIC was attached) — callers use that to degrade gracefully.
pub fn set_if_addr(ifname: &str, addr: [u8; 4]) -> io::Result<()> {
    let mut req = Ifreq::new(ifname)?;
    req.ifru[0..16].copy_from_slice(&sockaddr_in_bytes(addr));
    ioctl_ifreq(libc::SIOCSIFADDR as libc::Ioctl, &mut req)
}

/// Set interface `ifname`'s IPv4 netmask (`SIOCSIFNETMASK`).
pub fn set_if_netmask(ifname: &str, mask: [u8; 4]) -> io::Result<()> {
    let mut req = Ifreq::new(ifname)?;
    req.ifru[0..16].copy_from_slice(&sockaddr_in_bytes(mask));
    ioctl_ifreq(libc::SIOCSIFNETMASK as libc::Ioctl, &mut req)
}

/// Bring interface `ifname` up: read its flags (`SIOCGIFFLAGS`), OR in
/// `IFF_UP | IFF_RUNNING`, and write them back (`SIOCSIFFLAGS`).
pub fn set_if_up(ifname: &str) -> io::Result<()> {
    let mut req = Ifreq::new(ifname)?;
    ioctl_ifreq(libc::SIOCGIFFLAGS as libc::Ioctl, &mut req)?;
    // `ifr_flags` is a `short` occupying the first two bytes of the union.
    let mut flags = i16::from_ne_bytes([req.ifru[0], req.ifru[1]]);
    flags |= (libc::IFF_UP | libc::IFF_RUNNING) as i16;
    req.ifru[0..2].copy_from_slice(&flags.to_ne_bytes());
    ioctl_ifreq(libc::SIOCSIFFLAGS as libc::Ioctl, &mut req)
}

/// Add the IPv4 default route via gateway `gw` (`SIOCADDRT` with an
/// `RTF_UP | RTF_GATEWAY` rtentry; destination and genmask `0.0.0.0`).
pub fn add_default_route(gw: [u8; 4]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    // SAFETY: `rtentry` is plain-old-data; an all-zero bit pattern is a valid
    // empty route that we immediately fill in.
    let mut rt: libc::rtentry = unsafe { std::mem::zeroed() };
    rt.rt_dst = sockaddr_v4([0, 0, 0, 0]);
    rt.rt_genmask = sockaddr_v4([0, 0, 0, 0]);
    rt.rt_gateway = sockaddr_v4(gw);
    rt.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
    let sock = inet_dgram_socket()?;
    // SAFETY: `&mut rt` is a live, fully-initialized `rtentry`; `SIOCADDRT` reads
    // exactly that struct through the pointer; `sock` is a valid `AF_INET` socket
    // held for the duration of the call.
    let rc = unsafe {
        libc::ioctl(
            sock.as_raw_fd(),
            libc::SIOCADDRT as libc::Ioctl,
            &mut rt as *mut libc::rtentry,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_is_exactly_kernel_sized() {
        assert_eq!(std::mem::size_of::<Ifreq>(), 40);
    }

    #[test]
    fn sockaddr_in_bytes_layout() {
        let b = sockaddr_in_bytes([10, 107, 3, 2]);
        // sin_family = AF_INET (2) in native-endian.
        assert_eq!(&b[0..2], &(libc::AF_INET as u16).to_ne_bytes());
        // sin_port = 0.
        assert_eq!(&b[2..4], &[0, 0]);
        // sin_addr = network-order a.b.c.d.
        assert_eq!(&b[4..8], &[10, 107, 3, 2]);
        // sin_zero = 0.
        assert_eq!(&b[8..16], &[0u8; 8]);
    }

    #[test]
    fn sockaddr_v4_roundtrips_family_and_addr() {
        let sa = sockaddr_v4([192, 168, 1, 254]);
        // Reinterpret back to raw bytes and check the fields.
        let raw: [u8; 16] = unsafe { std::mem::transmute(sa) };
        assert_eq!(&raw[0..2], &(libc::AF_INET as u16).to_ne_bytes());
        assert_eq!(&raw[4..8], &[192, 168, 1, 254]);
    }

    #[test]
    fn ifreq_new_copies_name_and_rejects_long() {
        let r = Ifreq::new("eth0").unwrap();
        assert_eq!(&r.name[0..4], b"eth0");
        assert_eq!(r.name[4], 0, "name must be NUL-padded");
        assert!(Ifreq::new("this-name-is-way-too-long").is_err());
    }
}
