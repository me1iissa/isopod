//! Safe wrappers over the handful of raw `libc` calls the jail launcher needs.
//!
//! Every `unsafe` block in the whole crate lives in this module. Each wrapper
//! documents why its call is sound; `main` never touches `libc` directly. The
//! relevant public specifications are `unshare(2)`, `user_namespaces(7)`,
//! `pid_namespaces(7)`, `mount(2)`, `pivot_root(2)`, `prctl(2)` (`PR_SET_PDEATHSIG`),
//! `fork(2)`, `wait(2)`, `execve(2)`, `kill(2)`, `cgroups(7)`.

use std::ffi::CString;
use std::io;
use std::sync::atomic::{AtomicI32, Ordering};

/// Convert a Rust `&str` into a NUL-terminated C string, rejecting interior NULs.
fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

/// Attach `ctx` to an `io::Error`, preserving its kind.
pub fn annotate(e: io::Error, ctx: &str) -> io::Error {
    io::Error::new(e.kind(), format!("{ctx}: {e}"))
}

/// This process's pid (`getpid(2)`; PID 1 inside the new pid namespace once the
/// child has forked).
#[must_use]
pub fn getpid() -> i32 {
    // SAFETY: `getpid` takes no arguments and cannot fail.
    unsafe { libc::getpid() }
}

/// `unshare(2)` with the given `CLONE_*` mask.
///
/// Used with `CLONE_NEWUSER` (drop host capabilities via a single-id map),
/// `CLONE_NEWPID` (the next child becomes PID 1 of a fresh pid namespace), and
/// `CLONE_NEWNS` (a private mount namespace whose binds/pivot never touch the host).
pub fn unshare(flags: libc::c_int) -> io::Result<()> {
    // SAFETY: `unshare` takes only an integer flag mask and has no pointer
    // arguments or memory-safety preconditions.
    let rc = unsafe { libc::unshare(flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `fork(2)`. Returns `0` in the child and the child pid in the parent.
///
/// The launcher is single-threaded at the fork point (no async runtime, no
/// spawned threads), so the classic fork-in-a-threaded-process hazards do not
/// apply: the child is a faithful single-threaded copy.
pub fn fork() -> io::Result<i32> {
    // SAFETY: `fork` takes no arguments. The caller is single-threaded, so the
    // child inherits a consistent address space; both returns are checked.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(pid)
    }
}

/// Ask the kernel to deliver `SIGKILL` to this process if its parent dies
/// (`prctl(PR_SET_PDEATHSIG, SIGKILL)`), so a child jailed process is reaped even
/// if the supervisor is killed and the child reparents.
pub fn set_pdeathsig_kill() -> io::Result<()> {
    // SAFETY: `PR_SET_PDEATHSIG` reads only the second argument (a signal number);
    // the remaining prctl arguments are ignored for this option.
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Make the whole mount tree rooted at `/` private and recursive
/// (`mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL)`) so binds and `pivot_root`
/// in this namespace do not propagate back to the host, and shared-mount
/// propagation does not reject the pivot.
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

/// Recursively bind-mount `src` onto `dst` (`mount(src, dst, NULL, MS_BIND|MS_REC, NULL)`).
///
/// Binding the *existing* node preserves the source's identity — for a device
/// node this keeps the real `root:kvm` gid and the source `/dev` devtmpfs's
/// dev-allowed flags, so `/dev/kvm` stays openable inside the user namespace.
pub fn bind_mount(src: &str, dst: &str) -> io::Result<()> {
    let src = cstr(src)?;
    let dst = cstr(dst)?;
    // SAFETY: `src` and `dst` are NUL-terminated C strings that outlive the call;
    // a bind mount ignores `fstype`/`data` (both NULL) and reads only the flag mask.
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REC) as libc::c_ulong,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Make `dst` read-only **including every mount beneath it**.
///
/// [`remount_readonly`] alone is not enough and the gap is silent. `bind_mount`
/// uses `MS_REC`, so a bind carries its submounts with it — but
/// `MS_REMOUNT | MS_RDONLY` applies to ONE mount, so every submount stays
/// writable. Measured, not inferred: bind a tree containing a tmpfs, remount the
/// top read-only, and a write to the top is refused while a write to the
/// submount succeeds.
///
/// That matters here because the jail binds `~/.isopod` read-only, and that tree
/// holds the stage store and the guest images. A submount under it — a separate
/// disk for images, a tmpfs, an encrypted volume — would be writable by the very
/// process this jail exists to contain, and a stage corrupted there is forked by
/// every later run that builds on it.
///
/// Two implementations, in preference order:
///
/// 1. `mount_setattr(2)` with `AT_RECURSIVE` (Linux 5.12+). The kernel walks the
///    tree itself in one atomic call, *adding* `MOUNT_ATTR_RDONLY` and clearing
///    nothing — so it cannot trip the locked-flag rule described on
///    [`remount_readonly`], no mount can appear between reading the mount table
///    and acting on it, and a mount that another mount is stacked over is still
///    reached (a path-driven walk can only ever see the topmost one).
/// 2. On an older kernel — `ENOSYS` — a read of `/proc/self/mountinfo` followed
///    by one bind remount per mount. Correct, but none of the three properties
///    above hold, which is why it is the fallback and not the design.
///
/// # Errors
/// If any mount at or beneath `dst` cannot be made read-only, or if the fallback
/// cannot read `/proc/self/mountinfo`. **Fails closed**: a jail that cannot prove
/// the tree is read-only must not report that it is.
pub fn remount_readonly_recursive(dst: &str) -> io::Result<()> {
    if std::env::var_os(FORCE_REMOUNT_WALK).is_none() {
        match mount_setattr_readonly_recursive(dst) {
            Ok(()) => return Ok(()),
            // Kernel older than 5.12: the walk below is the only option.
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => {}
            // Anything else is a real refusal, and this is a security boundary.
            Err(e) => return Err(annotate(e, "mount_setattr(AT_RECURSIVE)")),
        }
    }
    remount_readonly_walk(dst)
}

/// Test hook: take the pre-5.12 fallback even where `mount_setattr(2)` exists,
/// so the walk is exercised by the live jail probe instead of only ever running
/// on kernels nobody tests against.
///
/// It selects *which implementation* makes the tree read-only — never whether
/// the tree is made read-only. Both fail closed, so setting it cannot weaken a
/// jail; the worst it can do is make one refuse to start.
const FORCE_REMOUNT_WALK: &str = "ISOPOD_JAIL_FORCE_REMOUNT_WALK";

/// `struct mount_attr` from `mount_setattr(2)`.
///
/// There is no `libc` binding, and the kernel validates the struct size it is
/// handed against the version it knows, so the field order and widths here are
/// ABI, not an implementation detail.
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `mount_setattr(AT_FDCWD, dst, AT_RECURSIVE, {attr_set = MOUNT_ATTR_RDONLY})`.
///
/// `attr_clr` is zero: the call only ever *adds* the read-only attribute, so the
/// kernel's rule that a locked `nosuid`/`nodev`/`noexec` may not be cleared is
/// never engaged, whatever the tree happens to contain.
fn mount_setattr_readonly_recursive(dst: &str) -> io::Result<()> {
    let dst = cstr(dst)?;
    let attr = MountAttr {
        attr_set: libc::MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    // SAFETY: `dst` is a NUL-terminated C string that outlives the call; `attr`
    // is a live `#[repr(C)]` `struct mount_attr` and the size passed is its real
    // size, which is how the kernel selects the struct version. No libc wrapper
    // exists for this syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            dst.as_ptr(),
            libc::AT_RECURSIVE,
            std::ptr::from_ref(&attr),
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The pre-5.12 fallback: remount every mount at or beneath `dst`, deepest
/// first, each with the per-mount flags it already carries.
fn remount_readonly_walk(dst: &str) -> io::Result<()> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| annotate(e, "reading /proc/self/mountinfo"))?;
    let mut targets = submounts_of(&mountinfo, dst);
    // The bind itself may not be listed yet if the caller is racing its own
    // mount table read; remounting it is idempotent, so ensure it is included.
    let dst_norm = dst.trim_end_matches('/');
    if !dst_norm.is_empty() && !targets.iter().any(|t| t.path == dst_norm) {
        targets.push(Submount {
            path: dst_norm.to_string(),
            keep: 0,
        });
    }
    for target in &targets {
        remount_readonly(&target.path, target.keep)
            .map_err(|e| annotate(e, &format!("remounting {} read-only", target.path)))?;
    }
    Ok(())
}

/// Remount the existing bind at `dst` read-only, repeating the per-mount flags
/// in `keep` (`mount(NULL, dst, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY|keep, NULL)`).
///
/// `keep` is not decoration. A mount inherited into a new user namespace has its
/// `nosuid`, `nodev` and `noexec` bits **locked** (`mount_namespaces(7)`), and a
/// remount that omits one reads as an attempt to *clear* it — which the kernel
/// refuses with `EPERM`. Measured, not inferred: in a nested user namespace, a
/// `nosuid,nodev,noexec` submount rejects `MS_RDONLY` alone and accepts the same
/// remount the moment the three bits are passed back.
///
/// Atime flags are deliberately absent. `mount(2)` specifies that a remount
/// naming none of `MS_NOATIME`/`MS_NODIRATIME`/`MS_RELATIME`/`MS_STRICTATIME`
/// preserves the mount's existing atime setting — which is exactly what the same
/// locking rule requires, so parsing them could only introduce a way to get it
/// wrong.
pub fn remount_readonly(dst: &str, keep: libc::c_ulong) -> io::Result<()> {
    let dst = cstr(dst)?;
    // SAFETY: a bind remount needs only the target path; source/fstype/data are
    // ignored (NULL). The flag mask is the documented "make this bind read-only"
    // incantation, plus the flags this mount already carries.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            std::ptr::null(),
            (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY) as libc::c_ulong | keep,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount a fresh `proc` filesystem at `dst` reflecting this process's pid
/// namespace (`mount("proc", dst, "proc", 0, NULL)`).
/// Every mountpoint at or beneath `target`, deepest first, parsed from the
/// contents of `/proc/self/mountinfo`.
///
/// Pure and total, so the parsing is testable without privilege — which matters
/// because getting it wrong leaves a writable hole in a read-only bind and
/// nothing anywhere says so.
///
/// mountinfo's format is fixed up to a variable run of optional fields, which is
/// terminated by a literal `-`. The mount point is field 5 (index 4), and it is
/// **octal-escaped**: a path containing a space, tab, newline or backslash
/// appears as `\040`, `\011`, `\012`, `\134`. Comparing the raw text would miss
/// a submount under a directory with a space in its name — an attacker-chosen
/// condition wherever the bound path is user-controlled.
///
/// Deepest-first because a remount must not be shadowed by a later remount of
/// its parent.
#[must_use]
pub fn submounts_of(mountinfo: &str, target: &str) -> Vec<Submount> {
    // Trimming `/` to the empty string is what makes the separator test below
    // treat every mount as being under the root, as it should.
    let target = target.trim_end_matches('/');
    let mut found: Vec<Submount> = mountinfo
        .lines()
        .filter_map(|line| {
            // Fields before the optional run: id, parent, dev, root, mountpoint,
            // then the per-mount options.
            let mut fields = line.split(' ');
            let mount_point = fields.nth(4)?;
            // A line truncated after the mount point still names a real mount.
            // Yielding it with no flags fails closed — the remount errors and
            // the jail refuses to start — where skipping it would silently leave
            // that mount writable.
            let options = fields.next().unwrap_or("");
            let decoded = unescape_octal(mount_point);
            let under = decoded == target
                || decoded
                    .strip_prefix(target)
                    .is_some_and(|rest| rest.starts_with('/'));
            under.then(|| Submount {
                path: decoded,
                keep: preserved_flags(options),
            })
        })
        .collect();
    // Deepest first: a parent remounted after its child would shadow the child.
    found.sort_by(|a, b| {
        b.path
            .matches('/')
            .count()
            .cmp(&a.path.matches('/').count())
            .then_with(|| a.path.cmp(&b.path))
    });
    found.dedup();
    found
}

/// One mount to make read-only: where it is, and the per-mount flags a remount
/// of it must repeat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submount {
    /// Mount point, with mountinfo's octal escapes already decoded.
    pub path: String,
    /// `MS_*` bits this mount already carries. See [`remount_readonly`] for why
    /// dropping one turns a remount into an `EPERM`.
    pub keep: libc::c_ulong,
}

/// The `MS_*` bits a bind remount must repeat, read from mountinfo's per-mount
/// options field (`rw,nosuid,nodev,noexec,relatime`).
///
/// Deliberately narrow: the three flags the kernel *locks* on a mount inherited
/// into a user namespace, plus `nosymfollow` — which is not locked, and so fails
/// differently and worse. Omitting it does not error; it silently clears the
/// flag, turning a remount meant to tighten a mount into one that loosens it.
///
/// Atime options are not parsed at all; see [`remount_readonly`].
#[must_use]
fn preserved_flags(options: &str) -> libc::c_ulong {
    options.split(',').fold(0, |keep, opt| {
        keep | match opt {
            "nosuid" => libc::MS_NOSUID,
            "nodev" => libc::MS_NODEV,
            "noexec" => libc::MS_NOEXEC,
            "nosymfollow" => libc::MS_NOSYMFOLLOW,
            _ => 0,
        }
    })
}

/// Decode mountinfo's octal escapes (`\040` space, `\011` tab, `\012` newline,
/// `\134` backslash). Anything that is not a complete 3-digit octal escape is
/// passed through unchanged rather than dropped.
fn unescape_octal(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &s[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(digits, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

pub fn mount_proc(dst: &str) -> io::Result<()> {
    let source = cstr("proc")?;
    let dst = cstr(dst)?;
    let fstype = cstr("proc")?;
    // SAFETY: all three pointers are NUL-terminated C strings valid for the call;
    // flags are 0 and the fs-options pointer is NULL (no per-fs data).
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            dst.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Change the working directory (`chdir(2)`).
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

/// `pivot_root(2)` (no libc wrapper exists, so the raw syscall is used).
///
/// Driven with the `pivot_root(".", ".")` idiom documented in `pivot_root(2)`
/// NOTES: with the new root as the working directory, the old root is stacked
/// over the new one and a subsequent [`umount_detach`] of `.` removes it,
/// leaving no path back out of the chroot (unlike a plain `chroot`).
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

/// Lazily detach the mount at `target` (`umount2(target, MNT_DETACH)`).
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

/// Replace the process image with `program` and `argv` (`execve(2)`, inheriting
/// the current environment). Only returns — carrying `errno` — on failure.
pub fn exec(program: &str, argv: &[String]) -> io::Error {
    let prog = match cstr(program) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // Build a NULL-terminated argv of borrowed C strings.
    let cargs: Vec<CString> = match argv.iter().map(|a| cstr(a)).collect() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mut ptrs: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `prog` and every `cargs` entry are NUL-terminated and outlive the
    // call; `ptrs` is NULL-terminated as `execv` requires; `execv` uses the global
    // `environ`. On success control never returns here.
    unsafe {
        libc::execv(prog.as_ptr(), ptrs.as_ptr());
    }
    io::Error::last_os_error()
}

// ===========================================================================
// Supervisor: forward termination to the jailed child, then proxy its status.
// ===========================================================================

/// The forked child's pid, published so the signal handler can forward to it.
static CHILD_PID: AtomicI32 = AtomicI32::new(0);

/// `SIGTERM`/`SIGINT` handler: forward `SIGKILL` to the jailed child.
///
/// Async-signal-safe: it performs only an atomic load and a `kill(2)`.
extern "C" fn forward_signal(_sig: libc::c_int) {
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: `kill` with a real pid and a valid signal is always sound.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
}

/// Install `forward_signal` for `SIGTERM` and `SIGINT` and record `child` so a
/// termination signal delivered to the supervisor is relayed to the jailed child.
pub fn install_child_forwarding(child: i32) {
    CHILD_PID.store(child, Ordering::SeqCst);
    // SAFETY: installing a handler with a valid signal number and function
    // pointer is sound; the handler itself is async-signal-safe. `signal`'s
    // handler argument is a `sighandler_t` (pointer-sized); cast via a thin
    // pointer as the lint prescribes.
    let handler = forward_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Block until `child` exits, then exit with a faithful copy of its status: the
/// same exit code, or — if it was killed by a signal — re-raise that signal on
/// ourselves so the supervisor's own status reflects it. Never returns.
///
/// This makes the jail transparent to the parent `FcProcess`: a Firecracker
/// that dies before its API socket appears still surfaces as an early exit.
pub fn wait_and_proxy(child: i32) -> ! {
    let mut status: libc::c_int = 0;
    // SAFETY: `&mut status` is a valid writable int pointer; blocking wait on a
    // real child pid.
    let rc = unsafe { libc::waitpid(child, &mut status, 0) };
    if rc < 0 {
        // Could not reap (should not happen); exit non-zero.
        unsafe { libc::_exit(1) };
    }
    if libc::WIFEXITED(status) {
        unsafe { libc::_exit(libc::WEXITSTATUS(status)) };
    }
    if libc::WIFSIGNALED(status) {
        let sig = libc::WTERMSIG(status);
        // Reset the signal to its default action and re-raise it so our exit
        // status mirrors the child's terminating signal.
        // SAFETY: resetting to SIG_DFL then raising a valid signal is sound.
        unsafe {
            libc::signal(sig, libc::SIG_DFL);
            libc::raise(sig);
            // If raising somehow returns, fall through to a non-zero exit.
            libc::_exit(128 + sig);
        }
    }
    unsafe { libc::_exit(1) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real excerpt, shape-for-shape: the variable optional-field run before
    /// the `-` separator is what makes naive splitting wrong, so the fixture
    /// includes lines both with and without it.
    const MOUNTINFO: &str = "\
25 30 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
26 30 0:23 / /home/u/.isopod rw,relatime - ext4 /dev/sda2 rw
27 26 0:24 / /home/u/.isopod/images rw,relatime shared:9 - tmpfs none rw
28 27 0:25 / /home/u/.isopod/images/deep rw,relatime - tmpfs none rw
29 30 0:26 / /home/u/.isopod-other rw,relatime - ext4 /dev/sda3 rw
31 30 0:27 / /home/u/.isopodx rw,relatime - ext4 /dev/sda4 rw
";

    /// Mount points only, for the tests that are about *which* mounts are found.
    fn paths(found: &[Submount]) -> Vec<String> {
        found.iter().map(|s| s.path.clone()).collect()
    }

    #[test]
    fn submounts_include_the_target_and_everything_under_it() {
        let got = paths(&submounts_of(MOUNTINFO, "/home/u/.isopod"));
        assert!(got.contains(&"/home/u/.isopod".to_string()));
        assert!(got.contains(&"/home/u/.isopod/images".to_string()));
        assert!(got.contains(&"/home/u/.isopod/images/deep".to_string()));
    }

    /// The one that took down the first version of this code. A mount inherited
    /// into a user namespace has `nosuid`/`nodev`/`noexec` locked, so a remount
    /// that does not name them again is read as an attempt to clear them and is
    /// refused with `EPERM` — turning a fix for a silent hole into a jail that
    /// will not start. The flags have to come back out of mountinfo.
    #[test]
    fn the_flags_the_kernel_locks_are_read_back_from_the_mount_options() {
        let got = submounts_of(MOUNTINFO, "/proc");
        assert_eq!(
            got[0].keep,
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            "a locked flag dropped here is an EPERM at the syscall"
        );
    }

    /// Atime is locked too, but `mount(2)` preserves it for a remount that names
    /// no atime flag. Parsing them could only add a way to get it wrong.
    #[test]
    fn atime_is_left_for_the_kernel_to_preserve() {
        assert_eq!(preserved_flags("rw,relatime"), 0);
        assert_eq!(preserved_flags("rw,noatime,nodiratime"), 0);
    }

    /// `nosymfollow` is *not* locked, so omitting it does not fail loudly — it
    /// clears the flag, quietly loosening a mount this call exists to tighten.
    #[test]
    fn nosymfollow_is_repeated_so_the_remount_cannot_clear_it() {
        assert_eq!(preserved_flags("ro,nosymfollow"), libc::MS_NOSYMFOLLOW);
    }

    /// An unknown option contributes nothing rather than being guessed at.
    #[test]
    fn unrecognised_options_contribute_no_flags() {
        assert_eq!(preserved_flags("rw,seclabel,inode64,idmapped"), 0);
    }

    /// A line truncated after the mount point still names a real mount. It is
    /// kept, with no flags, so the remount fails and the jail refuses to start —
    /// dropping it would leave that mount writable and report success.
    #[test]
    fn a_line_with_no_options_field_still_yields_the_mount() {
        let got = submounts_of("25 30 0:22 / /proc\n", "/proc");
        assert_eq!(paths(&got), vec!["/proc".to_string()]);
        assert_eq!(got[0].keep, 0);
    }

    /// A prefix match on the raw string would sweep in `/home/u/.isopod-other`
    /// and `/home/u/.isopodx`, remounting mounts the jail was never given —
    /// read-only, on the host, outside the jail's own tree. The boundary must be
    /// a path separator, not a character count.
    #[test]
    fn a_sibling_that_merely_shares_a_prefix_is_not_a_submount() {
        let got = paths(&submounts_of(MOUNTINFO, "/home/u/.isopod"));
        assert!(
            !got.iter().any(|m| m == "/home/u/.isopod-other"),
            "a prefix match would remount an unrelated mount: {got:?}"
        );
        assert!(
            !got.iter().any(|m| m == "/home/u/.isopodx"),
            "a prefix match would remount an unrelated mount: {got:?}"
        );
    }

    /// Deepest first. Remounting a parent before its child lets the parent's
    /// mount shadow the child, and the child stays writable — the exact hole
    /// this function exists to close, reintroduced by ordering alone.
    #[test]
    fn deepest_mounts_come_first() {
        let got = paths(&submounts_of(MOUNTINFO, "/home/u/.isopod"));
        let deep = got.iter().position(|m| m == "/home/u/.isopod/images/deep");
        let mid = got.iter().position(|m| m == "/home/u/.isopod/images");
        let top = got.iter().position(|m| m == "/home/u/.isopod");
        assert!(deep < mid && mid < top, "wrong order: {got:?}");
    }

    /// mountinfo octal-escapes space, tab, newline and backslash in the mount
    /// point. Comparing the raw text would miss a submount under a directory
    /// whose name contains one — and the name is frequently user-chosen.
    #[test]
    fn octal_escaped_mount_points_are_decoded_before_comparison() {
        let mi = "\
40 30 0:30 / /home/u/my\\040stage rw,relatime - ext4 /dev/sda5 rw
41 40 0:31 / /home/u/my\\040stage/inner rw,relatime - tmpfs none rw
";
        let got = paths(&submounts_of(mi, "/home/u/my stage"));
        assert_eq!(
            got,
            vec![
                "/home/u/my stage/inner".to_string(),
                "/home/u/my stage".to_string()
            ],
            "a space in the path must not hide a submount"
        );
    }

    #[test]
    fn unescape_passes_through_anything_that_is_not_a_complete_escape() {
        assert_eq!(unescape_octal("/plain/path"), "/plain/path");
        assert_eq!(unescape_octal("/a\\040b"), "/a b");
        assert_eq!(unescape_octal("/a\\011b"), "/a\tb");
        assert_eq!(unescape_octal("/a\\134b"), "/a\\b");
        // Truncated / non-octal: kept verbatim rather than silently dropped.
        assert_eq!(unescape_octal("/a\\04"), "/a\\04");
        assert_eq!(unescape_octal("/a\\09b"), "/a\\09b");
    }

    /// A target with no submounts still yields itself, so the caller always has
    /// something to remount and never silently does nothing.
    #[test]
    fn a_target_with_no_submounts_still_returns_itself() {
        assert_eq!(
            paths(&submounts_of(MOUNTINFO, "/proc")),
            vec!["/proc".to_string()]
        );
    }

    /// Garbage in must not panic: this parses a kernel file on the security
    /// path, and a panic there takes down a jail launch.
    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let mi = "short line\n\n25 30 0:22 /\n25 30 0:22 / /proc rw - proc proc rw\n";
        assert_eq!(paths(&submounts_of(mi, "/proc")), vec!["/proc".to_string()]);
    }

    /// A trailing slash on the target is the same target. Without normalising,
    /// `/home/u/.isopod/` would match nothing and the whole tree would be
    /// left writable while the call reported success.
    #[test]
    fn a_trailing_slash_on_the_target_is_ignored() {
        assert_eq!(
            submounts_of(MOUNTINFO, "/home/u/.isopod/"),
            submounts_of(MOUNTINFO, "/home/u/.isopod")
        );
    }

    /// Binding `/` read-only is a real configuration (the live probe uses it),
    /// and it is the one target that trims to the empty string. Every mount must
    /// still be found — a `/`-rooted bind that swept up nothing would report
    /// success over an entirely writable tree.
    #[test]
    fn binding_the_root_finds_every_mount() {
        let got = paths(&submounts_of(MOUNTINFO, "/"));
        assert_eq!(got.len(), MOUNTINFO.lines().count(), "got {got:?}");
        assert!(got.contains(&"/proc".to_string()));
        assert!(got.contains(&"/home/u/.isopodx".to_string()));
    }
}
