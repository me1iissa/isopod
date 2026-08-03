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
/// A single `MS_REMOUNT | MS_RDONLY` is not enough and the gap is silent.
/// `bind_mount` uses `MS_REC`, so a bind carries its submounts with it — but a
/// remount applies to ONE mount, so every submount stays writable. Measured, not
/// inferred: bind a tree containing a tmpfs, remount the top read-only, and a
/// write to the top is refused while a write to the submount succeeds.
///
/// That matters here because the jail binds `~/.isopod` read-only, and that tree
/// holds the stage store and the guest images. A submount under it — a separate
/// disk for images, a tmpfs, an encrypted volume — would be writable by the very
/// process this jail exists to contain, and a stage corrupted there is forked by
/// every later run that builds on it.
///
/// Done with `mount_setattr(2)` and `AT_RECURSIVE`, which is the only mechanism
/// that actually holds:
///
/// * the kernel walks the tree itself, in one call, so no mount can appear
///   between reading a mount table and acting on it;
/// * it *adds* `MOUNT_ATTR_RDONLY` and clears nothing, so it cannot trip the rule
///   that a `nosuid`/`nodev`/`noexec` bit locked into a user namespace may not be
///   cleared (`mount_namespaces(7)`); and
/// * it reaches a mount that another mount is stacked over, which nothing driven
///   by path can do — a remount by path only ever finds the topmost.
///
/// A hand-rolled walk over `/proc/self/mountinfo` was tried for kernels without
/// the syscall and abandoned. It failed all three ways above, each time on a real
/// host and never on a developer's machine, because whether it fails at all is a
/// property of the host's mount table. A second implementation of a security
/// boundary that runs only where nobody tests is worth less than the hosts it
/// buys.
///
/// # Errors
/// If the tree cannot be made read-only, including [`io::ErrorKind::Unsupported`]
/// on a kernel older than 5.12. **Fails closed**: a jail that cannot prove the
/// tree is read-only must not report that it is.
pub fn remount_readonly_recursive(dst: &str) -> io::Result<()> {
    mount_setattr_readonly_recursive(dst).map_err(|e| {
        if e.raw_os_error() == Some(libc::ENOSYS) {
            io::Error::new(
                io::ErrorKind::Unsupported,
                kernel_too_old_message(kernel_release().as_deref()),
            )
        } else {
            annotate(e, "mount_setattr(AT_RECURSIVE)")
        }
    })
}

/// What to tell an operator whose kernel predates `mount_setattr(2)`.
///
/// This is the whole user-facing contract of the failure, so it is a pure
/// function with tests rather than a format string at the call site: it has to
/// name the requirement, what this host actually is, and why the jail refuses
/// instead of carrying on.
#[must_use]
fn kernel_too_old_message(release: Option<&str>) -> String {
    let found = release.unwrap_or("unknown");
    format!(
        "this kernel has no mount_setattr(2), which the jail needs to make a bind \
         read-only including every mount beneath it: Linux 5.12 or newer is \
         required and this host reports {found}. Without it a read-only bind \
         leaves its submounts writable and says nothing, so the jail refuses to \
         start rather than report a boundary it cannot enforce. Run without \
         ISOPOD_JAIL=1 to start an unjailed VM instead"
    )
}

/// This host's kernel release (`uname(2)`'s `release`), for the message above.
fn kernel_release() -> Option<String> {
    // SAFETY: `uname` fills the `utsname` it is given; an all-zero `utsname` is a
    // valid starting value and the result is read only after a success return.
    let uts = unsafe {
        let mut uts: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut uts) != 0 {
            return None;
        }
        uts
    };
    let release: Vec<u8> = uts
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8(release).ok().filter(|s| !s.is_empty())
}

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
    /// The message is the whole user-facing contract of an unsupported kernel:
    /// it has to name the requirement, say what this host actually is, and give
    /// a way forward. A bare "Operation not supported" sends the reader hunting
    /// through the jail for a bug that is not there.
    #[test]
    fn an_unsupported_kernel_is_named_along_with_the_requirement() {
        let msg = kernel_too_old_message(Some("5.4.0-190-generic"));
        assert!(msg.contains("5.12"), "names the requirement: {msg}");
        assert!(msg.contains("5.4.0-190-generic"), "names this host: {msg}");
        assert!(msg.contains("mount_setattr"), "names the syscall: {msg}");
        assert!(msg.contains("ISOPOD_JAIL"), "offers a way forward: {msg}");
    }

    /// `uname` can fail. The message still has to be usable when it does, rather
    /// than reading as though this host runs a kernel called "".
    #[test]
    fn an_unreadable_kernel_release_still_gives_a_usable_message() {
        let msg = kernel_too_old_message(None);
        assert!(msg.contains("unknown"), "{msg}");
        assert!(msg.contains("5.12"), "{msg}");
    }

    /// The release really is readable here, so the case above is a fallback and
    /// not the only one ever exercised.
    #[test]
    fn this_host_reports_a_kernel_release() {
        let release = kernel_release().expect("uname must report a release");
        assert!(
            release.chars().next().is_some_and(|c| c.is_ascii_digit()),
            "a kernel release starts with its version: {release:?}"
        );
    }
}
