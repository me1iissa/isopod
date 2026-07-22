//! `isopod-jail` — a rootless microjail *launcher* used as a command prefix.
//!
//! `isopod-core` prepends this binary to the Firecracker argv (via the existing
//! [`command_prefix`] seam) when `ISOPOD_JAIL=1`. It wraps the VMM in a second
//! isolation layer with no privileged host component:
//!
//! 1. **Join a delegated cgroup** (`--cgroup`), as the real user, *before* any
//!    namespace work — the child (Firecracker) inherits the cgroup and its
//!    `memory.max` / `cpu.max` / `pids.max` caps (cgroup membership survives
//!    `fork`/`unshare`).
//! 2. **Enter a single-id user + pid namespace.** In-namespace root maps to the
//!    real uid/gid only (`0 <uid> 1`), so a VMM/KVM escape lands as an
//!    unprivileged, unmapped id on the host (`CapEff=0` w.r.t. the init user
//!    namespace). Supplementary groups (notably `kvm`) are *retained* —
//!    `setgroups=deny` blocks *dropping* them, it never clears them — so
//!    `/dev/kvm` (mode `0660 root:kvm`) stays openable with no host `chmod`.
//! 3. **`pivot_root` into a minimal chroot** built from identity bind mounts
//!    (each host path mapped at its identical absolute path), so Firecracker's
//!    argv and API payloads are byte-for-byte the same jailed or not.
//! 4. **`exec` Firecracker** as PID 1 of the new pid namespace.
//!
//! A thin supervisor stays in the host pid namespace as the process the parent
//! [`FcProcess`] tracks; it forwards termination to the jailed child, reaps it,
//! and proxies its exit status. No `CLONE_NEWNET`: Firecracker must stay in the
//! root network namespace so the existing tap + nftables fabric works unchanged;
//! the user namespace already removes host privilege from an escape.
//!
//! Relevant public specs: `user_namespaces(7)`, `pid_namespaces(7)`,
//! `mount_namespaces(7)`, `pivot_root(2)`, `cgroups(7)`, `capabilities(7)`.
//!
//! [`command_prefix`]: (the `FcProcessConfig` builder in `isopod-fc`)
//! [`FcProcess`]: (the supervised Firecracker handle in `isopod-fc`)

mod sys;

use std::io;
use std::path::{Path, PathBuf};

/// Parsed launcher arguments (everything after `--` is the program to exec).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    /// Delegated leaf cgroup to place this process in (optional: omit to skip
    /// cgroup placement, e.g. in a standalone namespace smoke test).
    cgroup: Option<PathBuf>,
    /// Absolute chroot directory to `pivot_root` into.
    root: PathBuf,
    /// Real host uid mapped to in-namespace root.
    uid: u32,
    /// Real host gid mapped to in-namespace root.
    gid: u32,
    /// Identity bind mounts: `(host_path, writable)`; each is mounted at the same
    /// absolute path under `root`.
    binds: Vec<(PathBuf, bool)>,
    /// Device nodes to bind (rw) at their identical path under `root`.
    devs: Vec<PathBuf>,
    /// The program and its arguments (argv, `argv[0]` first).
    program: Vec<String>,
}

impl Args {
    /// Parse the launcher argv (the slice *after* the binary name).
    fn parse(raw: &[String]) -> Result<Args, String> {
        let mut cgroup = None;
        let mut root = None;
        let mut uid = None;
        let mut gid = None;
        let mut binds = Vec::new();
        let mut devs = Vec::new();
        let mut program = Vec::new();

        // Pull the value that must follow a flag at index `i`.
        fn value_at<'a>(raw: &'a [String], i: usize, name: &str) -> Result<&'a str, String> {
            raw.get(i + 1)
                .map(String::as_str)
                .ok_or_else(|| format!("{name} requires a value"))
        }

        let mut i = 0;
        while i < raw.len() {
            match raw[i].as_str() {
                "--cgroup" => {
                    cgroup = Some(PathBuf::from(value_at(raw, i, "--cgroup")?));
                    i += 1;
                }
                "--root" => {
                    root = Some(PathBuf::from(value_at(raw, i, "--root")?));
                    i += 1;
                }
                "--uid" => {
                    let v = value_at(raw, i, "--uid")?;
                    uid = Some(v.parse().map_err(|_| format!("invalid --uid {v:?}"))?);
                    i += 1;
                }
                "--gid" => {
                    let v = value_at(raw, i, "--gid")?;
                    gid = Some(v.parse().map_err(|_| format!("invalid --gid {v:?}"))?);
                    i += 1;
                }
                "--bind" => {
                    let (path, writable) = parse_bind_spec(value_at(raw, i, "--bind")?);
                    binds.push((path, writable));
                    i += 1;
                }
                "--dev" => {
                    devs.push(PathBuf::from(value_at(raw, i, "--dev")?));
                    i += 1;
                }
                "--" => {
                    program = raw[i + 1..].to_vec();
                    break;
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
            i += 1;
        }

        let root = root.ok_or("--root is required")?;
        let uid = uid.ok_or("--uid is required")?;
        let gid = gid.ok_or("--gid is required")?;
        if program.is_empty() {
            return Err("missing program after `--`".to_string());
        }
        Ok(Args {
            cgroup,
            root,
            uid,
            gid,
            binds,
            devs,
            program,
        })
    }
}

/// Parse a `--bind` spec: `path`, `path:ro`, or `path:rw`. A missing or
/// unrecognized suffix defaults to read-write. Only a trailing `:ro`/`:rw` is a
/// mode; a bare `:` elsewhere in the path is left untouched.
fn parse_bind_spec(spec: &str) -> (PathBuf, bool) {
    if let Some((path, mode)) = spec.rsplit_once(':') {
        match mode {
            "ro" => return (PathBuf::from(path), false),
            "rw" => return (PathBuf::from(path), true),
            _ => {}
        }
    }
    (PathBuf::from(spec), true)
}

fn main() {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(&raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("isopod-jail: usage error: {e}");
            std::process::exit(2);
        }
    };
    // From here control either exits inside `run` (the parent proxies the
    // child's status; the child execs or `_exit`s) or `run` returns an error
    // from the pre-fork setup, which we surface and exit non-zero.
    match run(args) {
        Ok(()) => std::process::exit(0), // unreachable: run never returns Ok
        Err(e) => {
            eprintln!("isopod-jail: {e}");
            std::process::exit(1);
        }
    }
}

/// The pre-fork setup + fork. The parent and child both exit inside; this only
/// returns `Err` when a step *before* the fork fails.
fn run(args: Args) -> io::Result<()> {
    // (a) Join the delegated cgroup FIRST, as the real user (the delegated files
    // are owned by us; the value written is our host pid). The forked child and
    // its exec'd Firecracker inherit the cgroup automatically.
    if let Some(cgroup) = &args.cgroup {
        join_cgroup(cgroup)?;
    }

    // (b) User namespace with a single-id map: in-ns root -> the real uid/gid.
    sys::unshare(libc::CLONE_NEWUSER).map_err(|e| sys::annotate(e, "unshare(CLONE_NEWUSER)"))?;
    write_id_maps(args.uid, args.gid)?;

    // Pid namespace: only affects the *next* child, so unshare then fork.
    sys::unshare(libc::CLONE_NEWPID).map_err(|e| sys::annotate(e, "unshare(CLONE_NEWPID)"))?;

    match sys::fork().map_err(|e| sys::annotate(e, "fork"))? {
        0 => child(args),
        child_pid => {
            // Supervisor: relay termination to the jailed child, then proxy its
            // exit status. Never returns.
            sys::install_child_forwarding(child_pid);
            sys::wait_and_proxy(child_pid);
        }
    }
}

/// The jailed child (PID 1 of the new pid namespace): build the chroot and exec.
/// Never returns — it either replaces its image or `_exit`s with a diagnostic.
fn child(args: Args) -> ! {
    match child_setup(&args) {
        Ok(()) => {
            let err = sys::exec(&args.program[0], &args.program);
            eprintln!(
                "isopod-jail: exec {:?} failed: {err}",
                args.program.first().map(String::as_str).unwrap_or("")
            );
            // SAFETY: `_exit` terminates the child without running atexit hooks
            // (which would double-flush the shared stdio inherited from fork).
            unsafe { libc::_exit(127) }
        }
        Err(e) => {
            eprintln!("isopod-jail: child setup failed: {e}");
            unsafe { libc::_exit(1) }
        }
    }
}

/// Private mount namespace, identity binds + devices, a fresh `/proc`, then
/// `pivot_root` into the chroot.
fn child_setup(args: &Args) -> io::Result<()> {
    // Own mount namespace so the pivot never disturbs the supervisor's view.
    sys::unshare(libc::CLONE_NEWNS).map_err(|e| sys::annotate(e, "unshare(CLONE_NEWNS)"))?;
    // If the supervisor dies, take this child down too (belt-and-braces alongside
    // the process-group kill and the host-side orphan reaper).
    sys::set_pdeathsig_kill().map_err(|e| sys::annotate(e, "prctl(PR_SET_PDEATHSIG)"))?;
    // Private, recursive propagation so binds/pivot stay in this namespace.
    sys::make_root_private().map_err(|e| sys::annotate(e, "make root mount private"))?;

    let root = args.root.as_path();
    let root_s = path_str(root)?;
    // `pivot_root(2)` requires the new root to be a mount point; bind it onto
    // itself first, before the nested binds so they layer on top of it.
    sys::bind_mount(root_s, root_s)
        .map_err(|e| sys::annotate(e, "bind new root onto itself"))?;

    // Identity bind mounts, in the order given (a read-only parent is bound
    // before any read-write child nested under it, whose mountpoint then already
    // exists via the parent bind).
    for (src, writable) in &args.binds {
        apply_bind(root, src, *writable)?;
    }
    // Device nodes (rw): bind the real node so its gid + dev-allowed flags carry
    // over — this is what keeps `/dev/kvm` openable inside the user namespace.
    for dev in &args.devs {
        apply_bind(root, dev, true)?;
    }

    // A fresh /proc reflecting this pid namespace.
    let proc_mnt = under_root(root, Path::new("/proc"));
    ensure_dir(&proc_mnt)?;
    sys::mount_proc(path_str(&proc_mnt)?).map_err(|e| sys::annotate(e, "mount /proc"))?;

    // pivot_root(".", ".") idiom: stack the old root over the new one, detach it.
    sys::chdir(root_s).map_err(|e| sys::annotate(e, "chdir to new root"))?;
    sys::pivot_root(".", ".").map_err(|e| sys::annotate(e, "pivot_root"))?;
    sys::umount_detach(".").map_err(|e| sys::annotate(e, "detach old root"))?;
    sys::chdir("/").map_err(|e| sys::annotate(e, "chdir to /"))?;
    Ok(())
}

/// Write this process's pid into `<cgroup>/cgroup.procs`.
fn join_cgroup(cgroup: &Path) -> io::Result<()> {
    use std::io::Write;
    let procs = cgroup.join("cgroup.procs");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&procs)
        .map_err(|e| sys::annotate(e, &format!("opening {}", procs.display())))?;
    f.write_all(sys::getpid().to_string().as_bytes())
        .map_err(|e| sys::annotate(e, &format!("writing pid to {}", procs.display())))
}

/// Write the single-id uid/gid maps for the new user namespace.
///
/// `setgroups=deny` is written *first* (required before `gid_map`, per
/// `user_namespaces(7)`; it blocks *dropping* supplementary groups and so
/// preserves the `kvm` membership that keeps `/dev/kvm` openable). We never call
/// `setgroups(2)` to clear the groups.
fn write_id_maps(uid: u32, gid: u32) -> io::Result<()> {
    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| sys::annotate(e, "writing /proc/self/setgroups=deny"))?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))
        .map_err(|e| sys::annotate(e, "writing /proc/self/uid_map"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))
        .map_err(|e| sys::annotate(e, "writing /proc/self/gid_map"))?;
    Ok(())
}

/// Bind `src` at its identical absolute path under `root`, creating the
/// mountpoint (a directory or an empty file matching the source), then remount
/// read-only when requested.
fn apply_bind(root: &Path, src: &Path, writable: bool) -> io::Result<()> {
    let dst = under_root(root, src);
    let meta = std::fs::symlink_metadata(src)
        .map_err(|e| sys::annotate(e, &format!("stat bind source {}", src.display())))?;
    if meta.is_dir() {
        ensure_dir(&dst)?;
    } else {
        ensure_file(&dst)?;
    }
    let src_s = path_str(src)?;
    let dst_s = path_str(&dst)?;
    sys::bind_mount(src_s, dst_s)
        .map_err(|e| sys::annotate(e, &format!("bind {} -> {}", src.display(), dst.display())))?;
    if !writable {
        sys::remount_readonly(dst_s)
            .map_err(|e| sys::annotate(e, &format!("remount {} read-only", dst.display())))?;
    }
    Ok(())
}

/// Map an absolute host path to its identical path under `root`
/// (`root` + the path with its leading `/` stripped).
fn under_root(root: &Path, abs: &Path) -> PathBuf {
    let rel = abs.strip_prefix("/").unwrap_or(abs);
    root.join(rel)
}

/// Ensure `dst` exists as a directory mountpoint. Checks existence first so it
/// never tries to `mkdir` under a read-only parent bind (where the mountpoint
/// already exists via that bind).
fn ensure_dir(dst: &Path) -> io::Result<()> {
    if dst.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dst)
        .map_err(|e| sys::annotate(e, &format!("creating dir mountpoint {}", dst.display())))
}

/// Ensure `dst` exists as an (empty) file mountpoint for binding a file / socket
/// / device node. Checks existence first (see [`ensure_dir`]).
fn ensure_file(dst: &Path) -> io::Result<()> {
    if dst.exists() {
        return Ok(());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            sys::annotate(e, &format!("creating parent of mountpoint {}", dst.display()))
        })?;
    }
    std::fs::File::create(dst)
        .map(|_| ())
        .map_err(|e| sys::annotate(e, &format!("creating file mountpoint {}", dst.display())))
}

/// Borrow a `Path` as a `&str`, erroring on non-UTF-8 (isopod paths are UTF-8).
fn path_str(p: &Path) -> io::Result<&str> {
    p.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("non-UTF-8 path {}", p.display()),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bind_spec_modes() {
        assert_eq!(
            parse_bind_spec("/a/b:ro"),
            (PathBuf::from("/a/b"), false),
            "ro suffix"
        );
        assert_eq!(
            parse_bind_spec("/a/b:rw"),
            (PathBuf::from("/a/b"), true),
            "rw suffix"
        );
        assert_eq!(
            parse_bind_spec("/a/b"),
            (PathBuf::from("/a/b"), true),
            "no suffix defaults rw"
        );
        // A stray colon that is not a mode is kept as part of the path.
        assert_eq!(
            parse_bind_spec("/a:b"),
            (PathBuf::from("/a:b"), true),
            "non-mode colon is path text"
        );
    }

    #[test]
    fn under_root_maps_identity_path() {
        let root = Path::new("/vm/jail-root");
        assert_eq!(
            under_root(root, Path::new("/home/u/.isopod")),
            PathBuf::from("/vm/jail-root/home/u/.isopod")
        );
        assert_eq!(
            under_root(root, Path::new("/dev/kvm")),
            PathBuf::from("/vm/jail-root/dev/kvm")
        );
    }

    #[test]
    fn parse_full_argv() {
        let raw: Vec<String> = [
            "--cgroup",
            "/sys/fs/cgroup/user.slice/isopod.slice/dev-1/",
            "--root",
            "/vm/dev-1/jail-root",
            "--uid",
            "1000",
            "--gid",
            "1000",
            "--bind",
            "/home/u/.isopod:ro",
            "--bind",
            "/home/u/.isopod/vms/dev-1:rw",
            "--dev",
            "/dev/kvm",
            "--dev",
            "/dev/null",
            "--",
            "/home/u/.isopod/bin/firecracker",
            "--api-sock",
            "/home/u/.isopod/vms/dev-1/api.sock",
            "--id",
            "dev-1",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let args = Args::parse(&raw).expect("parses");
        assert_eq!(
            args.cgroup.as_deref(),
            Some(Path::new(
                "/sys/fs/cgroup/user.slice/isopod.slice/dev-1/"
            ))
        );
        assert_eq!(args.root, PathBuf::from("/vm/dev-1/jail-root"));
        assert_eq!(args.uid, 1000);
        assert_eq!(args.gid, 1000);
        assert_eq!(
            args.binds,
            vec![
                (PathBuf::from("/home/u/.isopod"), false),
                (PathBuf::from("/home/u/.isopod/vms/dev-1"), true),
            ]
        );
        assert_eq!(
            args.devs,
            vec![PathBuf::from("/dev/kvm"), PathBuf::from("/dev/null")]
        );
        assert_eq!(args.program[0], "/home/u/.isopod/bin/firecracker");
        assert_eq!(args.program.len(), 5);
        assert_eq!(args.program.last().unwrap(), "dev-1");
    }

    #[test]
    fn parse_requires_root_uid_gid_and_program() {
        let only_uid: [String; 2] = ["--uid".into(), "0".into()];
        assert!(Args::parse(&only_uid).is_err());
        // root but no program after `--`.
        let missing_prog = ["--root", "/r", "--uid", "0", "--gid", "0"].map(String::from);
        assert!(Args::parse(&missing_prog).is_err());
    }

    #[test]
    fn cgroup_is_optional() {
        let raw = ["--root", "/r", "--uid", "0", "--gid", "0", "--", "/bin/true"].map(String::from);
        let args = Args::parse(&raw).expect("parses without --cgroup");
        assert!(args.cgroup.is_none());
        assert_eq!(args.program, vec!["/bin/true".to_string()]);
    }
}
