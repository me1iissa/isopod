//! On-disk layout for `~/.isopod` — the single source of truth every subsystem
//! resolves its paths through.
//!
//! The root is `$ISOPOD_HOME` when set (tests and CI point it at a scratch dir),
//! otherwise `~/.isopod`. Directory accessors create their target on demand with
//! mode `0700` so callers never have to pre-create anything.
//!
//! `0700`, not `0755`, because of what lives under it: every run's `console.log`,
//! `exec-stdout.log`, `exec-stderr.log` and `egress.jsonl`, each created with a
//! plain `File::create` and therefore `0644` under the usual umask. A traversable
//! parent made all of it readable by every local account on the host. Nothing
//! isopod runs needs the tree to be world-traversable — firecracker runs as the
//! same user — so the directory mode is where this is fixed once, rather than at
//! every file creation.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Resolve the isopod home directory: `$ISOPOD_HOME` if set, else `~/.isopod`.
///
/// This does not create the directory — the per-subdirectory accessors
/// ([`images_dir`], [`stages_dir`], …) do that.
pub fn isopod_home() -> Result<PathBuf> {
    home_from(std::env::var_os("ISOPOD_HOME"), dirs::home_dir())
}

/// Pure resolution of the home directory from an (optional) override and an
/// (optional) OS home directory. Split out so it can be unit-tested without
/// mutating process-global environment state.
fn home_from(override_var: Option<OsString>, os_home: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(v) = override_var {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let home = os_home.context("cannot determine home directory (set ISOPOD_HOME)")?;
    Ok(home.join(".isopod"))
}

/// The mode every isopod state directory is created with, and tightened to if it
/// is found looser. See the module docs for why it is not `0755`.
const DIR_MODE: u32 = 0o700;

/// Create `dir` (and parents) if absent, and tighten it to [`DIR_MODE`] if it is
/// currently more permissive than that.
///
/// Tightening only, never loosening. This used to `set_permissions(0o755)`
/// unconditionally on every call — not at create time, on *every* call — so an
/// operator who ran `chmod 700 ~/.isopod/vms` had it silently undone by the next
/// run. Going the other way is safe: a directory this process can already reach
/// stays reachable, and anything beyond `0700` on a per-user state tree was not
/// serving a purpose isopod knows about.
fn ensure_dir(dir: PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating directory {}", dir.display()))?;
    let current = std::fs::metadata(&dir)
        .with_context(|| format!("reading the mode of {}", dir.display()))?
        .permissions()
        .mode()
        & 0o7777;
    if current & !DIR_MODE != 0 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(DIR_MODE))
            .with_context(|| format!("tightening {} to 0700", dir.display()))?;
    }
    Ok(dir)
}

/// `~/.isopod/images` — kernels and rootfs images. Created on demand.
pub fn images_dir() -> Result<PathBuf> {
    ensure_dir(isopod_home()?.join("images"))
}

/// `~/.isopod/stages` — committed stage layers (M3). Created on demand.
pub fn stages_dir() -> Result<PathBuf> {
    ensure_dir(isopod_home()?.join("stages"))
}

/// `~/.isopod/vms` — per-VM runtime state and exec logs (M2). Created on demand.
pub fn vms_dir() -> Result<PathBuf> {
    ensure_dir(isopod_home()?.join("vms"))
}

/// The kernel's hard limit on a Unix-domain socket path: `sun_path` is 108
/// bytes including its NUL terminator, so 107 usable bytes.
///
/// Measured, not read off a header: binding at successively deeper paths fails
/// at exactly 108.
const SUN_PATH_MAX: usize = 107;

/// The longest basename isopod appends inside a VM directory (`vsock.sock`;
/// `api.sock` is shorter).
const LONGEST_SOCKET_NAME: &str = "/vsock.sock";

/// Refuse a VM directory whose sockets would not fit in `sun_path`.
///
/// Firecracker's API socket and the guest-agent vsock both live inside the VM
/// directory, so a deep `$ISOPOD_HOME` silently pushes them past the kernel's
/// limit. The failure is invisible at the point it happens: `bind` fails inside
/// Firecracker, the process exits 1, and isopod waits the full **ten seconds**
/// for a socket that will never appear before reporting a timeout that names
/// the path but not the reason. This turns that into an immediate, specific
/// refusal.
///
/// # Errors
/// If `<vm_dir>/vsock.sock` would exceed the kernel's 107-byte limit.
pub fn check_socket_path_fits(vm_dir: &Path) -> Result<()> {
    let len = socket_path_len(vm_dir);
    if len <= SUN_PATH_MAX {
        return Ok(());
    }
    let over = len - SUN_PATH_MAX;
    anyhow::bail!(
        "the VM directory {} is too deep for a Unix socket: its vsock path is {len} bytes and \
         the kernel's limit is {SUN_PATH_MAX}, so Firecracker cannot bind and the run would \
         fail as an unexplained timeout. Shorten $ISOPOD_HOME by at least {over} bytes (it is \
         currently {home} bytes) or leave it unset to use ~/.isopod",
        vm_dir.display(),
        home = vm_dir
            .parent()
            .and_then(Path::parent)
            .map_or(0, |p| p.as_os_str().len()),
    )
}

/// Byte length of the longest socket path isopod will create inside `vm_dir`.
///
/// Pure, so the arithmetic is testable without building a directory tree that
/// deep — which is the only reason this boundary went unnoticed.
#[must_use]
fn socket_path_len(vm_dir: &Path) -> usize {
    vm_dir.as_os_str().len() + LONGEST_SOCKET_NAME.len()
}

/// `~/.isopod/snapshots` — warm-pool snapshot artifacts (M6). Created on demand.
pub fn snapshots_dir() -> Result<PathBuf> {
    ensure_dir(isopod_home()?.join("snapshots"))
}

/// Compute a lowercase hex SHA-256 of a file, streamed (no full-file buffering).
pub fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file =
        std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher).with_context(|| format!("hashing {}", path.display()))?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    /// The exact boundary, asserted rather than assumed. 107 bytes bind; 108
    /// does not — measured by binding at successively deeper paths.
    #[test]
    fn the_socket_budget_is_the_kernels_and_not_a_guess() {
        // A vm_dir whose vsock path lands exactly on the limit is allowed.
        let exact = "x".repeat(SUN_PATH_MAX - LONGEST_SOCKET_NAME.len());
        let dir = std::path::PathBuf::from(&exact);
        assert_eq!(socket_path_len(&dir), SUN_PATH_MAX);
        assert!(check_socket_path_fits(&dir).is_ok(), "107 bytes must fit");

        // One byte more must not.
        let over = std::path::PathBuf::from(format!("{exact}y"));
        assert_eq!(socket_path_len(&over), SUN_PATH_MAX + 1);
        assert!(check_socket_path_fits(&over).is_err(), "108 bytes must not");
    }

    /// The refusal has to be actionable: the failure it replaces named the path
    /// and nothing else, which is why it cost ten seconds and a head-scratch.
    #[test]
    fn the_refusal_says_how_much_too_long_and_what_to_change() {
        let dir = std::path::PathBuf::from(format!("/{}/vms/dev-0123abcd", "d".repeat(120)));
        let err = check_socket_path_fits(&dir).unwrap_err().to_string();
        assert!(err.contains("ISOPOD_HOME"), "names the knob: {err}");
        assert!(err.contains("Shorten"), "says what to do: {err}");
        assert!(err.contains("107"), "names the limit: {err}");
        assert!(
            err.contains("unexplained timeout"),
            "connects it to the symptom the operator actually sees: {err}"
        );
    }

    /// The default home must not be anywhere near the limit — if it were, this
    /// guard would refuse ordinary installs.
    #[test]
    fn the_default_home_leaves_ample_room() {
        let dir =
            std::path::PathBuf::from("/home/a-reasonably-long-username/.isopod/vms/dev-0123abcd");
        assert!(
            check_socket_path_fits(&dir).is_ok(),
            "a normal home must not trip the guard"
        );
    }

    use super::*;

    #[test]
    fn ensure_dir_tightens_a_loose_tree_and_leaves_a_tight_one_alone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mode_of = |p: &Path| std::fs::metadata(p).expect("stat").permissions().mode() & 0o7777;

        // Created fresh: 0700, so the run logs and egress records inside it are not
        // readable by every local account.
        let fresh = ensure_dir(tmp.path().join("fresh")).expect("create");
        assert_eq!(mode_of(&fresh), DIR_MODE);

        // Found world-traversable: tightened.
        let loose = tmp.path().join("loose");
        std::fs::create_dir_all(&loose).expect("mkdir");
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let loose = ensure_dir(loose).expect("tighten");
        assert_eq!(mode_of(&loose), DIR_MODE);

        // Found tighter than we ask for: left exactly as the operator set it. The
        // bug this replaces was a chmod on every call, which silently undid a
        // deliberate `chmod 700` — so re-loosening here would be the same mistake
        // in the other direction.
        let tight = tmp.path().join("tight");
        std::fs::create_dir_all(&tight).expect("mkdir");
        std::fs::set_permissions(&tight, std::fs::Permissions::from_mode(0o500)).expect("chmod");
        let tight = ensure_dir(tight).expect("leave alone");
        assert_eq!(mode_of(&tight), 0o500);
    }

    #[test]
    fn override_wins_over_home() {
        let got = home_from(
            Some(OsString::from("/scratch/iso")),
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(got, PathBuf::from("/scratch/iso"));
    }

    #[test]
    fn empty_override_falls_back_to_home() {
        let got = home_from(Some(OsString::from("")), Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(got, PathBuf::from("/home/u/.isopod"));
    }

    #[test]
    fn default_is_home_dot_isopod() {
        let got = home_from(None, Some(PathBuf::from("/home/u"))).unwrap();
        assert_eq!(got, PathBuf::from("/home/u/.isopod"));
    }

    #[test]
    fn no_home_and_no_override_errors() {
        assert!(home_from(None, None).is_err());
    }
}
