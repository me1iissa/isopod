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
