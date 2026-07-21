//! On-disk layout for `~/.isopod` — the single source of truth every subsystem
//! resolves its paths through.
//!
//! The root is `$ISOPOD_HOME` when set (tests and CI point it at a scratch dir),
//! otherwise `~/.isopod`. Directory accessors create their target on demand with
//! mode `0755` so callers never have to pre-create anything.

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

/// Create `dir` (and parents) if absent and ensure it is mode `0755`.
fn ensure_dir(dir: PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating directory {}", dir.display()))?;
    let perms = std::fs::Permissions::from_mode(0o755);
    std::fs::set_permissions(&dir, perms)
        .with_context(|| format!("setting 0755 on {}", dir.display()))?;
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
