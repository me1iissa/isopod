//! Directory-relative syscalls — the only `unsafe` in this crate.
//!
//! Everything here operates on a [`Dir`], an open descriptor for a directory,
//! and a single **name** (never a path with separators). That shape is the
//! confinement: a name cannot address a parent, and `O_NOFOLLOW` means a name
//! cannot be redirected by a symbolic link. The caller walks the tree one
//! component at a time and therefore sees, and gets to refuse, every link.
//!
//! `openat(2)`, `mkdirat(2)`, `unlinkat(2)`, `symlinkat(2)`, `linkat(2)` and
//! `fstatat(2)` are POSIX.1-2008; `O_NOFOLLOW` and `O_DIRECTORY` are specified
//! by POSIX for `open(2)` and inherited by `openat`.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;

/// A name that syscalls will accept: no interior NUL, not a path, and not `.`
/// or `..`.
///
/// This is the check that makes "a name cannot address a parent" true of this
/// module rather than only of its callers. `..` is not hypothetical: a whiteout
/// marker spelled `.wh...` asks for `..` to be deleted from the marker's own
/// directory, and at the top of the tree that names the staging root's parent —
/// the caller's destination directory. The name is refused twice, here and when
/// the entry is planned, because only one of those two places is obvious.
fn cname(name: &OsStr) -> io::Result<CString> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'/') || bytes == b"." || bytes == b".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name:?} is not a single, self-naming path component"),
        ));
    }
    CString::new(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))
}

fn last_err<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

/// An open directory descriptor.
#[derive(Debug)]
pub struct Dir(OwnedFd);

/// Flags shared by every directory open: never follow a link, never leak the
/// descriptor across an exec, and refuse anything that is not a directory.
const DIR_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

impl Dir {
    /// Open a directory by path. Used once, for the staging root; every
    /// descendant is reached with [`Dir::open_dir`] instead.
    pub fn open_root(path: &Path) -> io::Result<Self> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call.
        let fd = unsafe { libc::open(c.as_ptr(), DIR_FLAGS) };
        if fd < 0 {
            return last_err();
        }
        // SAFETY: `fd` is a fresh, valid, owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Self)
    }

    /// Open a child **directory**. Fails `ELOOP` if the child is a symbolic
    /// link, `ENOTDIR` if it is anything else that is not a directory, and
    /// `ENOENT` if it does not exist — the three answers the walk needs to tell
    /// apart.
    pub fn open_dir(&self, name: &OsStr) -> io::Result<Self> {
        let c = cname(name)?;
        // SAFETY: `self.0` is an open directory descriptor and `c` is a valid
        // C string that outlives the call.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), c.as_ptr(), DIR_FLAGS) };
        if fd < 0 {
            return last_err();
        }
        // SAFETY: `fd` is a fresh, valid, owned descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Create a child directory. `EEXIST` is the caller's to interpret.
    pub fn mkdir(&self, name: &OsStr, mode: u32) -> io::Result<()> {
        let c = cname(name)?;
        // SAFETY: as above.
        let rc = unsafe { libc::mkdirat(self.0.as_raw_fd(), c.as_ptr(), mode as libc::mode_t) };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Create a child **regular file**, failing if anything already sits at the
    /// name. `O_EXCL` is what makes that true even for a symbolic link:
    /// together with `O_NOFOLLOW` it is the one open that cannot be redirected.
    pub fn create_file(&self, name: &OsStr, mode: u32) -> io::Result<File> {
        let c = cname(name)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: as above; the variadic `mode` is required by `O_CREAT` and is
        // passed with the C default promotion `mode_t` -> `c_uint`.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c.as_ptr(),
                flags,
                libc::c_uint::from(mode as libc::mode_t),
            )
        };
        if fd < 0 {
            return last_err();
        }
        // SAFETY: `fd` is a fresh, valid, owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Create a symbolic link. The target is stored verbatim and never
    /// resolved: inside the image it will be interpreted against the image's
    /// own root, and this extractor never follows one.
    pub fn symlink(&self, target: &[u8], name: &OsStr) -> io::Result<()> {
        let c = cname(name)?;
        let t = CString::new(target)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "target contains NUL"))?;
        // SAFETY: both strings are valid and outlive the call.
        let rc = unsafe { libc::symlinkat(t.as_ptr(), self.0.as_raw_fd(), c.as_ptr()) };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Hard-link `src_dir/src` to `self/name`.
    ///
    /// `flags` is 0, i.e. **not** `AT_SYMLINK_FOLLOW`: if the source name is a
    /// symbolic link the new link refers to the link itself, so a link target
    /// cannot reach outside the tree by pointing at one.
    pub fn link_from(&self, src_dir: &Dir, src: &OsStr, name: &OsStr) -> io::Result<()> {
        let s = cname(src)?;
        let d = cname(name)?;
        // SAFETY: both descriptors are open directories and both strings are valid.
        let rc = unsafe {
            libc::linkat(
                src_dir.0.as_raw_fd(),
                s.as_ptr(),
                self.0.as_raw_fd(),
                d.as_ptr(),
                0,
            )
        };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// `lstat` a child: never follows a link in the final component.
    pub fn lstat(&self, name: &OsStr) -> io::Result<libc::stat> {
        let c = cname(name)?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
        // SAFETY: `st` is writable for `libc::stat` and `c` is valid.
        let rc = unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                c.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc < 0 {
            return last_err();
        }
        // SAFETY: `fstatat` returned 0, so it initialised the buffer.
        Ok(unsafe { st.assume_init() })
    }

    /// Unlink a child. `dir` selects `AT_REMOVEDIR`; without it a directory
    /// fails with `EISDIR` and a symbolic link is removed rather than followed.
    pub fn unlink(&self, name: &OsStr, dir: bool) -> io::Result<()> {
        let c = cname(name)?;
        let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
        // SAFETY: as above.
        let rc = unsafe { libc::unlinkat(self.0.as_raw_fd(), c.as_ptr(), flags) };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Set this directory's own mode.
    pub fn chmod(&self, mode: u32) -> io::Result<()> {
        // SAFETY: `self.0` is an open descriptor.
        let rc = unsafe { libc::fchmod(self.0.as_raw_fd(), mode as libc::mode_t) };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Set a child **directory's** mode.
    ///
    /// `fchmodat` follows a symbolic link in the final component, so this is
    /// only ever called where the caller has already established that the child
    /// is a real directory — `unlinkat` answering `EISDIR`, which a link would
    /// not produce because it would simply have been removed.
    pub fn chmod_child(&self, name: &OsStr, mode: u32) -> io::Result<()> {
        let c = cname(name)?;
        // SAFETY: `self.0` is an open directory descriptor and `c` is valid.
        let rc = unsafe { libc::fchmodat(self.0.as_raw_fd(), c.as_ptr(), mode as libc::mode_t, 0) };
        if rc < 0 {
            return last_err();
        }
        Ok(())
    }

    /// Child names, excluding `.` and `..`.
    ///
    /// Reads through a duplicate of the descriptor because `fdopendir(3)` takes
    /// ownership of the one it is given and `closedir(3)` closes it — handing it
    /// `self.0` would close a descriptor the caller still holds.
    pub fn entries(&self) -> io::Result<Vec<OsString>> {
        // SAFETY: `self.0` is an open descriptor.
        let dup = unsafe { libc::dup(self.0.as_raw_fd()) };
        if dup < 0 {
            return last_err();
        }
        // SAFETY: `dup` is a fresh descriptor for a directory; `fdopendir`
        // takes ownership of it on success.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: `fdopendir` failed, so `dup` is still ours to close.
            unsafe { libc::close(dup) };
            return Err(e);
        }
        let mut out = Vec::new();
        let mut err = None;
        loop {
            // `readdir` returns NULL both at end-of-directory and on error, and
            // only `errno` tells them apart — so it has to be cleared first.
            // SAFETY: `__errno_location` always returns a valid pointer.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: `dirp` is an open directory stream.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(0) {
                    err = Some(e);
                }
                break;
            }
            // SAFETY: `readdir` returned a valid `dirent` whose `d_name` is a
            // NUL-terminated string owned by the stream, valid until the next
            // `readdir`/`closedir`; it is copied out immediately.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let bytes = name.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            out.push(OsString::from_vec(bytes.to_vec()));
        }
        // SAFETY: `dirp` is open and not used again.
        unsafe { libc::closedir(dirp) };
        match err {
            Some(e) => Err(e),
            None => Ok(out),
        }
    }
}

/// Is this `st_mode` a symbolic link?
#[must_use]
pub fn is_symlink(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// Is this `st_mode` a directory?
#[must_use]
pub fn is_dir(st: &libc::stat) -> bool {
    st.st_mode & libc::S_IFMT == libc::S_IFDIR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_cannot_address_a_parent_or_spell_a_path() {
        // Defence in depth for the whiteout-target hole: `.wh...` produces the
        // target `..`, which reaches this module without having been through
        // the entry-name component loop. If `open_dir("..")` ever succeeds, the
        // recursive delete walks out of the staging tree and into the caller's
        // destination directory.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(tmp.path().join("sub")).expect("mkdir");
        let d = Dir::open_root(tmp.path()).expect("open root");
        for bad in ["..", ".", "sub/..", "/etc", "", "a/b"] {
            assert!(
                d.open_dir(OsStr::new(bad)).is_err(),
                "{bad:?} was accepted as a single component"
            );
        }
        assert!(d.open_dir(OsStr::new("sub")).is_ok(), "the ordinary case");
    }
}
