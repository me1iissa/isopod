//! A vsock connection wrapped so its frame writes can be serialized across the
//! per-connection dispatch thread and the exec output pumps.
//!
//! The accepted `AF_VSOCK` fd is turned into a [`std::fs::File`], which gives
//! blocking `Read`/`Write` on the socket and closes it on drop. The `File` lives
//! behind an `Arc<Mutex<…>>`: the dispatch loop reads request frames through it,
//! and — during an exec — the two output-pump threads lock it to interleave
//! `ExecStream` frames without corrupting each other or the terminal frame.

use std::fs::File;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex};

use isopod_proto::{read_frame, write_frame, FrameError, Request, Response};

/// A shared, write-serialized handle to one vsock connection.
#[derive(Clone)]
pub struct Conn {
    inner: Arc<Mutex<File>>,
}

impl Conn {
    /// Adopt an accepted vsock fd as a connection.
    pub fn from_fd(fd: OwnedFd) -> Self {
        Self {
            inner: Arc::new(Mutex::new(File::from(fd))),
        }
    }

    /// Another handle to the same connection (for the exec output pumps).
    pub fn clone_handle(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }

    /// Read the next request frame, or `Ok(None)` on a clean EOF at a frame
    /// boundary (peer closed the connection).
    ///
    /// Blocks while holding the lock, which is correct: the dispatch loop only
    /// reads between requests, when no exec pump is writing.
    pub fn read_request(&self) -> Result<Option<Request>, FrameError> {
        let mut g = self.lock();
        read_frame(&mut *g)
    }

    /// Write one response frame (locks, writes, flushes).
    pub fn send(&self, resp: &Response) -> Result<(), FrameError> {
        let mut g = self.lock();
        write_frame(&mut *g, resp)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, File> {
        // A panicked writer must not wedge the connection; recover the guard.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}
