//! PID-1 zombie reaping that never steals an exec handler's child.
//!
//! A single reaper thread owns `waitpid(-1)`. Any process reparented to PID 1
//! (double-forked daemons, orphaned grandchildren) would otherwise become an
//! unreapable zombie; the reaper collects them all. Exec handlers must **not**
//! call [`std::process::Child::wait`] — that races the reaper for the same
//! status. Instead a handler [`register`](Reaper::register)s its child's pid and
//! receives the exit status over a channel.
//!
//! ## The register/reap race, closed
//!
//! A handler learns its child's pid only after `spawn()` returns, and a very
//! short-lived child could be reaped before the handler registers. To make
//! registration race-free the reaper does not blindly discard a status it can't
//! route: it briefly *stashes* it (bounded FIFO). [`register`](Reaper::register)
//! checks the stash first, so a status that arrived early is delivered anyway.
//! Genuine orphans that no handler ever registers age out of the stash — their
//! zombie is still reaped (the essential PID-1 duty), only the status is dropped.

use std::collections::{HashMap, VecDeque};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::sys::{self, Reap, WaitResult};

/// Upper bound on stashed statuses awaiting a late `register`. Far larger than
/// the microsecond spawn→register window ever needs; caps memory under
/// pathological orphan churn.
const MAX_PENDING: usize = 512;

/// Back-off when there are momentarily no children to wait on.
const IDLE_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Inner {
    /// Handlers waiting for a specific pid's exit.
    waiters: HashMap<i32, Sender<WaitResult>>,
    /// Statuses reaped before their handler registered (race window).
    pending: HashMap<i32, WaitResult>,
    /// Insertion order of `pending`, for bounded FIFO eviction.
    order: VecDeque<i32>,
}

/// Handle to the shared reaper registry. Cheaply cloneable.
#[derive(Clone)]
pub struct Reaper {
    inner: Arc<Mutex<Inner>>,
}

impl Reaper {
    /// Create an (unstarted) reaper.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner::default())),
        }
    }

    /// Start the reaper thread that owns `waitpid(-1)` for the process's life.
    pub fn spawn(&self) {
        let inner = self.inner.clone();
        let _ = std::thread::Builder::new()
            .name("reaper".to_string())
            .spawn(move || reaper_loop(&inner));
    }

    /// Register interest in `pid`. The returned receiver yields that pid's exit
    /// status exactly once (immediately if it was already reaped).
    pub fn register(&self, pid: i32) -> Receiver<WaitResult> {
        let (tx, rx) = mpsc::channel();
        let mut g = lock(&self.inner);
        if let Some(res) = g.pending.remove(&pid) {
            // Reaped during the spawn→register window; deliver the stashed status.
            let _ = tx.send(res);
        } else {
            g.waiters.insert(pid, tx);
        }
        rx
    }
}

impl Default for Reaper {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock the registry, recovering from poisoning (a panicked holder must not wedge
/// PID 1 forever).
fn lock(inner: &Mutex<Inner>) -> std::sync::MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

fn reaper_loop(inner: &Mutex<Inner>) -> ! {
    loop {
        match sys::wait_any_blocking() {
            Reap::Child(res) => route(inner, res),
            Reap::Interrupted => {}
            Reap::NoChildren => std::thread::sleep(IDLE_BACKOFF),
        }
    }
}

fn route(inner: &Mutex<Inner>, res: WaitResult) {
    let mut g = lock(inner);
    if let Some(tx) = g.waiters.remove(&res.pid) {
        let _ = tx.send(res);
        return;
    }
    // No waiter yet: stash it (a handler may be mid-register) with a hard cap.
    if g.pending.len() >= MAX_PENDING {
        if let Some(old) = g.order.pop_front() {
            g.pending.remove(&old);
        }
    }
    g.pending.insert(res.pid, res);
    g.order.push_back(res.pid);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn late_register_receives_stashed_status() {
        let reaper = Reaper::new();
        // Simulate the reaper reaping a pid before the handler registers.
        route(
            &reaper.inner,
            WaitResult {
                pid: 42,
                exit_code: Some(7),
                signal: None,
            },
        );
        let rx = reaper.register(42);
        let got = rx.recv().expect("stashed status delivered");
        assert_eq!(got.pid, 42);
        assert_eq!(got.exit_code, Some(7));
    }

    #[test]
    fn early_register_then_reap_delivers() {
        let reaper = Reaper::new();
        let rx = reaper.register(99);
        route(
            &reaper.inner,
            WaitResult {
                pid: 99,
                exit_code: None,
                signal: Some(9),
            },
        );
        let got = rx.recv().expect("status routed to waiter");
        assert_eq!(got.signal, Some(9));
    }

    #[test]
    fn pending_stash_is_bounded() {
        let reaper = Reaper::new();
        for pid in 0..(MAX_PENDING as i32 + 10) {
            route(
                &reaper.inner,
                WaitResult {
                    pid,
                    exit_code: Some(0),
                    signal: None,
                },
            );
        }
        let g = lock(&reaper.inner);
        assert!(g.pending.len() <= MAX_PENDING);
    }
}
