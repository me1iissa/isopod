//! Per-VM resource allocation: vCPU count + guest memory size, resolved and
//! validated against the host's real capacity.
//!
//! A `isopod run` / `sandbox_run` caller may ask for a specific size; this
//! module turns a requested `(vcpus, mem_mib)` pair into a host-validated
//! [`Resources`], or a clear error naming the exceeded cap. Requests are
//! **never silently clamped** — the caller asked for a concrete size, so a
//! quiet shrink would be a surprising footgun; an out-of-range value is a hard
//! error instead.
//!
//! # Warm-pool cache key (M6 design note)
//! The resolved `(vcpus, mem_mib)` pair is part of the future warm-pool
//! snapshot cache key. A Firecracker **memory snapshot is bound to the exact
//! guest memory size it was captured at** and cannot be resumed into a VM
//! configured with a different `mem_size_mib` (the memory file is a byte image
//! of that much RAM); the vCPU count is likewise fixed in the saved vmstate.
//! So M6 must key each snapshot on the resource shape alongside the FC build
//! hash, host kernel, CPU model, base flavor and snapshot format — any mismatch
//! falls back to a cold boot. [`Resources`] is therefore kept trivially
//! hashable (`#[derive(Hash)]`) and stringifiable ([`Resources::cache_fragment`])
//! so it drops straight into that composite key with no further normalization.

use anyhow::{bail, Context, Result};

/// Default vCPU count when the caller does not request a specific size.
pub const DEFAULT_VCPUS: u32 = 1;

/// Default guest memory (MiB) when the caller does not request a specific size.
///
/// Bumped from the historical 256 MiB: `pip` / `npm` installs OOM-kill at
/// 256 MiB on any non-trivial dependency set, so 512 MiB is the safer floor for
/// the default toolchain base.
pub const DEFAULT_MEM_MIB: u32 = 512;

/// Absolute floor on guest memory (MiB): below this the guest kernel + PID-1
/// agent will not boot reliably.
pub const MIN_MEM_MIB: u32 = 128;

/// Hard ceiling on guest memory (MiB) regardless of host size, so a single VM
/// can never request an unbounded slice even on a large host.
pub const MAX_MEM_MIB: u32 = 4096;

/// Guest memory (MiB) held back for the host (kernel, page cache, the VMM's own
/// footprint) when capping a request against detected RAM.
pub const HOST_MEM_HEADROOM_MIB: u32 = 512;

/// Firecracker's own hard ceiling on vCPUs (`vcpu_count` must be in `[1, 32]`).
pub const MAX_VCPUS: u32 = 32;

/// A resolved, host-validated per-VM resource allocation.
///
/// Constructed only via [`resolve`] / [`resolve_for_host`], so an instance is a
/// proof that the values fit the host. See the module docs for the M6 warm-pool
/// cache-key role that motivates the `Hash` derive and [`Self::cache_fragment`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Resources {
    /// Guest vCPU count (`vcpu_count` in the Firecracker machine-config).
    pub vcpus: u32,
    /// Guest memory in MiB (`mem_size_mib` in the Firecracker machine-config).
    pub mem_mib: u32,
}

impl Resources {
    /// A stable, compact string form for the M6 warm-pool cache key, e.g.
    /// `2c-1024m`. Deterministic and collision-free across distinct shapes, so
    /// it can be concatenated into a larger key or hashed directly.
    #[must_use]
    pub fn cache_fragment(&self) -> String {
        format!("{}c-{}m", self.vcpus, self.mem_mib)
    }
}

/// Effective guest-memory ceiling (MiB) for a host with `host_mem_mib` total
/// RAM: leave [`HOST_MEM_HEADROOM_MIB`] for the host, and never exceed the hard
/// [`MAX_MEM_MIB`] cap. Saturating so a tiny host cannot underflow.
fn mem_cap(host_mem_mib: u32) -> u32 {
    host_mem_mib
        .saturating_sub(HOST_MEM_HEADROOM_MIB)
        .min(MAX_MEM_MIB)
}

/// Effective vCPU ceiling for a host with `host_nproc` processors: never more
/// than the host has, and never above Firecracker's [`MAX_VCPUS`] hard limit.
fn vcpu_cap(host_nproc: u32) -> u32 {
    host_nproc.min(MAX_VCPUS)
}

/// Validate a requested `(vcpus, mem_mib)` against host capacity, returning the
/// resolved [`Resources`] unchanged on success.
///
/// Pure and side-effect-free: `host_nproc` and `host_mem_mib` are injected so
/// this is unit-testable without depending on the machine it runs on. Callers
/// on the real host use [`resolve_for_host`], which detects those two values.
///
/// # Errors
/// Returns an error naming the violated bound (and its cap) when `vcpus` or
/// `mem_mib` is out of range. Values are never silently clamped.
pub fn resolve(vcpus: u32, mem_mib: u32, host_nproc: u32, host_mem_mib: u32) -> Result<Resources> {
    let vcpu_cap = vcpu_cap(host_nproc);
    if vcpus < 1 {
        bail!("vcpus must be at least 1 (requested {vcpus})");
    }
    if vcpus > vcpu_cap {
        bail!(
            "vcpus {vcpus} exceeds the host CPU cap of {vcpu_cap} \
             (host has {host_nproc} processors); request 1..={vcpu_cap}"
        );
    }
    // Firecracker requires vcpu_count to be 1 or an even number; reject odd
    // counts > 1 up front rather than surfacing an opaque API 400 at boot.
    if vcpus > 1 && !vcpus.is_multiple_of(2) {
        bail!("vcpus {vcpus} is invalid: Firecracker allows 1 or an even count (2, 4, 6, …)");
    }

    let mem_cap = mem_cap(host_mem_mib);
    if mem_mib < MIN_MEM_MIB {
        bail!("mem_mib {mem_mib} is below the {MIN_MEM_MIB} MiB floor");
    }
    if mem_mib > mem_cap {
        bail!(
            "mem_mib {mem_mib} exceeds the host memory cap of {mem_cap} MiB \
             (host has {host_mem_mib} MiB total; {HOST_MEM_HEADROOM_MIB} MiB reserved for the host, \
             hard max {MAX_MEM_MIB} MiB)"
        );
    }

    Ok(Resources { vcpus, mem_mib })
}

/// Resolve `(vcpus, mem_mib)` against the *current* host's detected capacity
/// (CPU count via [`host_nproc`], total RAM via [`host_mem_mib`]).
///
/// # Errors
/// If host RAM cannot be read, or the request is out of range (see [`resolve`]).
pub fn resolve_for_host(vcpus: u32, mem_mib: u32) -> Result<Resources> {
    let nproc = host_nproc();
    let mem = host_mem_mib()?;
    resolve(vcpus, mem_mib, nproc, mem)
}

/// Detect the number of processors usable by this process.
///
/// Uses [`std::thread::available_parallelism`] (which honours CPU affinity and
/// cgroup quotas — a truer "how many CPUs can I actually use" than the raw
/// `/proc/cpuinfo` count), falling back to 1 if the platform cannot report it.
#[must_use]
pub fn host_nproc() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Detect total host RAM in MiB from `/proc/meminfo` (`MemTotal`, reported in
/// kB).
///
/// # Errors
/// If `/proc/meminfo` cannot be read or has no parseable `MemTotal` line.
pub fn host_mem_mib() -> Result<u32> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").context("reading /proc/meminfo")?;
    parse_mem_total_mib(&meminfo)
}

/// Parse `MemTotal` (kB) out of `/proc/meminfo` text and return it in MiB.
/// Split out so the parse is unit-testable off a fixed fixture.
///
/// # Errors
/// If no `MemTotal:` line is present or its value does not parse.
fn parse_mem_total_mib(meminfo: &str) -> Result<u32> {
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            // e.g. "MemTotal:        6069372 kB"
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .with_context(|| format!("parsing MemTotal from {line:?}"))?;
            return Ok((kb / 1024) as u32);
        }
    }
    bail!("no MemTotal line found in /proc/meminfo")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Representative WSL2 host: 4 vCPU, ~5.9 GiB RAM.
    const HOST_NPROC: u32 = 4;
    const HOST_MEM_MIB: u32 = 5927;

    #[test]
    fn defaults_resolve_on_a_typical_host() {
        let r = resolve(DEFAULT_VCPUS, DEFAULT_MEM_MIB, HOST_NPROC, HOST_MEM_MIB)
            .expect("defaults must fit a typical host");
        assert_eq!(r.vcpus, 1);
        assert_eq!(r.mem_mib, 512);
    }

    #[test]
    fn requested_values_pass_through_unchanged() {
        let r = resolve(2, 1024, HOST_NPROC, HOST_MEM_MIB).expect("2c/1024m fits");
        assert_eq!(
            r,
            Resources {
                vcpus: 2,
                mem_mib: 1024
            }
        );
    }

    #[test]
    fn vcpus_above_host_count_error_names_the_cap() {
        let err = resolve(99, 512, HOST_NPROC, HOST_MEM_MIB).expect_err("99 vCPUs must error");
        let msg = err.to_string();
        assert!(msg.contains("99"), "names the request: {msg}");
        assert!(msg.contains("host CPU cap of 4"), "names the cap: {msg}");
    }

    #[test]
    fn vcpus_capped_at_firecracker_max_even_on_a_huge_host() {
        // 64-core host: the FC hard limit of 32 binds before the host count.
        let err = resolve(48, 512, 64, 131_072).expect_err("48 > FC max 32");
        assert!(err.to_string().contains("host CPU cap of 32"));
        assert!(
            resolve(32, 512, 64, 131_072).is_ok(),
            "exactly 32 is allowed"
        );
    }

    #[test]
    fn zero_vcpus_is_rejected() {
        assert!(resolve(0, 512, HOST_NPROC, HOST_MEM_MIB).is_err());
    }

    #[test]
    fn odd_vcpus_above_one_are_rejected() {
        let err = resolve(3, 512, HOST_NPROC, HOST_MEM_MIB).expect_err("3 is odd");
        assert!(err.to_string().contains("even"), "explains the rule: {err}");
        // 1 is the one allowed odd value.
        assert!(resolve(1, 512, HOST_NPROC, HOST_MEM_MIB).is_ok());
        assert!(resolve(4, 512, HOST_NPROC, HOST_MEM_MIB).is_ok());
    }

    #[test]
    fn mem_below_floor_is_rejected() {
        let err = resolve(1, 64, HOST_NPROC, HOST_MEM_MIB).expect_err("64 MiB < floor");
        assert!(err.to_string().contains("128 MiB floor"), "{err}");
        assert!(resolve(1, MIN_MEM_MIB, HOST_NPROC, HOST_MEM_MIB).is_ok());
    }

    #[test]
    fn mem_above_host_headroom_error_names_the_cap() {
        // Small host: 2 GiB total => cap = 2048 - 512 = 1536 MiB.
        let err = resolve(1, 2000, 2, 2048).expect_err("2000 > 1536 cap");
        let msg = err.to_string();
        assert!(msg.contains("2000"), "names the request: {msg}");
        assert!(msg.contains("cap of 1536 MiB"), "names the cap: {msg}");
        assert!(
            resolve(1, 1536, 2, 2048).is_ok(),
            "exactly the cap is allowed"
        );
    }

    #[test]
    fn mem_hard_max_binds_on_a_large_host() {
        // 64 GiB host: headroom cap would be huge, but MAX_MEM_MIB (4096) binds.
        let err = resolve(1, 8192, 8, 65_536).expect_err("8192 > 4096 hard max");
        assert!(err.to_string().contains("cap of 4096 MiB"), "{err}");
        assert!(resolve(1, MAX_MEM_MIB, 8, 65_536).is_ok());
    }

    #[test]
    fn cache_fragment_is_stable_and_distinct() {
        assert_eq!(
            Resources {
                vcpus: 2,
                mem_mib: 1024
            }
            .cache_fragment(),
            "2c-1024m"
        );
        assert_eq!(
            Resources {
                vcpus: 1,
                mem_mib: 512
            }
            .cache_fragment(),
            "1c-512m"
        );
        assert_ne!(
            Resources {
                vcpus: 2,
                mem_mib: 512
            }
            .cache_fragment(),
            Resources {
                vcpus: 1,
                mem_mib: 1024
            }
            .cache_fragment(),
        );
    }

    #[test]
    fn parses_mem_total_to_mib() {
        let sample = "MemFree:          123456 kB\nMemTotal:        6069372 kB\nBuffers: 1 kB\n";
        assert_eq!(parse_mem_total_mib(sample).unwrap(), 6069372 / 1024);
    }

    #[test]
    fn parse_mem_total_errors_without_the_line() {
        assert!(parse_mem_total_mib("MemFree: 100 kB\n").is_err());
    }
}
