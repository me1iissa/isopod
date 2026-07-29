//! Local observability: the sealed span-attribute type and its recorder.
//!
//! Every span attribute isopod records goes through [`Attr`]. The enum has no
//! free-form `String` variant on purpose: a user-chosen or guest-authored value
//! cannot reach a span attribute without a visible type change in the diff.
//! The only string-shaped variants are `&'static str` (compile-time text, the
//! same invariant the egress recorder's `EgressDenied.note` enforces) and
//! [`Attr::VmId`], which carries the host-minted random `dev-<8 hex>` id — the
//! one identifier that is neither user-chosen nor guest-written.
//!
//! Nothing here exports anywhere. Spans reach stderr through a `tracing-fmt`
//! subscriber the binaries install under `RUST_LOG`, and are inert without one.
//! Size-proportional magnitudes (output bytes, copy counts) are recorded only
//! as log2 bucket indices even locally, so a future export layer has nothing
//! to strip; durations stay exact locally by design — quantizing them is an
//! export-path concern, not a measurement change.

use std::time::Instant;

/// All spans use this target, so one `RUST_LOG=isopod=debug` directive enables
/// the whole tree regardless of which crate module emitted a span.
pub(crate) const TARGET: &str = "isopod";

/// Which boot source served a run, normalized to a closed set. The raw
/// `rootfs_flavor` slug is user-authored once OCI import is in play, so it
/// never becomes an attribute; this enum is what may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlavorKind {
    /// An isopod-built flavor or base image.
    Built,
    /// An imported OCI image (`oci:<name>` — the name itself stays local).
    Imported,
    /// A committed stage chain (one or more layers over a base).
    Stage,
}

impl FlavorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            FlavorKind::Built => "built",
            FlavorKind::Imported => "imported",
            FlavorKind::Stage => "stage",
        }
    }
}

/// A span attribute isopod is willing to record. Sealed: every variant is
/// host-minted and either exact-safe (durations of host-shaped phases, closed
/// enums, resource counts) or pre-bucketed ([`Attr::Bucket`]).
pub(crate) enum Attr<'a> {
    /// An exact duration in milliseconds, host-measured.
    Ms(&'static str, u64),
    /// A boolean flag (e.g. `isopod.exit_zero` — the collapse of `exit_code`).
    Flag(&'static str, bool),
    /// A log2 bucket index, never the exact magnitude. See [`log2_bucket`].
    Bucket(&'static str, u32),
    /// A small host-validated count (vCPUs, MiB, chain depth).
    Count(&'static str, u64),
    /// A compile-time string from a closed set (e.g. `isopod.disk.kind`).
    Static(&'static str, &'static str),
    /// Which boot path served the run (`warm` / `cold`).
    Path(crate::vm::RunPath),
    /// The normalized flavor kind (`built` / `imported` / `stage`).
    FlavorKind(FlavorKind),
    /// The claimed network slot index.
    Slot(usize),
    /// The host-minted random `dev-<8 hex>` VM id — the correlation key.
    VmId(&'a str),
}

/// Record `attrs` on `span`. The span must have declared each field name with
/// `tracing::field::Empty` at creation, or the record is silently dropped —
/// which is the correct failure mode for telemetry.
pub(crate) fn record(span: &tracing::Span, attrs: &[Attr<'_>]) {
    for attr in attrs {
        match attr {
            Attr::Ms(key, v) => span.record(*key, *v),
            Attr::Flag(key, v) => span.record(*key, *v),
            Attr::Bucket(key, v) => span.record(*key, *v),
            Attr::Count(key, v) => span.record(*key, *v),
            Attr::Static(key, v) => span.record(*key, *v),
            Attr::Path(p) => span.record(
                "isopod.run.path",
                match p {
                    crate::vm::RunPath::Warm => "warm",
                    crate::vm::RunPath::Cold => "cold",
                },
            ),
            Attr::FlavorKind(k) => span.record("isopod.flavor.kind", k.as_str()),
            Attr::Slot(s) => span.record("isopod.net.slot", *s as u64),
            Attr::VmId(id) => span.record("isopod.vm_id", *id),
        };
    }
}

/// The log2 bucket index for a magnitude: 0 for 0, else `floor(log2(n)) + 1`.
/// Bucket 11 means `n ∈ [1024, 2048)`. Coarse on purpose: the index is what a
/// guest-influenced magnitude is allowed to disclose.
pub(crate) fn log2_bucket(n: u64) -> u32 {
    u64::BITS - n.leading_zeros()
}

/// The in-flight cold-boot measurement: the span to parent `kernel_wait` under
/// and the instant the `InstanceStart` request was issued. Carried from the
/// boot to the readiness wait so `boot_ms` ends at the first successful ping.
pub(crate) struct BootWait {
    pub(crate) span: tracing::Span,
    pub(crate) started: Instant,
}

/// Emit the synthesized guest-exec marker span. The guest reports only a
/// monotonic interval (`duration_ms` in `ExecDone`); its wall clock is never
/// trusted. Bare `tracing` cannot backdate a span's start, so locally this is
/// a zero-width span carrying the interval as an exact attribute — an export
/// layer with an explicit-timestamp builder would end-anchor it instead.
/// The number inherits `ExecDone`'s known conflation of compute with vsock
/// output streaming; a clean split needs additive proto fields.
pub(crate) fn guest_exec_marker(duration_ms: u64) {
    let span = tracing::debug_span!(
        target: TARGET,
        "isopod.guest.exec",
        isopod.exec.duration_ms = duration_ms,
    );
    drop(span.entered());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log2_bucket_is_zero_only_for_zero_and_splits_powers_of_two() {
        assert_eq!(log2_bucket(0), 0);
        assert_eq!(log2_bucket(1), 1);
        assert_eq!(log2_bucket(2), 2);
        assert_eq!(log2_bucket(3), 2);
        assert_eq!(log2_bucket(1023), 10);
        assert_eq!(log2_bucket(1024), 11);
        assert_eq!(log2_bucket(u64::MAX), 64);
    }
}
