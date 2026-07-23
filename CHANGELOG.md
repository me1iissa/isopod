# Changelog

All notable changes to isopod. The format follows
[Keep a Changelog](https://keepachangelog.com/) loosely; versions follow
[Semantic Versioning](https://semver.org/) with pre-1.0 semantics (minor =
features or breaking changes, patch = fixes). See CONTRIBUTING.md §
Versioning for the policy.

## [0.7.2] — 2026-07-23

- Formatting fixup missed from the 0.7.1 commit (whitespace only).

## [0.7.1] — 2026-07-23

- **CI**: GitHub Actions workflow — build, `cargo fmt --check`, clippy
  (`-D warnings`), full test suite, plus a `version-guard` job that enforces
  the versioning policy on every PR and push.
- Lint cleanup (clippy `manual_is_multiple_of`, `large_enum_variant`).

## [0.7.0] — 2026-07-23

The post-v1 hardening and findings-fix wave; adopts the versioning policy
(versions 0.2.0–0.6.0 below were tagged retroactively at their milestone-close
commits).

- **Breaking**: host↔guest RPC protocol v3 — guest hostname support, streamed
  `copy_out`, richer base metadata, protocol-stamped images with a pre-boot
  guard (`image ls` shows staleness; `image build-all` rebuilds coherently).
- **Security hardening**:
  - Guest egress restricted to public destinations by default (RFC1918 /
    CGNAT / link-local dropped, per-tap anti-spoofing, IPv6 deny);
    `setup --allow-lan-egress` opts out.
  - Opt-in rootless microjail (`ISOPOD_JAIL=1`): user/pid namespaces, minimal
    chroot, per-VM cgroup caps. Fails closed on missing prerequisites.
  - Every guest-controlled host sink bounded: exec logs capped per stream,
    serial sinks capped, all agent RPCs time-bounded, run budgets capped.
  - Guest kernel pinned by exact artifact and sha256, verified on fetch and
    on cached reuse.
- **Features**: `stdin_file` (big payloads without transiting model context),
  `--copy-out`/`copy_out` artifact extraction, run observability
  (`path`/`resume_ms`/`snapshot_built`/`commit_ms`), MCP auto-GC of VM
  records, guest hostname = vanity name.
- **Fixes**: overlay chain depth off-by-one at max depth; degraded overlay
  root now loudly fatal instead of silent; pre-boot env-var validation;
  clear error naming the failing subject on exec spawn failures; `--base`
  without `--stage` is a hard error.

## [0.6.0] — 2026-07-22

- **M5.5 + M6**: flexible per-VM resources (`vcpus`, `mem_mib`, host-capped
  with clear errors) and the warm pool — full-VM snapshot save/resume with
  post-resume network/clock reconfiguration over vsock (`warmpool
  build`/`list`/`rm`), transparent resume for eligible runs.

## [0.5.0] — 2026-07-21

- **M5**: MCP server (`isopod-mcp`, rmcp 2.2 stdio) exposing
  `sandbox_run` and the stage/VM tools; workflow skill; Claude Code plugin
  packaging; stdin plumbing.

## [0.4.0] — 2026-07-21

- **M4**: networking — one-time `sudo isopod setup` provisioning user-owned
  tap slots + nftables NAT, `--no-network`, orphaned-VMM reaping, the
  `base-alpine` toolchain image.

## [0.3.0] — 2026-07-21

- **M3**: stages — squashfs base + overlay chains, content-addressed
  commit/fork/stack store, `stage list/info/rm`, `vm ls/gc`, vanity names.

## [0.2.0] — 2026-07-21

- **M2**: exec — `isopod-proto` host↔guest RPC contract, musl PID-1 guest
  agent, `isopod run` end to end over vsock.

## [0.1.0] — 2026-07-21

- **M0/M1**: feasibility spike; cargo workspace; typed `isopod-fc`
  Firecracker client; guest-image pipeline; vendored Firecracker v1.16.1
  built from source; dev boot path.
