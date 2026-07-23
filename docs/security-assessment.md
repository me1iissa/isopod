# isopod — Sandbox Breakout Security Assessment

> Pre-publication assessment (2026-07-22). Scope: **can code running inside an
> isopod guest microVM escape to, or harm, the host or other guests?** Method:
> live breakout attempts against real sandboxes on this host **+** a multi-agent
> adversarial static review (25 agents, ~1.6M tokens) of every host-side code
> path that ingests guest-controlled data, with each finding independently
> verified or refuted. Findings are ranked by host impact; file:line references
> are to the tree at the time of assessment. Environment-specific values (host
> LAN IP, etc.) are this host's; the *classes* of finding are general.

## Threat model & isolation boundary

Inside a guest, untrusted code runs as **uid 0 (root), with all 41 capabilities,
no in-guest seccomp, and a full devtmpfs** (`/dev/mem`, `/dev/vda`, `/dev/loop*`,
`/dev/kmsg`, …). **This is by design** — the guest is expendable and fully owned.
The security boundary is therefore *not* inside the guest; it is:

1. the **Firecracker VMM + KVM** (hardware virtualization),
2. the **host-side code that ingests guest-controlled bytes** (the vsock RPC
   responses, the committed ext4 image, exec/serial output), and
3. **networking** (the tap/nftables fabric).

A finding only matters if it reaches one of: host code-execution, host file
read/write outside the VM, host denial-of-service, or cross-contamination of
another guest or the shared stage/snapshot store.

## Verdict

**No guest→host escape or guest→guest breach was found**, by either live testing
or static review. The load-bearing control is correctly configured: Firecracker
runs unprivileged with its seccomp BPF filter on and all capabilities dropped.
The confirmed issues are **denial-of-service, lateral-movement, and hardening**
gaps — not escapes.

**Safe to publish the source** (it is honest about the v1/v2 split), provided the
README/security notes state the posture plainly and the must-fix items are
tracked. Do **not** run genuinely hostile or multi-tenant workloads until the
egress restriction (F1), the unbounded-log DoS (F3), and the jailer (F2) land.

## What holds (verified secure)

| # | Property | How verified |
|---|----------|--------------|
| S1 | **VMM hardened**: live `firecracker` runs as uid 1000, `CapEff=0` (all caps dropped), `NoNewPrivs=1`, `Seccomp=2` (BPF filter **on**). No `--no-seccomp`/`--seccomp` override. | `/proc/<fc>/status`; `process.rs` |
| S2 | **Guest→host blocked** on all tested ports (22/80/8080/111/445/3389) and ICMP, to both the tap gateway and the host WAN IP. | live probe |
| S3 | **Guest→guest blocked**, incl. **two concurrent live guests** (slot-1 prober could not reach a live slot-0 listener; all cross-guest connects timed out). | live: two concurrent VMs |
| S4 | **`--no-network` airtight**: no NIC, all egress fails; exec still works over vsock. | live |
| S5 | **No host FS exposure**: base image read-only at the VMM (`/sys/block/vda/ro=1`); no 9p/virtiofs/host mount in the guest; FC holds no writable host-FS handles. | live + `/proc/<fc>/fd` |
| S6 | **No guest→host control channel**: guest AF_VSOCK to the host (CID 2) is reset; MMDS not configured/reachable. | live |
| S7 | **Resource requests bounded pre-boot**: over-cap `mem_mib`/`vcpus` rejected cleanly, no boot, no host OOM. | live |
| S8 | **Naming/commit injection-safe**: `commit_as` labels with traversal / `$(…)` / backticks / `--flags` produced content-addressed `st-<hex>` ids + `[a-z0-9-]` names; the label is stored as pure metadata; **no host artifact created**. | live + `names.rs`/`stage.rs` |
| S9 | **Commit never parses guest filesystems on the host**: the guest ext4 is `cp --sparse`-copied and BLAKE3 content-addressed; the host never `mount`s / `resize2fs` / `e2fsck`s it. (Independently re-verified; the "malicious stage attacks host tooling" hypothesis was **refuted**.) | static (`stage.rs`) |

## Findings (ranked by host impact)

### F1 — Unrestricted egress to the host's private network — HIGH

The forward rule (`net/setup.rs:244`) accepts **any** tap-sourced packet routed
out the WAN, with **no destination filter**, and the NAT masquerade covers the
whole `10.107.0.0/16` supernet. A guest therefore reaches **anything the host can
route to**, not just the public internet. Live: from a guest, the host's LAN
gateway (an RFC1918 address) answered on 22/53/80/443 and was pingable; public egress
and DNS worked normally. Independently confirmed by static review (HIGH).

Two related weaknesses in the same ruleset:
- **Source spoofing**: the egress accept matches `iifname` only while the
  masquerade is gated on `ip saddr 10.107.0.0/16`, so a guest that spoofs a
  source **outside** its supernet is forwarded out `eth0` with the spoofed source
  **un-rewritten** — it can inject spoofed-source packets onto the LAN/WAN.
- **IPv6** is only latently contained: the `inet` forward chain would accept
  un-NATed v6 `tap→wan` if v6 forwarding were ever enabled.

- **Impact**: untrusted/agent code can port-scan and reach the host's RFC1918
  LAN (router admin, internal services, other machines) and — on a cloud host
  (unlike this WSL box) — `169.254.169.254` metadata. Lateral movement / SSRF /
  exfiltration.
- **Fix**: before the egress accept, drop private/link-local destinations for
  tap-sourced forwards —
  `iifname "isopod-tap*" ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 } drop`
  (plus the IPv6 equivalent) — i.e. **public-only egress**, or an explicit
  allowlist. Add a per-tap anti-spoof drop (`iifname "isopod-tapN" ip saddr != 10.107.N.2 drop`)
  or gate the egress accept on `ip saddr 10.107.0.0/16`. Add a v6 default-deny
  for tap-sourced forwarding unless v6 egress is a supported feature. Keep
  `--no-network` for the untrusted case.

### F2 — No second isolation layer (no jailer) in v1 — MEDIUM

Firecracker is **not** run under the jailer. The live process shares the host's
root `net`/`mnt`/`pid`/`user`/`cgroup` namespaces and is **not chrooted**
(`root=/`); `FcProcess::spawn` (`process.rs:223`) sets no `setrlimit`/cgroup. Its
only defenses are its own seccomp filter and dropped capabilities.

- **Impact**: isolation rests entirely on Firecracker's seccomp + KVM with **no
  defense in depth**. A hypothetical Firecracker/KVM escape would land as the
  full invoking-user account — the whole home directory, all of `~/.isopod` (every
  tenant's stages/snapshots/logs), and a `sudo`-capable user. E2B/Fly run the
  jailer specifically to contain a VMM compromise.
- **Fix**: ship the jailer (v2 backlog): chroot + dedicated uid + `net`/`pid`/
  `mnt` namespaces + cgroup v2 caps (pass `--cgroup-version 2` on this host).
  Until then, document that v1 is single-layer and single-tenant.

### F3 — Unbounded host-disk / host-RAM DoS via exec + serial log tees — HIGH

Guest exec stdout/stderr is teed **1:1** to `~/.isopod/vms/<id>/exec-*.log` with
**no size cap** (`StreamSink::write`, `agent.rs:577`; `self.total` is counted but
never checked). The guest **serial console** is a second, independent unbounded
sink teed to `console.log` (`vm/console.rs`, `drain_to_log`). VM directories and
logs are explicitly retained ("keep every log regardless", `vm/mod.rs:1031`).
Live: 50 MiB of guest stdout produced a 52,428,868-byte host file. Three
amplifiers found by static review:
- **Host OOM on timeout**: the host-wall-timeout path (`capture_from_log`,
  `vm/mod.rs:~1703`) does `tokio::fs::read(whole_log)` into a single `Vec<u8>`
  *before* truncating — a guest that streams a multi-GB log and never sends
  `ExecDone` forces the whole file into host RAM.
- **`timeout_s` is not upper-clamped** (CLI/MCP), so one run can stream to disk
  for an arbitrarily long window.
- The host **never re-enforces `EXEC_CHUNK_LEN`** (32 KiB) — only the 8 MiB
  `MAX_FRAME_LEN` — so a malicious guest agent can send 8 MiB frames to maximize
  fill throughput.

- **Impact**: a single untrusted run (even `cat /dev/zero`) fills the host disk;
  a malicious/hung agent additionally triggers host OOM. Filling `~/.isopod`
  breaks the host and every other sandbox/stage/snapshot — cross-tenant DoS.
- **Fix**: enforce a per-stream on-disk byte ceiling in `StreamSink` and in the
  console drainer (stop teeing past the cap, mark truncated); never `fs::read`
  the whole log back — read only a bounded head; clamp `timeout_s`; add
  log retention/auto-gc; ideally a cgroup disk limit (F2).
- **CLOSED (2026-07-23)**: `StreamSink` now caps each exec log at 64 MiB
  (`EXEC_LOG_CAP`; bytes beyond the cap are counted but not persisted, marker
  line in the log); all three serial sinks (`drain_to_log`, `drain_serial`, and
  the previously uncapped `tokio::io::copy` on the snapshot resume path) cap at
  16 MiB while still draining the pipe; `drain_serial` also bounds its line
  buffer (64 KiB) against newline-free floods; `capture_from_log` reads only the
  inline head + stats the size (no whole-file read); `timeout_s` is hard-bounded
  to `1..=3600` in `run_ephemeral` (shared CLI/MCP choke point); the host
  re-enforces `EXEC_CHUNK_LEN` on exec and copy-out chunks and enforces the
  copy-out `max_bytes` ceiling host-side (the guest's word is no longer
  trusted). Live-verified: a 100 MB guest spray produced a 67,108,935-byte log
  (64 MiB + marker) with exact totals in the report; out-of-range `timeout_s`
  errors before any VM work. Log retention/auto-gc and the global disk cgroup
  remain follow-ups (F2/F4 scope).

### F4 — Host memory-exhaustion DoS via concurrent sandboxes — MEDIUM

`resources.rs` validates each VM's `mem_mib` against static **`MemTotal`** (minus
512 MiB headroom, hard-capped 4096) with **no accounting of running VMs** and no
global governor. With 8 slots, up to 8 concurrent VMs × up to 4096 MiB (= 32 GiB)
can be requested against a 5.9 GiB host.

- **Impact**: concurrent sandboxes over-commit host RAM → OOM. (The session
  handover already noted memory pressure likely killing a co-running agent.)
- **Fix**: check `MemAvailable` at slot-claim time, and/or a global running-VM
  memory budget, and/or cgroup memory caps (via the jailer, F2).

### F5 — No I/O or network rate limiters (claimed but not implemented) — LOW–MEDIUM

`PLAN.md` "Security posture" lists "per-drive/NIC token-bucket rate limiters as
throttles," but every drive (`Drive::virtio` hard-codes `rate_limiter: None`,
`models.rs:173`) and NIC (`rx/tx_rate_limiter: None`, `vm/mod.rs:543`) is
unthrottled. The types exist; nothing sets them.

- **Impact**: a guest can saturate host disk IO and network uplink, compounding
  F1/F3/F4; also a doc/reality mismatch to fix before publishing.
- **Fix**: attach a default token-bucket `RateLimiter` to the scratch/base drives
  and both NIC directions, or amend the PLAN claim.

### F6 — Lax permissions on host artifacts — LOW–MEDIUM (deployment-dependent)

`~/.isopod/vms/<id>` is created world-traversable `0755` (`paths.rs`) and logs
(`exec-*.log`, `console.log`, `firecracker.log`) and snapshot files inherit the
default umask (`0644`). The per-VM directory holding the **Firecracker API socket
and the vsock UDS** is not `0700` and the sockets are not `0600`, so their
reachability by another local user depends on ambient umask (`vm/mod.rs:~954`).

- **Impact**: on a shared/multi-user host, another local user can read all
  sandbox I/O — including **exec/serial logs that contain untrusted workload
  output** — and potentially reach a live VM's control socket. (Moot on a
  single-user box; warm-pool *snapshots* themselves predate untrusted code, so
  the memfile carries no workload secrets — that specific "world-readable RAM"
  angle was **refuted** as a win condition. The logs are the real exposure.)
- **Fix**: create `~/.isopod` and per-VM dirs `0700`, write artifacts `0600`,
  chmod the API/vsock sockets `0600` after bind.

### F7 — Untrusted guest output reaches the orchestrating agent verbatim — LOW (agentic-sandbox-specific)

Exec stdout/stderr (head-capped 64 KiB, `mcp/main.rs:164`) and stored `commit_as`
labels are returned verbatim to the driving agent (Claude) via MCP. Not a host
escape, but a guest can emit crafted text attempting **prompt injection** of the
orchestrator — precisely what the sandbox exists to contain.

- **Fix**: wrap returned guest output in a hard-to-spoof untrusted-content
  envelope (e.g. a random per-call fence token, or a structured
  `untrusted_output` field the client is told never to interpret as
  instructions).

### F8 — Slot/VM leak via unbounded host-side vsock reads — MEDIUM

Neither `read_frame` variant applies a read/idle timeout (`proto/frame.rs:81`):
`read_exact(...).await` blocks forever if the peer completes the vsock CONNECT
handshake then withholds bytes. The post-exec teardown awaits `halt` **without a
timeout** (`let _ = vm.agent.halt(true).await;`, `vm/mod.rs:1619`), and the run
has no outer deadline.

- **Impact**: a malicious guest that runs its own vsock listener on port 52 (it
  is root; it can kill the real agent) accepts the host's `halt` connection and
  stalls. The teardown hangs, so the `net_slot` and `FcProcess` drop-guards never
  fire — the network slot and the Firecracker process **leak permanently**.
  Repeat 8× (one per slot) to exhaust the pool → no further networked sandboxes
  can start (persistent DoS).
- **Fix**: wrap every host-side vsock read (or each `AgentClient` op) in a bounded
  `tokio::time::timeout`, and/or wrap the whole run in an outer deadline that
  drops the future so the drop-guards fire (and reap the FC process on timeout).
- **CLOSED (2026-07-23)**: every `AgentClient` op is now time-bounded — control
  RPCs (ping/clock/net/hostname/put/get/**halt**, and the vsock CONNECT
  handshake itself) get a 10 s wall (`CONTROL_RPC_TIMEOUT`); `copy_out` gets a
  30 s per-frame idle bound (`STREAM_IDLE_TIMEOUT`) so large transfers stay
  legal but a wedged guest cannot stall teardown; `exec` reads remain bounded by
  the caller's existing wall clock (documented contract). A stalling guest now
  surfaces as `AgentError::Timeout`, teardown proceeds to the forced VMM
  shutdown, and the slot/process drop-guards fire — no leak. Covered by
  paused-clock unit tests (stalled ping and stalled halt both time out; over-
  ceiling copy-out fails and removes the partial file).

### F9 — Guest-kernel supply chain: checksum recorded but never verified — LOW

`fetch_kernel` (`image/kernel.rs`) downloads the CI `vmlinux` from S3 and computes
its SHA-256 only to **report** it (`FetchKernelOutcome.sha256`) — there is **no
`got != expected` comparison**, asymmetric with the SHA-256-**pinned** busybox/apk
artifacts. Image fetches (S3, Alpine CDN) use default reqwest cert validation with
no pinning.

- **Impact**: a CA-level MITM or an S3/CDN tamper could swap the **guest kernel**
  (the most privileged guest component) or rootfs, undetected. Build-time /
  supply-chain, not a runtime guest escape.
- **Fix**: pin the kernel to an allow-list of known-good `(series → sha256)`
  digests (or a signed manifest) and fail the download on mismatch, matching the
  other artifacts.
- **CLOSED (2026-07-23)**: the kernel is now pinned by exact artifact
  (CI prefix + version + sha256) — the CI bucket rebuilds the same kernel
  version per date-stamped prefix with different bytes, so a version-only pin
  would not identify the artifact. The default fetch (including the boot-path
  auto-fetch) downloads the pinned artifact directly (no prefix enumeration),
  verifies the digest **before** the atomic rename (bad bytes never land where
  the boot resolver looks), and verifies the cached copy on reuse; the newest-
  first enumeration survives only behind `--allow-unpinned` (loud warning,
  `pinned:false` in the report) as the pin-bump discovery path. The pinned
  digest was anchored by an independent re-fetch from S3 matching the deployed
  kernel byte-for-byte. Live-verified: tampered cache refused, unpinned series
  fail-closed, forced re-download fetch-verifies. TLS/cert pinning for the S3
  and Alpine CDN endpoints remains open (LOW residual).

## Verified robustness / hardening gaps (INFO–LOW)

Confirmed real by static review; low host impact today, worth tracking:

- **Snapshot cache key** (`snapshot.rs:80`) omits a base-image *content* hash and
  the kernel `BOOT_ARGS`; an in-place base rebuild (same slug) or a cmdline change
  could resume a stale snapshot. Fold a content hash + BOOT_ARGS into the key.
- **Orphan reaper** (`vm/registry.rs:123`) decides liveness by bare `/proc/<pid>`
  existence — PID-reuse racy; can wedge a slot or mis-signal a same-user process.
  Add a start-time/boot-id check.
- **Name assignment** (vanity + stage names) does read-all → pick-unique → write
  with no lock; N concurrent sessions can collide. Serialize under the store lock.
- **Snapshot resume** performs no integrity check on `vmstate`/`memfile` (only
  matters post-host-compromise, since writing them needs host FS access).
- **serde on the shared store** (`meta.json`, `VmRecord`) reads with no size
  bound; relevant only if the store is shared across trust boundaries.
- **`--keep`** leaves guest-authored `scratch.ext4`/rootfs copies indefinitely →
  unbounded `~/.isopod` growth.

## Considered and dismissed (refuted on verification)

These plausible-looking hypotheses were checked against the code and found **not**
to be host risks — recorded so they aren't re-raised:

- *Malicious committed stage ext4 attacks host tooling* — refuted: the host only
  `cp --sparse` + BLAKE3s the image; it never mounts/fscks it.
- *Overlay lowers omit `nodev`/`nosuid`/`noexec`* and *full devtmpfs + no in-guest
  seccomp* — real code facts, but **no win condition** under the current
  fully-root guest model (a forker's guest is already omnipotent inside its VM);
  defense-in-depth only.
- *World-readable snapshot memfile leaks secrets* — the memfile is a pristine
  pre-untrusted-code idle VM; no workload secrets. (The workload **logs** are the
  real perms concern — see F6.)
- *Concurrent same-key warm-snapshot builds publish a torn snapshot* — races
  exist but self-heal (a bad resume falls back to cold boot).
- *Host paths/username leak to the agent context* — they are the operator's own
  paths; negligible.

## Before publishing — checklist

**Must state in the README/security notes (no code change required):**
- v1 is **single-layer isolation** (Firecracker seccomp + KVM only; no jailer),
  intended for **single-tenant** use. (F2)
- Networked guests reach the **host's whole routable network**; use
  `--no-network` for untrusted code until egress is restricted. (F1)

**Should fix before hostile/multi-tenant use:**
- F1 egress restriction + anti-spoof + v6 default-deny.
- F3 exec/console log byte caps + bounded timeout read-back + `timeout_s` clamp.
- F8 vsock read timeouts / outer run deadline (slot-leak DoS).
- F2 jailer; F4 concurrent-VM memory governor.

**Nice to have:** F5 rate limiters (or correct the claim), F6 artifact/socket
perms, F7 output fencing, F9 kernel checksum pinning, and the robustness list.

## Appendix — how this was tested

- **Live VMM inspection**: caught the running `firecracker` PID and read
  `/proc/<pid>/{status,fd,ns,limits}` (uid/caps/seccomp/namespaces/open files).
- **Live network probes**: TCP/ICMP from guests against the host tap gateway,
  host WAN IP, other slots' taps/guests, the RFC1918 gateway, `169.254.169.254`,
  and the public internet; `--no-network` egress; a two-concurrent-guest
  listener/prober isolation test (slots 0 and 1).
- **Live breakout attempts**: guest→host vsock; base-drive write protection;
  host-FS-share enumeration; MMDS; over-cap resource requests; `commit_as`
  path-traversal / command-substitution / argument-injection.
- **Static review (adversarial, 25 agents)**: vsock RPC + framing; stage store
  commit/fork/gc + naming; snapshot/warm-pool; FC process/VMM config + lifecycle;
  nftables ruleset; guest boot/overlay assembly; MCP/CLI surface; image-fetch
  supply chain. Each finding was independently verified or refuted; 11 confirmed,
  6 refuted.
