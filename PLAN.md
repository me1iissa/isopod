# isopod — Firecracker-based agentic sandbox for Claude Code

> Status: FINAL PLAN (2026-07-21). Research-backed; all ⏳ items resolved.
> Sources: Firecracker v1.16.1 docs/swagger, E2B infra, CodeSandbox engineering blogs,
> Fly.io init-snapshot, rmcp 2.2, Claude Code plugin docs, plus local verification of this host.

## Context

Claude Code needs somewhere fast and safe to run commands, build code, and execute untrusted or
experimental workloads. Containers are heavy to set up, slow to tear down cleanly, and share the
host kernel. AWS Firecracker microVMs give hardware isolation with ≤125 ms cold boots (spec
commitment, minimal kernel) and single-digit-ms snapshot restores — the right fit for a
"one action, one sandbox" agent cadence.

**isopod** is an agentic sandbox system on Firecracker with one central idea:

- **Sandboxes are ephemeral.** A microVM exists for one action/context, then dies.
- **Stages are persistent.** A sandbox can leave behind a *stage* — a small copy-on-write disk
  layer capturing exactly what it changed. Later sandboxes **fork** from a stage (start on top of
  it — the stage is never mutated) or **stack** (commit a new layer on top). Stages are small,
  portable files; nothing else survives a VM.
- Claude Code drives it through an **MCP server** plus a companion **skill** teaching usage patterns.

## Decisions (locked)

| Decision | Choice | Basis |
|---|---|---|
| Language | Rust end-to-end | user choice |
| FC SDK | **Hand-roll `isopod-fc`** (~1–2k lines), publishable later | every 3rd-party crate is dead or bus-factor-1 alpha (fctools); API is only 26 paths / 38 ops; production users all hand-roll |
| Firecracker | **v1.16.1, built from vendored source** (fork-ready; stock/unpatched for v1) | current stable; fixes CVE-2026-5747 + post-restore vsock timeouts; FC is Rust, so an in-tree build costs little and enables patching when needed |
| Stage mechanism | **Guest-side overlayfs over stacked raw ext4 drives** | only mechanism that is root-free, snapshot-compatible, and yields small portable per-stage files; dm-thin/dm-snapshot/reflink all rejected (root, non-portable, or ext4-host) |
| Memory snapshots | Warm-pool **cache only**, never the durable artifact | FC snapshots are version/kernel/CPU-fragile by design |
| Guest image | Alpine + python3/nodejs/git/gcc, squashfs base | user choice |
| Guest kernel | Custom vmlinux from FC's `microvm-kernel-ci-x86_64-6.18.config` + overlayfs/squashfs/vsock | 6.1 guest support ends 2026-09-02; 6.18 is the go-forward validated config |
| Host↔guest RPC | **vsock** (FC hybrid vsock = plain unix socket on host) | works with networking disabled (unlike E2B's TAP-based envd); no host vhost dependency |
| Networking | Per-VM netns slots, **identical guest IP in every VM**, nftables NAT | the E2B/CodeSandbox trick that lets one snapshot restore as N concurrent forks with zero guest reconfig |
| MCP SDK | **rmcp 2.2** (official Rust SDK), stdio transport | mature: #[tool] macros, schemars structured output, progress notifications |

## Host environment (verified locally 2026-07-21)

WSL2 kernel `6.6.114.1-microsoft-standard-WSL2`, Ubuntu 24.04.4, systemd PID 1, pure cgroup v2.
`/dev/kvm` OK (user in `kvm` group, nested=Y), `tun` loaded, full `/lib/modules` tree present
(the "WSL2 has no modules" folklore is obsolete). `OVERLAY_FS=y`, `SQUASHFS=y`, `LOOP=y`,
`USERFAULTFD=y`, `VSOCKETS=y`, dm-thin/dm-snapshot/nbd/erofs `.ko` present. 4 vCPU / 5.8 GiB RAM
/ 8 GiB swap / 781 GB free ext4-on-VHDX.

### Known risks (all have mitigations, one needs a spike FIRST)

1. ~~🔴 `networkingMode=mirrored` may drop kernel-forwarded packets (microsoft/WSL#10842)~~ —
   **RESOLVED 2026-07-21 by M0 spike: NAT egress WORKS under mirrored mode on this host**
   (netns→MASQUERADE→eth0 verified end-to-end incl. DNS + HTTPS; see docs/feasibility.md).
   No `.wslconfig` change; planned NAT design proceeds unchanged.
2. No passwordless sudo — all privileged provisioning is concentrated in one explicit
   `sudo isopod setup` step (tap/netns slot pool, sysctl `ip_forward` persisted via
   /etc/sysctl.d, nftables rules). Runtime never needs root.
3. WSL2 utility VM auto-terminates when the last session exits — prewarmed VMs die with it.
   v1: warm pool is a lazy cache (rebuilt on demand, losing it costs one cold boot). Later:
   systemd user service + `vmIdleTimeout` guidance.
4. Host kernel 6.6 is not in FC's CI-validated set (5.10/6.1/6.18) — expected to work; M0
   smoke-tests boot AND snapshot-restore specifically before we build on them.
5. 5.8 GiB RAM cap — default guests 256–512 MiB; snapshot memfiles are RAM-sized (page cache
   counts against the cap; consider `.wslconfig autoMemoryReclaim=gradual`).
6. WSL2 clock skews after Windows sleep, and every snapshot resume has a stale guest clock —
   guest agent resyncs time on every boot/resume (host time pushed over vsock; VMClock later).
7. `/dev/userfaultfd` is 0600 root — irrelevant for v1 (plain mmap'd File-backend restore needs
   nothing); only matters if/when UFFD lazy restore is added.

## Architecture

```
Claude Code ── stdio (rmcp) ──> isopod mcp        ─┐
Human / CI  ── argv + JSON  ──> isopod <subcmd>   ─┤  same binary, same core
                                                   ▼
                              isopod-core (lib)
                              ├─ vm.rs        lifecycle: spawn FC, configure via API, reap
                              ├─ stage.rs     stage store: commit / fork / stack / flatten / gc
                              ├─ snapshot.rs  warm-pool: full-snapshot save/restore, invalidation
                              ├─ net.rs       netns slot pool claim/release
                              ├─ agent.rs     vsock RPC client (exec/files), reconnect-per-request
                              └─ store.rs     ~/.isopod on-disk state, file-locked (N sessions)
                                     │
                              isopod-fc (crate: typed FC client, candidate standalone SDK)
                                     │ HTTP/JSON over per-VM unix socket
                              firecracker v1.16.1 (one process per VM, in a netns slot)
                                     │ virtio-blk×N   hybrid vsock (host UDS)   virtio-net(tap)
                              ┌──────┴───────────────────────────────────────────┐
                              │ guest: custom vmlinux (6.18 microvm config)      │
                              │ isopod-guest-agent = PID 1 (static musl)         │
                              │   mounts overlay(base+stages+scratch), pivots,   │
                              │   serves exec/file RPC on vsock, resyncs clock   │
                              └──────────────────────────────────────────────────┘
```

### Cargo workspace

```
isopod/
├── Cargo.toml                # workspace; pin rmcp = "2.2", FC version const = 1.16.1
├── crates/
│   ├── fc-client/            # isopod-fc — see below
│   ├── core/                 # orchestrator library (all logic lives here)
│   ├── guest-agent/          # x86_64-unknown-linux-musl static bin; PID 1 in guest
│   ├── proto/                # shared host↔guest RPC types (serde)
│   └── cli/                  # `isopod` binary: run/exec/start/stop/stage/image/setup/mcp/doctor
├── images/                   # kernel .config (checked in), rootfs build driven by `isopod image`
├── skill/                    # SKILL.md (+ later .claude-plugin/ packaging)
├── docs/feasibility.md       # M0 spike results (latency numbers, mirrored-mode outcome)
└── PLAN.md
```

Everything is **one-shot argv + JSON + state-on-disk** (no REPLs, no persistent stdin), so CLI,
MCP, humans, and CI all drive the same core. The MCP server is a thin stateless shim — Claude
Code spawns one per session and never restarts crashed stdio servers, so all registry/stage/pool
state lives under `~/.isopod` with file locking.

## isopod-fc (the "own SDK" crate)

Hand-rolled, pinned to the v1.16.1 swagger (Swagger 2.0; codegen rejected — progenitor needs
OpenAPI 3, openapi-generator can't target unix sockets cleanly, and 38 ops / ~25 needed models
is days of work by hand):

- serde models + typed client over **reqwest `ClientBuilder::unix_socket()`** (one Client per VM
  — a shared client would silently talk to the wrong VM).
- Type-level encoding of **pre-boot vs post-boot** phases (the swagger doesn't express that
  `PUT /drives` is pre-boot only while `PATCH /drives/{id}` is post-boot media-change — a typed
  state machine prevents confusing 400s).
- Endpoints: machine-config, boot-source, drives (PUT/PATCH), network-interfaces, vsock, mmds,
  actions (InstanceStart/CtrlAltDel), vm pause/resume, snapshot create/load (incl.
  `network_overrides`, `vsock_override`, `resume_vm`), balloon, version.
- `tokio::process` supervision: `kill_on_drop(true)`, process groups, spawn-in-netns.
- ~50-line hybrid-vsock helper (host side is a UDS: `CONNECT <port>\n` → `OK <hostport>\n` → raw stream).
- Mine fctools for design ideas (executor layering); take no dependency on it.
- The vendored FC source tree doubles as the authoritative spec: resolve API ambiguities (e.g.
  pre/post-boot semantics) by reading the handler code, not by trial-and-error against the swagger.

## Extending Firecracker itself (we build from source, so we can)

FC is vendored as a git submodule pinned at the `v1.16.1` tag and built by our pipeline (M1+;
M0's spike uses the release binary for speed). **v1 carries zero patches** — everything v1 needs
is stock, and unpatched guest-facing code keeps upstream's audit value. Patch policy when the
time comes:

- **Upstream-first**: anything generally useful goes up as a PR; the carried patch set stays
  minimal and gets rebased every upstream minor (~3-month cadence; CVE fixes rebased promptly).
- **Snapshot cache keys use the FC build hash** (tag + patch-set), not just the version — a
  patched binary is its own snapshot-compatibility domain.
- Guest-facing patches (block/memory/device emulation) are attack surface — they get tests and
  fuzzing before untrusted workloads run on them.

Concrete options this unlocks (all backlog, none v1):

1. **In-VMM layered block backend (the preferred v3 storage endgame)** — teach virtio-blk to
   read through a content-addressed stage-chain manifest in-process. Strictly better than the
   E2B-style external NBD server (no root for `/dev/nbdX`, no extra process to crash, and stays
   snapshot-compatible where vhost-user cannot).
2. **`MAP_SHARED` guest memory + live fork** (CodeSandbox's patch): dirty pages sync to the
   backing file continuously → near-free snapshots and sub-2s clones of *running* VMs. Only if
   fork-from-paused-snapshot (95% of the value, zero patch risk) proves insufficient.
3. **Widened MMIO slot count** if stage-chain depth ever binds before `stage flatten` is
   convenient (stock cap ≈19 devices ⇒ ~10–14 layers).

## Stage model (core mechanism)

**Drive topology per VM** (all attached pre-boot; hotplug is still dev-preview):

| Drive | Content | Mode |
|---|---|---|
| vda | Alpine base — squashfs | RO, root device |
| vdb..vdN | stage layers — sparse ext4, each a previous run's overlay upperdir | RO |
| last | scratch — fresh sparse ext4 from a prewarmed empty-image pool | RW |

**Guest boot (agent as PID 1):** mount pseudo-fs; mount base at `/rom`, each stage at
`/layers/<i>`, scratch at `/overlay`; one overlay mount
`lowerdir=/layers/N:…:/layers/1:/rom, upperdir=/overlay/root, workdir=/overlay/work`
(multi-lowerdir in a SINGLE mount — overlay-on-overlay nests are kernel-capped at depth 2);
pivot_root; resync clock; listen on vsock. Add `redirect_dir=on` for rename-heavy builds.

**Commit:** guest syncs + halts → host runs `resize2fs -M`-style sparsify (optional) and stores
the scratch image content-addressed (blake3) under `~/.isopod/stages/<id>/` with `meta.json`
{parent chain, label, FC/base versions, created, bytes}. The raw ext4 image IS the artifact —
never tar the contents (whiteout char-devs and `trusted.overlay.*` xattrs get lost, silently
breaking deletions in later layers). Transfer with `cp --sparse=always` / `zstd`.

**Fork:** start a VM with the same RO lower chain + a pooled empty scratch — **<5 ms** of disk
setup, no copying, lowers shared by all concurrent forks. Committed stages are immutable ⇒ fork
is just "start from stage", no special tool needed.

**Limits & maintenance:** virtio-MMIO IRQ slots cap total devices ≈19 ⇒ practical chain depth
~10–14 (net + vsock + balloon + base + scratch take ~5). `isopod stage flatten` (backlog, design
now): boot a throwaway compaction VM that copies the merged view into a fresh single layer —
unprivileged, reuses existing machinery, reclaims whiteout garbage. Kernel lowerdir cap is 500 —
never the binding constraint.

**Correctness discipline (E2B issue #884 lesson — layered-diff bookkeeping is where correctness
dies):** stage round-trip integration tests land in the SAME milestone as commit/fork:
write→commit→fork→write→commit→verify both chains independent; deletion (whiteout) across
layers; xattr survival.

## Snapshots & warm pool (the speed path)

- Full snapshot of a booted-idle VM per (base or stage-chain): pause → `PUT /snapshot/create
  {Full}` → {vmstate, memfile} + frozen copy of its scratch image, stored under
  `~/.isopod/snapshots/<key>/`.
- Resume: fresh FC process (load requires a pristine process) → `PUT /snapshot/load
  {mem_backend: File, resume_vm: true, network_overrides, vsock_override}` into any free netns
  slot. File backend mmaps MAP_PRIVATE ⇒ lazy paging, restore API returns in low-single-digit ms;
  every fork needs its own private scratch copy first (never share a written upper).
- **Cache keyed on (FC build hash — tag + local patch-set, host kernel, CPU model, stage-chain
  hash)** — any mismatch ⇒ silently fall back to cold boot (~150–300 ms budget) and rebuild.
  WSL2 auto-updates its kernel, so this invalidation WILL fire in practice.
- Diff snapshots: at most one level (pause/resume of a running sandbox); persist only after
  offline `snapshot-editor edit-memory rebase` merge (oldest-first; only the final vmstate is
  valid). No lazy diff-chain composition exists — do not design around it.
- Agent must treat vsock connections as dead after any pause/resume/fork (device reset severs
  them; listeners survive) — reconnect-per-request handles this for free. Resync guest clock on
  every resume. Reseed entropy / regenerate any per-VM identity after fork; never bake secrets
  into stages that will be forked.
- UFFD lazy restore, balloon-shrink-before-snapshot, 8 KiB-chunk LZ4 snapshot compression
  (CodeSandbox's measured sweet spot): backlog optimizations, not v1.

## Networking

- `sudo isopod setup` (one-time, the ONLY root step) provisions N **netns slots**: each netns
  holds `tap0` with the identical guest-side config (guest always 10.107.7.2/30, gw .1), a veth
  pair to the root ns with a per-slot transit subnet, nftables SNAT/MASQUERADE + FORWARD rules,
  `net.ipv4.ip_forward=1` persisted. FC processes launch inside their slot's netns ⇒ every VM
  sees byte-identical network state ⇒ any snapshot restores into any slot unmodified.
- Slot pool is claimed/released via `~/.isopod/net/` state files; startup runs a leak-reclaim
  sweep (E2B pattern) for slots orphaned by crashes.
- DNS: public resolvers baked into guest `/etc/resolv.conf`.
- `--no-network`: no NIC attached at all. Control RPC is vsock, so exec works identically.
- Guest→host: never routed; host services are not reachable from guests (no route, nftables drop).

## Guest image build (`isopod image` subcommands, no root needed)

- **Kernel:** `isopod image fetch-kernel` pulls a prebuilt CI vmlinux from FC's public S3
  (`spec.ccfc.min/firecracker-ci/...`) to bootstrap M0; `isopod image build-kernel` builds our
  checked-in config = `microvm-kernel-ci-x86_64-6.18.config` + `OVERLAY_FS=y, SQUASHFS=y,
  EXT4_FS=y, VIRTIO_VSOCKETS=y` (all built-in, no modules). Uncompressed ELF vmlinux; boot args
  `reboot=k panic=1 pci=off quiet`.
- **Rootfs:** `isopod image build-rootfs` — `apk.static --root` install of
  `alpine-base python3 py3-pip nodejs npm git gcc musl-dev make busybox` into a dir +
  guest-agent at `/sbin/init` + pre-created mountpoints (`/rom /layers /overlay`) →
  `mksquashfs -all-root` (unprivileged).
- **Scratch pool:** pre-made empty sparse ext4 images (`mkfs.ext4 -d` unprivileged, lazy itable
  init DISABLED for deterministic prewarmed boots).

## Guest agent (`isopod-guest-agent`)

Fly-init-snapshot pattern: static musl Rust PID 1 — mounts, overlay assembly, static IP, clock
sync, zombie reaping — plus an RPC server on vsock port 52. Protocol (crate `proto`,
length-prefixed serde-JSON frames, one connection per operation, E2B envd surface as the spec):

- `exec {cmd, argv, env, cwd, timeout_ms, stdin?}` → streamed `{stdout|stderr chunk}` (32 KiB
  chunks) … `{exit_code, duration_ms}`; `signal {pid}`;
- `put_file {path, mode, bytes}` / `get_file {path}` (chunked);
- `ping`, `sync_clock {unix_nanos}`, `halt {sync: bool}`.

PTY support: backlog (needed for interactive TUIs, not for agent exec).

## MCP server (`isopod mcp`) + skill

rmcp 2.2 (`server, macros, schemars, transport-io`), stdio, `#[tool_router]`, `Parameters<T>`,
`Json<T>` structured results. Server instructions (<2 KB, front-load trigger phrases — tool
search reads them). v1 toolset (~11 tools, conventions match microsandbox/Daytona/Anthropic's
code-execution shape):

| Tool | Semantics |
|---|---|
| `sandbox_run` | **The 80% tool.** Boot (or snapshot-resume) → exec → destroy, one call. `{cmd, stage?, timeout_s=120, network=true, workdir?, env?}` → `{exit_code, stdout, stderr, duration_ms, truncated?}` |
| `sandbox_start` | `{stage?, network?, ttl_s?}` → `sandbox_id` (persistent session; hot-resume when cache valid). Fork ≡ `sandbox_start(stage=X)` — stages are immutable, no fork tool needed |
| `sandbox_exec` | sync exec in a running sandbox, default timeout 120 s |
| `sandbox_exec_start` / `sandbox_exec_poll` | job-handle pattern for long builds/servers (subagent MCP calls are never auto-backgrounded — this is the documented escape hatch) |
| `sandbox_stop` | `{sandbox_id, commit_as?}` |
| `sandbox_list` | running sandboxes |
| `stage_commit` | `{sandbox_id, name, message?}` → stage id (stack = commit on a forked chain) |
| `stage_list` / `stage_info` / `stage_rm` | store management (info shows chain, sizes, snapshot-cache status) |
| `file_put` / `file_get` | host ↔ sandbox file transfer |

Output policy: server-side head+tail truncation (~50 KB inline), full log at
`~/.isopod/vms/<sid>/exec-<n>.log` with the path in the result; declare
`_meta["anthropic/maxResultSizeChars"]` on exec tools; emit progress notifications every ~10 s
during long execs purely as idle-timeout keepalive (Claude Code doesn't render them; they don't
extend wall-clock).

**Skill** (`skill/SKILL.md`): teaches ephemeral-first (`sandbox_run` unless state must persist),
commit-then-fork discipline, stage naming (`<project>/<purpose>-<n>`), when `--no-network`, job
handles for >2 min work, cleanup habits.

**Packaging:** dev loop = repo `.mcp.json` (`claude mcp add --scope project isopod --
target/release/isopod mcp`). Later: Claude Code plugin `isopod` (plugin.json + bundled server +
skill; note plugin tool names become `mcp__plugin_isopod_<server>__*` — keep keys short). State
always in `~/.isopod`, never under plugin root (GC'd on update).

## Security posture

- v1: Firecracker unprivileged (kvm group), **built-in seccomp on** (never `--no-seccomp`),
  per-VM netns, no host FS sharing (files move only via explicit RPC), stages immutable,
  `--no-network` for untrusted code, per-drive/NIC token-bucket rate limiters as throttles.
- v2: jailer mode (root; MUST pass `--cgroup-version 2` on this host), cgroup memory/cpu caps.

## Milestones (each lands with a JSON-asserting smoke test)

- **M0 — Feasibility spike (no product code).** *[✅ COMPLETE 2026-07-21, all gates passed — see
  docs/feasibility.md: ~117 ms cold boot, ~30 ms restore, resume-not-reboot proven; NAT egress
  works under mirrored networking (no .wslconfig change); unprivileged open of root-created tap
  verified (runtime-no-root design holds).]* Fetch FC v1.16.1 + CI kernel + minimal rootfs;
  boot via curl over the API socket; snapshot create/restore round-trip **on this exact
  host/kernel**; 🔴 TAP+MASQUERADE egress test under mirrored networking (outcome decides:
  flip `.wslconfig` to NAT vs proxy fallback); measure cold-boot and resume latency (nested EPT
  means expect worse than marketing numbers — get real baselines). Results → `docs/feasibility.md`.
- **M1 — Boots from Rust.** *[✅ COMPLETE 2026-07-21 — isopod-fc typed client (live boot 39 ms +
  snapshot round trip through it), image pipeline (S3 prefix enumeration, unprivileged rootfs),
  vendored FC v1.16.1 built from source and booting via `isopod dev boot` (~134–161 ms), 66
  workspace tests green.]*
- **M2 — Exec.** Guest-agent RPC over vsock; `isopod run -- echo hi` →
  `{"exit_code":0,"stdout":"hi\n"}`; ephemeral lifecycle (boot→exec→destroy) + `isopod doctor`.
- **M3 — Stages.** Overlay chain assembly, `stage commit/list/info/rm`, fork-by-start, scratch
  pool; the round-trip + whiteout + xattr integration tests. Acceptance: commit a
  `pip install requests` stage, fork it, `python -c "import requests"` succeeds, parent unchanged.
- **M4 — Network.** `sudo isopod setup` slot pool, NAT per M0's verdict, leak-reclaim sweep,
  `--no-network`. Acceptance: `git clone` + `pip install` inside a VM; exec still works with
  networking off.
- **M5 — MCP + skill.** `isopod mcp`, `.mcp.json`, SKILL.md. Acceptance from a real Claude Code
  session: run code ephemerally → commit stage → new session forks it → fork sees state, parent
  stage unchanged.
- **M6 — Warm pool.** Snapshot save/resume path under `sandbox_run`/`sandbox_start`, cache
  invalidation keys, clock resync, resume-latency benchmark vs M0 baseline; `stage_info` shows
  cache status.

**Backlog (v2+):** jailer hardening; UFFD lazy restore + snapshot compression; `stage flatten`;
PTY exec; host→guest port forwarding; plugin marketplace packaging; systemd user service +
`vmIdleTimeout` story; content-addressed block-diff storage via the **in-VMM layered block
backend** (see "Extending Firecracker itself" — only if overlayfs chains become the bottleneck;
external NBD demoted to fallback, vhost-user ruled out as it breaks snapshots); live fork via
`MAP_SHARED` patch (v3, only if paused-snapshot forking proves insufficient).

## Verification (end-to-end acceptance for the whole project)

From Claude Code via MCP: `sandbox_run("uname -a")` cold; `sandbox_start` → `pip install` →
`stage_commit("demo/py-deps-1")` → in a second session `sandbox_start(stage=…)` → import works;
original stage bit-identical (blake3); `--no-network` sandbox can exec but not `curl`; kill -9
the MCP server mid-session → no leaked FC processes/slots after the startup sweep; latency
report: cold `sandbox_run` wall time, hot-resume wall time, fork disk-setup time (<100 ms target).

## Key references (public)

Firecracker docs: snapshot-support.md, vsock.md, network-setup.md, jailer.md, kernel-policy.md ·
swagger `firecracker.yaml` (v1.16.1 tag) · E2B `e2b-dev/infra` (envd surface, netns slots,
diff-store endgame) · CodeSandbox microVM cloning posts (same-IP trick, LZ4 chunking) ·
`superfly/init-snapshot` (Rust PID 1 shape) · rmcp docs.rs 2.2 · Claude Code MCP/plugin/skill docs ·
microsoft/WSL#10842 (mirrored-mode forwarding).
