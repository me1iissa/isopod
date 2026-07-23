# Dogfood findings

> Gaps found by *using* isopod, per the standing rule: dogfooding is the primary
> gap-discovery mechanism. Every entry gets a severity and a fix-or-file decision.
> Newest first. Format: `[status] severity — finding → decision`.

## 2026-07-21 — M2 surface gauntlet (exit codes, streams, truncation, timeout, env/cwd, binary, errors, concurrency)

What was thrown at `isopod run`: `exit 42`; stderr-only output; 200 KB stdout
(> 64 KiB cap); `sleep 30` under `--timeout-s 3`; `--env`/`--cwd`; 4 KiB of
`/dev/urandom`; a nonexistent binary; two concurrent runs; 25-run directory
accumulation. All core behaviors correct (truncation exact, full logs retained,
timeout kill in 3.05 s wall, signal 9 reported, concurrent runs isolated with
distinct vanity names).

1. **[fixed 9ecbd79] HIGH — vanity names exist but nothing lists or resolves them.**
   Names are persisted in each VM dir's `meta.json`, but there is no
   `isopod vm ls`, so a user/model cannot look up `resilient-legionary` after
   the fact — which defeats the point of memorable handles.
   → FIX at M3 integration: `isopod vm ls` (id, name, flavor, created, status)
   reading the meta.json files; name→vm resolution helper shared with stages.

2. **[fixed 9ecbd79] MEDIUM — `~/.isopod/vms/` grows without bound.** 25 dirs / 600 KB
   after one day of testing; harmless now (logs only), but every run adds one
   and nothing prunes. → FIX at M3 integration: `isopod vm gc [--keep-last N]
   [--older-than 7d]` with sane defaults; consider auto-gc on run.

3. **[fixed 9ecbd79] MEDIUM — command-not-found is indistinguishable from infra failure.**
   `isopod run -- /bin/nonexistent` yields `{ok:false, error:"exec over vsock:
   guest agent reported an error: exec: No such file or directory"}` — same
   shape as a genuine sandbox/transport failure, and no exit code. Callers
   (especially the future MCP tool) need to tell "your command is wrong" from
   "the sandbox broke". → FIX before M5: spawn-failure becomes a structured
   outcome (`exit_code:127`-style or an `error_kind` field), reserving
   `ok:false` for infrastructure faults.

4. **[fixed M5] LOW — no stdin plumbing.** The proto supports
   `stdin_b64` end-to-end but `isopod run` has no `--stdin`/`--stdin-file`, so
   piping data into a sandboxed command requires a file-put dance that doesn't
   exist yet either. → file for M5 (MCP `file_put` + a `--stdin-file` flag land
   together).

5. **[fixed 9ecbd79] MEDIUM — guest rootfs has no `/tmp`.** Found by probing the guest
   environment: `echo t > /tmp/x` fails on a fresh dev-agent VM (the dir simply
   isn't in the image; `mkdir -p` works). A large fraction of real scripts and
   tools assume `/tmp`. → FIX at M3 integration: add `/tmp` (mode 1777) and
   `/var/tmp` to every flavor's populate step (dev-busybox, dev-agent,
   base-sqfs). Guest-env facts for the record: 235 MB usable RAM of 256
   configured, ~53 MB free rootfs, 302 busybox applets, uid 0.

## 2026-07-21 — M4 networking (live, post-`sudo isopod setup`)

Egress works (ICMP + DNS through the NAT), concurrency lands on distinct slots
(0/1), host isolation holds (guest can't reach the host tap — the `iifname`
input-drop fix), `--no-network` attaches no NIC. Two findings:

7. **[fixed f332743+] HIGH — a leaked firecracker holding a tap breaks its slot until
   manually killed.** A VMM that outlived its run (here `dev-85eddd65` from an
   earlier failed attempt) kept `isopod-tap0` open, so every later slot-0 run
   died with `EBUSY` at `PUT /network-interfaces` — a confusing, persistent
   failure with no self-recovery. The stale-lock sweep only reclaims locks whose
   pid is *dead*; a live-but-orphaned VMM defeats it. → FIX: (a) claim should
   verify the tap is actually openable (or that no firecracker holds it) and
   either reclaim or skip to the next slot; (b) harden run teardown so a VMM is
   never orphaned (audit every error path between spawn and shutdown; the
   FcProcess Drop guard should cover it — find why this one escaped); (c)
   `isopod vm gc` / a `--kill-stale` should reap orphaned VMMs. Worth fixing
   before M5 (an MCP client hitting a wedged slot would be baffling).

8. **[note] MINOR — HTTP-by-IP to 1.1.1.1:80 is an unreliable egress probe.**
   `wget http://1.1.1.1` doesn't cleanly return 200 (Cloudflare redirects to
   HTTPS), so it's a poor liveness check even though egress works. Use ICMP +
   DNS (both confirmed) in the runbook; drop the plain-HTTP-by-IP check.

## 2026-07-21 — M4 acceptance (pip/git through isopod, Alpine base)

The marquee test passed: bare `pip install requests` into an Alpine stage →
commit → fork BY VANITY NAME → `import requests` with no reinstall → parent
byte-identical. Three fixes fell out of running it:

10. **[fixed 0a37865+] HIGH — bare `pip install` failed (PEP 668).** Alpine's
    Python 3.14 ships an `EXTERNALLY-MANAGED` marker, so `pip install` errored
    and an agent would have to know `--break-system-packages`. In a disposable
    sandbox that protection is pure friction. → FIXED: the `base-alpine` build
    removes every `pythonX.Y/EXTERNALLY-MANAGED` marker; bare `pip install` now
    works.

11. **[fixed] HIGH — `--commit-as` committed a stage even when the command
    FAILED.** The first pip run errored (PEP 668) yet still committed a stage
    (`lucent-crucible`) missing the package — a silent footgun for anyone who
    later forks it. → FIXED: `--commit-as` now commits only on `exit_code == 0`,
    logging a clear skip reason otherwise.

12. **[fixed] HIGH — a stage didn't record which base it was built on.** Meta
    hardcoded `base: base-sqfs` regardless; forking an Alpine-built stage
    without remembering `--base base-alpine` would mount alpine layers over a
    busybox base (site-packages but no interpreter) — a silent broken merge.
    → FIXED: `stage::commit` records the true base flavor; a fork auto-uses the
    recorded base (verified: forking with no `--base` runs Python 3.14), and
    stacking enforces a single base per chain.

9. **[note] DOC — `--timeout-s` budget includes boot.** `--timeout-s 3` gives
   the command ~2.6 s of real exec time (boot consumes ~0.4 s of the budget).
   Reasonable semantics for an outer wall clock, but must be documented in the
   CLI help and the eventual MCP tool description (whose default timeout should
   account for it).

## 2026-07-22 — self-build dogfood (isopod builds its own workspace) + M6 warm-pool verification

**Headline positive:** isopod compiled its **own full 6-crate workspace — 182 crates including
rustls / aws-lc-sys / reqwest / tokio / rmcp — in 96 s inside an isopod sandbox**, and the
freshly-built `isopod` binary ran (`isopod 0.1.0`) *inside the sandbox*. Recipe exercised the
stage-fork model end to end: stage the toolchain once (rustup stable-musl 1.97.1 → `rust-stable`
stage in 22 s), then fork it and build with `target/` on a guest tmpfs. Proof the stage/fork
model + M5.5 flex resources carry a real heavy workload. Five gaps fell out.

13. **[fixed] HIGH — sandbox networking doesn't survive a WSL2/host restart, and the failure is
    cryptic.** The user-owned `isopod-tap0..7` are non-persistent; after the WSL utility VM
    recycles they vanish and every networked `run`/`sandbox_run` fails with a raw Firecracker
    string — `Open tap device failed: Operation not permitted ... Invalid TUN/TAP Backend
    provided by isopod-tap0` — with **no hint** the fix is `sudo isopod setup`. Hit both the MCP
    path and the M6 agent this session. → FIXED: `require_network_setup` now, when a manifest
    exists, also checks the provisioned taps are actually present (`net::provisioned_taps_present`
    → `/sys/class/net/isopod-tap<i>`) and fails fast — before any disk work — with an actionable
    "networking was provisioned but its tap devices are missing — the host was most likely
    restarted … re-run `sudo isopod setup` (or --no-network)" message. (Runtime is unprivileged,
    so auto-reprovision isn't possible; the clear message is the fix. Unit-tested via an injected
    presence predicate.) (PLAN networking risk #3, made concrete.)

14. **[fixed] MED — writable scratch (overlay upper) was fixed at ~1 GiB with no size knob.** A
    *minimal* rustup toolchain (799 MiB) nearly fills it (98 MiB free, 89 %); a real build
    (`target/` reached 1.5 GiB) can't fit at all. Workaround that unblocked the self-build: mount
    a tmpfs in the guest and point `CARGO_TARGET_DIR`/`RUSTUP_HOME`/`CARGO_HOME` at it (trades RAM
    for space). → FIXED: added `--scratch-mib` (CLI) / `scratch_mib` (MCP `sandbox_run`), bounded
    128..=65536 MiB, validated before boot (clear range error, no VM launched). The image is
    sparse, so a large apparent size costs little host disk until written. Verified live: 4096 →
    3.9 G overlay, 8192 → 7.8 G. Passing it forces the cold ext4 path (a warm resume uses a RAM
    tmpfs upper), so the requested size always takes effect; `--mem-mib` remains the lever for a
    bigger RAM upper on warm runs.

15. **[fixed] MED — no Rust toolchain in any base, and `base-alpine` has no `apk`.** The squashfs
    base bakes in python/node/git/gcc/make/cmake but strips the package manager, so you can't
    `apk add` a toolchain at runtime. `curl`/`xz`/`bash` also absent (`wget`/`gzip`/`tar`/`base64`
    present). rustup-over-`wget` works fine. → for a system whose own dogfood is "build yourself",
    consider a toolchain-bearing base flavor, or keep `apk` available in base-alpine.
    → FIXED (2026-07-22 wave): base-alpine retains the verified static `apk` + signing keys
    (in-guest `apk add jq` verified live) and adds `cmake` + GNU `coreutils`; Rust toolchains
    stay stages (`rust-stable`), which the self-build proved out.

16. **[fixed] LOW/footgun — `--base X` without `--stage` silently boots the legacy `dev-agent`
    ext4 rootfs, ignoring `--base`.** The flag appears to do nothing — and, mid-M6, that legacy
    rootfs still carried the old proto v1 guest, surfacing a confusing "guest 1 does not match
    host 2" until you realise `--base` only applies with `--stage`. → warn/error when `--base` is
    passed without `--stage`, or make `--base` imply the squashfs/overlay topology.
    → FIXED (2026-07-22 wave): a lone `--base` is now a hard error naming both valid spellings.

17. **[fixed] proto-version skew across guest images after a `PROTO_VERSION` bump.** Bumping to v2
    for `ConfigureNet` (M6) requires rebuilding **every** guest image (base-sqfs, base-alpine
    squashfs, legacy dev-agent) *and* restarting any long-lived `isopod-mcp` server, or the guest
    baked into one image (or the stale server binary) mismatches. Credit: the error is clear and
    names both versions. → build tooling should rebuild all guest images together + stamp their
    proto version; surface per-image proto version in a status command.
    → FIXED (2026-07-22 wave): every build stamps `<image>.meta.json` (flavor, proto, agent
    sha256, image sha256); run paths refuse a stale image *pre-boot* naming the fix;
    `isopod image build-all` force-rebuilds every flavor together and `image ls` shows
    per-image proto + stale/unstamped. Exercised for real by the v2→v3 bump.

*Hypothesis retracted:* I expected `aws-lc-sys` to fail for want of cmake — it built cleanly
(base-alpine ships cmake for node-gyp, and aws-lc-sys has a cc path). Not a finding.

**Concurrency stress (positive, no gap).** 6 networked `run --stage base` launched in parallel
all **warm-resumed from the one shared 512 MiB snapshot**, each claimed a **distinct slot** (0–5)
with its own `/30`, all exited 0 with NET-OK, and left **zero leaks** (no firecracker procs, no
held slot locks). The `O_EXCL` slot-claim is race-free under real contention and concurrent
resume from a single read-only memfile is safe — the core multi-agent model holds under load.

## 2026-07-22 — MCP v2 gauntlet (post-restart, all-MCP) + self-build **via MCP**

Session restart picked up the proto-v2 `isopod-mcp` binary; the whole surface was re-verified
**through the MCP tools alone**: a 6-agent workflow ran ~37 scenarios (exec semantics, stage
lifecycle, network/F1, resource caps, toolchain, warm pool) with an adversarial coverage critic,
plus inline probes. Headline: **the full workspace now builds inside an isopod sandbox driven
end-to-end over MCP** — clean debug build 2 m 05.9 s (4 vcpu / 3072 MiB / 8 GiB scratch, crates.io
downloads included), committed as stage `isopod-build` (1.53 GiB layer, +34.3 s commit),
**incremental rebuild 6.93 s** from a fork, `cargo test -p isopod-proto -p isopod-fc` green in
39.6 s, release `isopod` in 2 m 35 s, and the binary **extracted byte-exact to the host**
(stdout log 14,300,661 B complete; decoded 10,585,920 B, sha256 match) where it runs directly —
`file`: static-pie musl, no loader dependency. Chain: `rust-stable` → `isopod-src` →
`isopod-build`, both new stages retained for future builds (see `docs/sandbox-build.md`).

**Corrections to the 2026-07-22 self-build entry above:**
- **cmake was never in base-alpine.** `ALPINE_PACKAGES` (rootfs.rs) never listed it and
  `git log -S cmake` on the file is empty; `cmake --version` in-guest fails. #15's
  "python/node/git/gcc/make/cmake" list and the retracted-hypothesis note ("ships cmake for
  node-gyp") were wrong — aws-lc-sys built via its cc path with **no cmake present**.
- **The warm pool DOES engage via MCP** — but invisibly, and two gauntlet agents misdiagnosed it
  as broken (a warm-eligible run's console.log is 121 B: agent re-IP line only, no kernel boot).
  What looked like a "provably cold" comparator (2 c/1024 MiB) had silently **built its own
  snapshot on first use** (5.4 s) and warm-resumed afterwards. End-to-end: warm ≈ 430 ms,
  cold ext4 path ≈ 570–700 ms, first-use-of-a-shape snapshot build ≈ 5.4 s. The M6 "resume
  52–72 ms" figure is the restore step, not wall time. See #20.

18. **[fixed] MED — a bad `cwd` fails blaming `/bin/sh`, not the missing directory.**
    `sandbox_run` with `cwd="/no/such/dir"` returns exit 127 with stderr
    `isopod-exec: /bin/sh: No such file or directory (os error 2)` — the natural read is "the
    image has no shell" (and 127 usually means command-not-found), a wrong-way debugging lead.
    → isopod-exec should check/chdir the cwd first and report `cwd '/no/such/dir': No such
    file or directory`.

19. **[fixed¹] MED — stale-proto guest failure is masked by a tap error on the networked path.**
    `base-sqfs` (still proto v1, #17) with default networking fails as `Open tap device failed:
    … Device or resource busy … Invalid TUN/TAP Backend provided by isopod-tap0` (reproduced
    twice; base-alpine on the same slot works immediately after) — pointing at host networking
    instead of the real cause. Only `network=false` surfaces the correct `guest agent protocol
    version 1 does not match host 2`. → surface the proto mismatch before/instead of the tap
    error; also worth checking whether any cold boot can transiently collide with a
    warm-pool-held tap.

20. **[fixed] LOW — MCP result JSON omits boot-path and commit-cost observability.** The CLI
    result has `path: "cold"|"warm"`; the MCP result doesn't, which is exactly why the warm pool
    was misdiagnosed mid-gauntlet. `commit_as` runs also fold commit time into `total_ms`
    (1612 ms total vs 41 ms exec on a trivial commit; ~34 s for a 1.53 GiB layer ≈ 20 s/GiB).
    → add `path` (incl. distinguishing "snapshot-build" from plain cold) and `commit_ms` to the
    MCP result.

21. **[fixed] LOW — no first-class host↔guest file channel.** Payload-in: MCP `stdin` transits
    model context twice, so the 290 KB source tarball (~75 k tokens) is unusable over MCP —
    injection had to use CLI `--stdin-file` (which worked perfectly). Artifact-out: base64 over
    stdout is lossless (log file byte-exact at 14.3 MB) but floods the tool result with a
    truncated blob. → `sandbox_run` `stdin_file` (host path) + a copy-out parameter (guest path →
    host file); a git remote will also fix source-in.

22. **[documented] — parallel `sandbox_run` tool calls in ONE Claude message execute serially.** Six
    batched calls all ran on slot 0 at ~3.3 s each (a genuine overlap would force distinct
    slots). Client-side behavior, not a server bug: concurrent requests from *separate* agent
    processes interleaved fine during the gauntlet (slots 0/1 held simultaneously), matching the
    6-way CLI proof. Guidance for agents: fan out via subagents for parallel sandboxes.

23. **[fixed] — guest hostname is `(none)`.** `$(hostname)` in-guest prints `(none)`; setting it
    to the vanity VM name (e.g. `lucent-cryptarch`) would improve log/prompt ergonomics.

24. **[fixed] — rootfs.rs comment implies in-guest `apk add`, but no apk ships.** The
    keep-parent-dirs comment says "so an online guest can `apk add` more packages later", yet
    `command -v apk apk.static` finds nothing in-guest (re-verified). Align the comment with
    however #15 is resolved.

**Positive re-verifications (all via MCP):**
- **F1 egress proven against a live service**: host connects to its own LAN listener
  (`<host-lan-ip>:3478`) instantly; the guest gets a filtered **timeout** on that same listening
  port, and on gateway:80, and on RFC1918/link-local probes — while DNS through the gateway
  works. Drop-not-refused + live-listener evidence closes the "maybe nothing was there" gap.
- Truncation: 600 KB stdout → in-band string capped, `stdout_truncated=true`, `stdout_bytes`
  exact, log file complete (verified byte-exact at 14.3 MB during extraction). Binary stdout is
  lossy U+FFFD in JSON but byte-accurate in the log; `stdout_bytes` counts raw bytes.
- Resource-cap errors are uniformly self-serve (vcpus 1-or-even w/ examples; host CPU cap;
  128 MiB mem floor; over-mem shows the full headroom arithmetic; scratch range 128..=65536).
- Stage model: commit-on-zero only (exit 3 → no stage), chain/parent info correct, whiteouts
  work, parents immutable, `stage_rm` protection names every dependent by id+label (excellent),
  child-first removal clean; label + vanity-name + full-id resolution work (id *prefix* is not
  supported — fine per docs, but docker/git-style unique-prefix ids would be nicer).
- Timeout shape: `timed_out=true, exit_code=null, signal=9`, partial stdout preserved.
- `network=false`: no NIC (fields absent from result), exec fine over vsock; offline forks of a
  pip-carrying stage import the package with no network.
- Quoting/UTF-8/env/cwd/stdin (12 B and 8 KB) all exact.

**Next-gauntlet checklist** (from the adversarial coverage critic — none ever covered):
duplicate + concurrent `commit_as` labels; timeout during boot/commit and whether `commit_as`
fires on `timed_out`; stderr truncation + dual-stream flood (pipe-deadlock class); unconsumed
stdin (EPIPE) and 64 KB–1 MB stdin; hostile labels (unicode, `../x`, very long) and env names
(`=`, empty, PATH/HOME override); opaque-dir whiteouts (`rm -rf` + recreate) and 8–16-layer
chains; `cwd` into stage-created/whiteouted dirs; VM-record/exec-log retention under a
long-lived MCP server (`vm_gc` semantics, dangling `*_log_path`); ICMP egress; nonexistent
command via MCP (#3 regression probe).

## 2026-07-22 — findings-fix wave: #15–#25 closed, proto v3, images rebuilt

One coordinated pass (plan-mode designed, code-explorer-mapped) closed every open finding.
Host-only wins first (#20 observability fields, #16 `--base` hard error, MCP `stdin_file`,
auto-GC at startup + every 20 runs, #22 docs), then a proto-v3 wave: `SetHostname` (#23),
streamed `CopyOut` (#21, CLI `--copy-out` / MCP `copy_out`), #18 cwd error fix, apk + cmake +
coreutils in base-alpine (#15/#24), image sidecars + `image build-all`/`image ls` + pre-boot
skew guard (#17, unmasks #19), and SnapshotKey v2 keyed on the base image's content id:

25. **[fixed] MED — `SnapshotKey` ignored image content, so warm snapshots survived image
    rebuilds as silent stale resumes** (surfaced by plan-mode exploration; almost certainly
    bit the v1→v2 bump too). Key material v2 adds the sidecar-recorded image sha256, cheap to
    read per run. A rebuilt base now simply keys to fresh snapshots.

**Verified live post-cutover (all four images rebuilt + stamped proto v3, warmpool cleared):**
guest hostname == vanity name on cold boot *and* warm resume; first warm-eligible run reports
`snapshot_built:true` with the ~4 s build visible in `total_ms`, next run `path:"warm"`,
`resume_ms:56`, 406 ms total; bad cwd → `isopod-exec: cwd '/no/such/dir': No such file or
directory`; `--copy-out` extracted a 0755 artifact byte-exact; in-guest `apk add jq` → jq
1.8.1; cmake 4.2.3 + GNU coreutils 9.11 present; **base-sqfs boots networked and
warm-resumes** (the #19 mask scenario is gone); `image ls` shows all images proto 3, none
stale. **Milestone: the full workspace test suite now runs inside a sandbox — 132/132 core
tests in-guest** (GNU cp closed the last host-only gap).

¹ #19's *masking* is fixed and NIC errors now name slot + tap; the original tap-busy
collision itself was never reproduced (static analysis cleared the slot claim, FC restore
override, and shutdown ordering) — a live repro attempt is queued for the next gauntlet.

**Caveat:** the long-lived `isopod-mcp` server must restart to pick up proto v3 — until then
the MCP tools fail fast against v3 guests (by design, and now pre-boot). Full MCP-side
re-verification + the checklist gauntlet run after the restart.

## 2026-07-22 (post-restart) — proto-v3 MCP verification gauntlet (the "Next-gauntlet checklist")

The `isopod-mcp` server was restarted onto proto v3 and the whole never-covered checklist
was run **through the MCP tools alone**, orchestrated as a phased workflow: a reachability
canary → 8 parallel scenario buckets → an isolated concurrent-same-label commit race → the
queued #19 tap-busy live repro (4 agents) → `vm_gc`/retention → **adversarial verification of
every candidate finding** (to kill probe artifacts) → a coverage critic. **49 scenarios, 23
agents, ~843 k tokens, ~17 min.** Result: **1 HIGH and 2 LOW confirmed; 2 candidate findings
refuted on verification.** Everything else PASS/INFO, including the full F1 re-verification.

26. **[fixed] HIGH — forking a stage with ≥10 overlay layers silently breaks and boots on the
    wrong rootfs.** *(Fix + live verification: see the 2026-07-23 fix-wave section below.)* `sandbox_run` happily commits a 10th layer (exit 0), but forking any
    depth-≥10 stage boots onto the **read-only squashfs base root** with *all committed layer
    state invisible*, writes failing — and **the MCP result returns a normal exit 0 with no
    error field** (a command that happens to exit 0 could even `commit_as` a bogus stage).
    Live repro: `gaunt-chain-10` fork → `/bin/sh: can't create /root/chain/l11: nonexistent
    directory`; `/proc/mounts` shows `/dev/root / squashfs ro` (no overlay), `/dev/vdb..vdj`
    mounted at `/layers/1..9`, but `/layers/10` absent; console: `[isopod-agent] overlay:
    FAILED to assemble stage root (layers=10, upper=drive): mount layer /dev/vdk at
    /layers/10: No such file or directory (os error 2); continuing on the read-only base
    root`. **Root cause** (`crates/guest-agent/src/overlay.rs:189-193`): the layer-mount loop
    mounts each drive at `/layers/<i+1>` but **never `create_dir_all`s the mountpoint** (unlike
    `UPPER_DIR`/`WORK_DIR` at `:185-186`); it relies on mountpoints pre-baked into the base
    image, which only ship `/layers/0..9`, so the 10th layer's `/layers/10` doesn't exist →
    `mount(2)` ENOENT. Practical cap is **9 committed layers**. The unit tests
    (`overlay.rs:354-355`) only assert `layer_mountpoint(1)` and `(9)` — never 10, so the cap
    was never caught. **The silent half** (`overlay.rs:65, 87-96`): an assembly failure is
    logged to the console only and boot proceeds on the base root ("best-effort by design");
    nothing propagates to the host / MCP result. → **FIX** (two parts): (a) one-liner —
    `std::fs::create_dir_all(&mnt)?;` before the `mount` in the `:189` loop, which removes the
    pre-baked-mountpoint dependency and lifts the cap entirely (add an integration test forking
    a 16-layer chain); (b) **surface overlay-assembly failure as a run error** (or at least a
    `overlay_degraded: true` flag in the exec result) instead of silently booting on the wrong
    rootfs — otherwise a broken deep fork masquerades as a healthy exit-0 run. (b) is a design
    call — making it fatal changes boot behavior — so worth an explicit decision. Requires a
    guest-agent rebuild + re-stamp of all images and a gauntlet re-run to close.

27. **[fixed] LOW — env keys are forwarded to the guest `execve` environment without
    validation.** *(Fix + live verification: see the 2026-07-23 fix-wave section below.)* `env={"FO=O":"bar"}` is accepted silently and lands in the guest environ as
    the ambiguous entry `FO=O=bar` (any parser reads it as `FO="O=bar"`, *not* the requested
    name); `env={"":"bar"}` lands as a nameless `=bar` entry. Verified at the raw
    `/proc/self/environ` level (not a busybox `env` display quirk). Neither crashes or wedges
    the guest agent, and later runs are unaffected — POSIX env names must be nonempty and
    `=`-free, but `execve` doesn't enforce it and the passthrough is faithful, so this is a
    minor input-validation gap, not a malfunction. Source: `crates/guest-agent/src/exec.rs:84`
    (`for (k, v) in &req.env { cmd.env(k, v); }` — no key check). → **FIX**: reject keys
    matching `/=|^$/` with a clear pre-boot error (host-side in the MCP/CLI param validation,
    mirroring the `stdin`/`stdin_file` -32602 style), or skip+warn in `exec.rs`.

**Refuted on verification (recorded so they aren't re-raised):**
- *Commit runs return `stage_id`/`stage_name`, not the "documented" `commit_id`* (G5, first
  raised LOW) — **refuted**: the string `commit_id` exists nowhere in the repo; `stage_id` +
  `stage_name` **are** the interface. No drift. (The workflow schema I wrote carried the wrong
  field name in from the checklist prose — the verifier caught it.)
- *`sandbox_run` doesn't return the committed stage's vanity name, so callers misreport it*
  (R2, first raised LOW) — **refuted**: the result **does** carry `stage_name`; both race
  agents simply reported `vm_name` by mistake. The committed name is directly available and
  can't be confused with the VM name.

**Positive re-verifications (all via MCP, all PASS):**
- **F1 egress hardening holds after the restart** — all 7 RFC1918/link-local probes
  (incl. `169.254.169.254`) **DROP** with a full ~3 s socket timeout (no `CONNECTED`, no fast
  `ConnectionRefused` = pure drop semantics), while public ICMP (`1.1.1.1`), DNS, and HTTP
  (`example.com` → 200) all work — destination-scoped, not a blanket kill. `network=false` is
  airtight (no `guest_ip`/`slot` fields, instant `OSError`, exec still over vsock).
- **#3** nonexistent-command and **#18** cwd-error stay closed (structured exit 127, correct
  `isopod-exec: cwd '…': No such file or directory`).
- **stderr truncation** (first stderr-side probe): 200 000 B → 64 KiB in-band cap,
  `stderr_truncated=true`, `stderr_bytes` exact, on-disk log complete at 200 000 B.
- **dual-stream 8 MB+8 MB interleaved flood** (the pipe-deadlock probe): **no deadlock** —
  completed in 176 ms, both streams truncated in-band with exact `*_bytes`, both logs complete
  at 8 000 000 B each.
- **stdin**: unconsumed 1 MiB `stdin_file` → clean exit 0 (host writer tolerates EPIPE); 64 KiB
  and 1 MiB delivered byte-exact (`wc -c` = 65536 / 1048576); `stdin`+`stdin_file` together and
  `stdin_file="-"` both rejected pre-boot (-32602).
- **hostile labels** (unicode `😀-café-Ω`, `../../../etc/passwd-pwned`, 410-char) all safe:
  labels are pure metadata, stage dirs are always `st-<hex>`, nothing written outside
  `~/.isopod/stages` (host-checked). **Duplicate labels** → clean ambiguity error naming all
  candidates (-32603), no silent pick.
- **opaque-dir whiteout** (`rm -rf /data` + recreate): only the new file visible, no lower-layer
  bleed. **cwd into a stage-created / whiteout-recreated dir**: works.
- **proto-v3 fixes**: hostname == vanity name on cold **and** warm; `copy_out` byte-exact
  (sha match, mode 0755); in-guest `apk add jq` → jq 1.8.1; cmake 4.2.3 + GNU coreutils cp
  9.11; observability fields (`path`/`resume_ms`/`snapshot_built`/`commit_ms`) all present.
- **timeout**: exec-timeout → `timed_out=true, exit_code=null, signal=9`, partial stdout kept;
  **`commit_as` on a timed-out run correctly commits NOTHING** (the key never-tested
  interaction); boot-timeout edge leaks no slot.
- **concurrent same-label commit race**: store fully consistent — both stages present, all 29
  vanity names unique, both forkable with distinct uncontaminated content, metadata survived
  the server restart. (Commits landed 2 s apart — batched MCP calls serialize — so a truly
  simultaneous index write wasn't forced; behavior nonetheless correct.)
- **#19 tap-busy**: **NOT reproduced** across 12 networked `base-sqfs` runs (cold→warm→warm on
  slot 0, egress live each time). *Caveat — under-powered:* the workflow cap is 2 agents and
  each agent's runs were sequential, so the concurrent / crashed-owner tap-reclaim paths
  (`crates/core/src/net.rs` slot allocator) were **not** exercised. Absence here ≠ absence.
- **`vm_gc`/retention**: `keep_last=5` keeps exactly the 5 newest ∪ sub-60 s records (the 62 s
  record was correctly pruned — the 1-minute grace is a hard cutoff), disk physically freed
  (39→5 dirs), no over-prune, and pruned runs' `*_log_path` become dangling **by design**
  (matches the docstring warning).

**Note — a security-heuristic false positive during the run:** the R2 verifier was flagged for
`stage_rm "solar-psion"` "with no evidence it was created this session". Investigated and
**cleared**: `solar-psion` was that agent's own throwaway — it ran
`commit_as="r2-verify-commit-name-probe"` (which returned `stage_name=solar-psion`) to check
whether the result exposes the stage name, then deleted its own test stage. All 9 pre-existing
stages remained intact; no real stage was lost.

**Next-gauntlet checklist** (from the coverage critic — genuinely open):
- **Post-#26-fix boundary sweep**: chains at exactly 9/10/11/16 layers; assert layer-1 content
  is visible at layer 16 and writes land. Plus a **silent-fallback guard probe** that asserts
  overlay-assembly failure surfaces as a run ERROR, not exit-0 on the base root.
- **cwd into a WHITEOUTED dir** (fork a stage where the cwd target was `rm -rf`'d in a later
  layer) — #18-style clean spawn error expected; only the stage-*created* case was covered.
- **Deep opaque-dir whiteout** (recreate at layer ~8 through a long lowerdir chain) — blocked by
  #26 today.
- **Deterministic timeout-DURING-commit** (dirty 2–4 GB of *incompressible* scratch so the
  commit genuinely runs multi-second; assert `timed_out`, no partial/orphan stage, store
  integrity). H4 sparsified to ~632 KB so this stayed unobserved.
- **Concurrent tap gauntlet**: N>slot-count simultaneous networked runs (expect graceful
  slot-exhaustion, not EBUSY) and SIGKILL-a-networked-VM-then-relaunch (crashed-owner tap
  reclaim) — the actual #19 failure class, still unexercised.
- **Warm-vs-cold matrix**: record the `path` field per scenario and force both; the RAM-upper
  (warm) vs drive-scratch (cold) overlay paths diverge, and big-write behavior on the RAM upper
  (ENOSPC/OOM within `mem_mib`) is uncovered.
- **`vm_gc` racing a live run**: invoke `vm_gc keep_last=1` mid-`sandbox_run`; assert the live
  record + its `*_log_path` survive.
- **Regression probes** once #26/#27 land (env-name rejection; the deep-chain fix).

## 2026-07-23 — #26/#27 fix wave (built in-sandbox, verified live)

**Root-cause refinement for #26**: the intended chain-depth cap was always **10**
(`stage.rs MAX_CHAIN_DEPTH`, derived from Firecracker's virtio-MMIO IRQ slot budget and
enforced at both `commit` and `chain_paths`) — the bug was an **off-by-one between the baked
mountpoints and the 1-based layer indexing**: base images shipped `/layers/0..9` while a
depth-10 chain needs `/layers/1..10`, so exactly the *last permitted depth* broke. (The
gauntlet's "≥10 layers" phrasing was thus really "the depth-10 boundary"; depths >10 were
always refused loudly by the cap.)

**Fixes landed:**
- **#26a (guest, `overlay.rs`)** — layer mountpoints now live on a **tmpfs mounted over
  `/layers`** and are `create_dir_all`'d per layer. The base root is a read-only squashfs, so
  the naive `create_dir_all` fix would have EROFS'd; the tmpfs removes the baked-mountpoint
  dependency for any depth the cap permits.
- **#26b (proto + guest + host)** — overlay-assembly failure is no longer silent: the guest
  records it and reports it in every `Pong` (additive `overlay_error` field, proto stays v3);
  the host's `ping()` turns it into a fatal `AgentError::OverlayDegraded` (exactly parallel to
  `ProtoMismatch`), so **all** readiness paths — run, snapshot build, warm resume — refuse to
  proceed on a wrong rootfs instead of returning exit 0. A degraded snapshot can never be
  cached. The guest still boots to the base root for serial-log diagnosability (PID 1 must not
  die), but no exec is served by a run.
- **#27 (host + guest)** — env validation at two levels: `core::vm::validate_env` rejects
  empty/`=`/NUL names and NUL values **pre-boot** (the shared choke point covering the MCP
  map, which `parse_env_kv` never sees), and the guest agent independently rejects the same
  shapes before `execve` (defense in depth, exit 127 + `isopod-exec:` stderr).
- Readiness error contexts reworded ("readiness check failed" instead of "did not answer a
  ping") so an `OverlayDegraded`/`ProtoMismatch` cause isn't wrapped in a misleading message.
- *Not* landed: a redundant 24-layer "vdz naming ceiling" guard drafted during the fix was
  removed on review — `MAX_CHAIN_DEPTH = 10` already governs strictly tighter at both commit
  and resolve, so the device-naming ceiling is unreachable.

**Build**: full workspace built + tested **inside an isopod sandbox** (`isopod-build` stage,
offline — taps were down, see below; `stdin_file` source injection + `copy_out` extraction).
All tests green (135 core + 42 + 39 + guest/proto/cli suites, 0 failures) including new units:
`layer_mountpoint(10)`, Pong `overlay_error` additive-shape round-trip, host
`ping_rejects_degraded_overlay_root`, `validate_env`, guest `validate_env_pair`. Warmed build
cache committed as stage `isopod-build/2026-07-23-fix26`. All four images re-stamped (proto 3,
agent `6b7d85db52c3…`); stale warm-pool snapshots (old base ids) cleared.

**Live verification (new CLI + images):**
- **Depth matrix at the real boundary**: depth 9 fork OK (regression); **depth-10 fork of
  `gaunt-chain-10` now works** — all 10 markers visible, writes land, `/proc/mounts` shows the
  10-deep overlay root (`lowerdir=/layers/10/upper:…:/layers/1/upper:/`); depth-11 commit
  refused pre-emptively with the clear MMIO-budget error. (The checklist's "16-layer" probe is
  moot — 16 was never bootable by design.)
- **MCP path, no server restart needed for the guest side**: `sandbox_run` forking
  `gaunt-chain-10` through the *running* server → 10 markers, overlay root, exit 0 (images are
  read per run). `env={"FO=O":"bar"}` → exit 127, `invalid environment variable name "FO=O"`;
  `env={"":"bar"}` → exit 127, `name must not be empty` (the guest-side defense; host-side
  pre-boot rejection activates on the next MCP server restart).
- The **silent-fallback guard** (#26b) is covered by unit + proto-shape tests; a live
  forced-assembly-failure probe would need a deliberately broken image and stays on the
  checklist.

**Environment notes**: WSL2 was restarted since the gauntlet — tap slots are gone, so
networked runs fail with the correct #13 guidance until `sudo isopod setup` is re-run (all of
the above verified with `--no-network`; warm-pool paths therefore unexercised this wave). The
long-lived MCP server still runs the pre-fix host code: guest-side fixes are already effective
through it (images re-read per run); `validate_env`, `OverlayDegraded`, and the reworded
contexts engage on its next restart (binaries at `target/release/{isopod-mcp,isopod-jail}` are
already the fixed builds).
