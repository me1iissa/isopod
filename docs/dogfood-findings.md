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

1. **[fixed b1caea7] HIGH — vanity names exist but nothing lists or resolves them.**
   Names are persisted in each VM dir's `meta.json`, but there is no
   `isopod vm ls`, so a user/model cannot look up `resilient-legionary` after
   the fact — which defeats the point of memorable handles.
   → FIX at M3 integration: `isopod vm ls` (id, name, flavor, created, status)
   reading the meta.json files; name→vm resolution helper shared with stages.

2. **[fixed b1caea7] MEDIUM — `~/.isopod/vms/` grows without bound.** 25 dirs / 600 KB
   after one day of testing; harmless now (logs only), but every run adds one
   and nothing prunes. → FIX at M3 integration: `isopod vm gc [--keep-last N]
   [--older-than 7d]` with sane defaults; consider auto-gc on run.

3. **[fixed b1caea7] MEDIUM — command-not-found is indistinguishable from infra failure.**
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

5. **[fixed b1caea7] MEDIUM — guest rootfs has no `/tmp`.** Found by probing the guest
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

7. **[fixed 4605db8+] HIGH — a leaked firecracker holding a tap breaks its slot until
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

10. **[fixed 3bea60c+] HIGH — bare `pip install` failed (PEP 668).** Alpine's
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

15. **[open] MED — no Rust toolchain in any base, and `base-alpine` has no `apk`.** The squashfs
    base bakes in python/node/git/gcc/make/cmake but strips the package manager, so you can't
    `apk add` a toolchain at runtime. `curl`/`xz`/`bash` also absent (`wget`/`gzip`/`tar`/`base64`
    present). rustup-over-`wget` works fine. → for a system whose own dogfood is "build yourself",
    consider a toolchain-bearing base flavor, or keep `apk` available in base-alpine.

16. **[open] LOW/footgun — `--base X` without `--stage` silently boots the legacy `dev-agent`
    ext4 rootfs, ignoring `--base`.** The flag appears to do nothing — and, mid-M6, that legacy
    rootfs still carried the old proto v1 guest, surfacing a confusing "guest 1 does not match
    host 2" until you realise `--base` only applies with `--stage`. → warn/error when `--base` is
    passed without `--stage`, or make `--base` imply the squashfs/overlay topology.

17. **[note] proto-version skew across guest images after a `PROTO_VERSION` bump.** Bumping to v2
    for `ConfigureNet` (M6) requires rebuilding **every** guest image (base-sqfs, base-alpine
    squashfs, legacy dev-agent) *and* restarting any long-lived `isopod-mcp` server, or the guest
    baked into one image (or the stale server binary) mismatches. Credit: the error is clear and
    names both versions. → build tooling should rebuild all guest images together + stamp their
    proto version; surface per-image proto version in a status command.

*Hypothesis retracted:* I expected `aws-lc-sys` to fail for want of cmake — it built cleanly
(base-alpine ships cmake for node-gyp, and aws-lc-sys has a cc path). Not a finding.

**Concurrency stress (positive, no gap).** 6 networked `run --stage base` launched in parallel
all **warm-resumed from the one shared 512 MiB snapshot**, each claimed a **distinct slot** (0–5)
with its own `/30`, all exited 0 with NET-OK, and left **zero leaks** (no firecracker procs, no
held slot locks). The `O_EXCL` slot-claim is race-free under real contention and concurrent
resume from a single read-only memfile is safe — the core multi-agent model holds under load.
