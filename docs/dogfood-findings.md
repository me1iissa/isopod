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

4. **[open] LOW — no stdin plumbing in the CLI.** The proto supports
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
