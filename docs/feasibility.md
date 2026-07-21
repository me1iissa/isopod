# M0 feasibility spike — results

> Status: ✅ M0 COMPLETE (2026-07-21) — all gates passed; M1 unblocked.
> Host: WSL2 6.6.114.1-microsoft-standard-WSL2 (NOT in Firecracker's CI-validated set), 4 vCPU, 5.8 GiB.
> Method: Firecracker v1.16.1 release binaries (sha256-verified) + CI vmlinux 6.1.176 & 6.18.36 +
> unprivileged busybox ext4 rootfs. Raw data, serial logs, configs, harness scripts: `~/.isopod/m0/`.

## Verdicts (gate for M1+)

| Question | Verdict | Evidence |
|---|---|---|
| FC v1.16.1 boots a guest on this host | ✅ PASS | ≥3 runs per kernel; serial + API state |
| Full snapshot → restore resumes execution (not reboot) | ✅ PASS | 6/6 round trips: guest-uptime TICK monotonic across restore, no boot banner in restored serial |
| Diff snapshot + `snapshot-editor` rebase + restore of merged result | ✅ PASS | resumes at diff point; diff memfile ~892 KiB sparse vs 256 MiB full |
| Snapshot format version (for cache keys) | **v10.0.0** | `snapshot-editor info-vmstate version` |
| Kernel-forwarded NAT egress under mirrored networking | ✅ **PASS** (2026-07-21, user-run) | netns→veth→MASQUERADE→eth0: ping 3/3 to 1.1.1.1, HTTPS-by-IP 301, DNS via 1.1.1.1 resolved, `https://api.github.com` HTTP 200. WSL#10842 does not bite this host — **no `.wslconfig` change needed; NAT design proceeds** |
| Unprivileged open of root-created tap | ✅ **PASS** (2026-07-21, user-run, `--tap-only`) | `melissa` opened `/dev/net/tun` + bound root-created tap via `TUNSETIFF (IFF_TAP\|IFF_NO_PI)` — the root-only-at-setup / no-root-at-runtime design holds. (First run was invalid: 17-char ifname vs `IFNAMSIZ` 15 — script bug, fixed) |

## Latency baselines (256 MiB / 1 vCPU guest, nested EPT, medians)

| Metric | 6.18.36 kernel | 6.1.176 kernel |
|---|---|---|
| Cold boot → userspace, optimized args | **~117 ms** (111–121) | ~139 ms |
| Cold boot, default verbose serial | ~884 ms (UART-bound, not compute) | — |
| InstanceStart API return | ~27 ms | — |
| Full snapshot create | ~297 ms | ~284 ms |
| Snapshot load API return (`resume_vm`, state Running) | ~30 ms | ~26 ms |
| Load → first observable guest activity | 20–80 ms | 20–80 ms |
| Diff snapshot create | ~46 ms | — |
| Idle FC RSS | ~48.7 MiB | — |

Even under WSL2 nested virtualization, the 6.18 kernel meets Firecracker's ≤125 ms boot spec and
hot-resume lands well inside the plan's 250 ms budget. PLAN.md's "cold `sandbox_run` < 1 s wall"
target is comfortably realistic.

## Findings that bind M1+ implementation

1. **`firecracker --id` SIGABRTs on dots** — allowed charset `[A-Za-z0-9_-]`; `isopod-fc` must
   sanitize/validate VM ids.
2. **S3 CI-artifact layout changed**: no `firecracker-ci/v1.16/` prefix exists (last versioned is
   v1.15); current kernels live under date-stamped prefixes (spike used
   `20260717-5ac3f5ffdcd7-0`). `isopod image fetch-kernel` must enumerate bucket prefixes, not
   template `v<major.minor>/` (the getting-started doc's own recipe 404s).
3. **Upstream rootfs recipe needs root** (`sudo mkfs.ext4 -d`) — our unprivileged path works:
   populate dir → `mkfs.ext4 -d` as user; CI kernels have `DEVTMPFS_MOUNT=y` so `/dev/console`
   appears without mknod.
4. **Guest cmdline must include `i8042.*` disables + `quiet`** — the i8042 keyboard probe alone
   costs ~440 ms; verbose serial costs ~300 ms more.
5. **`Content-Type: application/json` is mandatory** on API PUTs (else 400 + process exit 1) —
   encode in `isopod-fc`, cover with a test.
6. **Guest wall-clock is stale after restore** (PLAN risk #6 confirmed empirically) — guest-agent
   clock resync on every resume is required, not optional.

## Decisions triggered

- Warm-pool snapshot cache: key must include snapshot format (v10.0.0 today) alongside FC build
  hash, host kernel, CPU model, stage-chain hash.
- Guest kernel: 6.18-series confirmed as the right base (faster boot than 6.1 here, and it's
  Firecracker's go-forward validated config).
- Networking design decision: **RESOLVED — proceed with the planned NAT design under mirrored
  mode**; no `.wslconfig` flip, no proxy fallback. (`ip_forward` was 0 at baseline — `isopod
  setup` must set + persist it, as planned.)
- M1 note: interface naming scheme must respect `IFNAMSIZ` 15 — `isopod-tapN`/`iso-veth-N`
  style names validated at construction time in `net.rs`.

## Spike artifacts

`~/.isopod/m0/`: `bin/` (firecracker, jailer, snapshot-editor — sha256-verified),
`images/` (2 vmlinux + rootfs), `logs/` (19 serial logs + API PUT bodies + timing JSONL),
`vm/` (vmstate + memfiles), `results-boot.json`, `NOTES-boot.md`, harness scripts
(`boot-run.sh`, `snap-run.sh`, `diff-snap.sh`). Total footprint 891 MB.
