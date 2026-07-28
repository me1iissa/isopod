#!/usr/bin/env python3
"""isopod latency benchmark — real boot->exec->destroy timings.

Each sample is one full `isopod run` (claim slot -> boot/resume a microVM -> exec
a trivial command over vsock -> capture output -> destroy the VM). We read the
timings straight out of isopod's own JSON result (total_ms, resume_ms, exec_ms),
so a sample is the genuine end-to-end wall time of one disposable sandbox.

Categories (all on the same host, one base, 1 vCPU / 512 MiB):
  warm    default networked run  -> warm-pool snapshot resume   (the repeat-call path)
  cold    --scratch-mib 1024     -> forced cold ext4 boot, networked (first-call / cache miss)
  nonet   --no-network           -> cold boot, no NIC attached   (the untrusted-code mode)

Usage:  python3 scripts/bench.py [--iters N] [--warmup W] [--base B] [--json out.json]

`--base` takes anything `isopod run --base` takes, including an imported image
spelled `oci:<name>` — which is what makes a built base and an imported one
comparable on one harness rather than two.

Prints a human table to stderr and a JSON summary to stdout.
"""
import argparse, json, os, statistics as st, subprocess, sys, time

ISOPOD = os.environ.get("ISOPOD_BIN", "isopod")
DEFAULT_BASE = "base-alpine"
CATS = {
    "warm":  [],                         # default: networked, warm-pool eligible
    "cold":  ["--scratch-mib", "1024"],  # forces the cold ext4 path, still networked
    "nonet": ["--no-network"],           # cold boot, no NIC
}
CMD = ["--", "echo", "isopod-bench"]

def one_run(extra, base=DEFAULT_BASE):
    p = subprocess.run([ISOPOD, "run", "--stage", "base", "--base", base] + extra + CMD,
                       capture_output=True, text=True, timeout=120)
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        raise RuntimeError(f"non-JSON stdout: {p.stdout[:200]} / err: {p.stderr[:200]}")
    if not d.get("ok") or d.get("exit_code") != 0:
        raise RuntimeError(f"run failed: {d}")
    return d

def pct(xs, q):
    xs = sorted(xs)
    if not xs: return None
    i = min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))
    return xs[i]

def summarize(name, samples):
    tot = [s["total_ms"] for s in samples]
    row = {
        "category": name,
        "n": len(tot),
        "path": samples[0].get("path"),
        "total_ms": {
            "min": min(tot), "p50": pct(tot, 50), "mean": round(st.mean(tot), 1),
            "p90": pct(tot, 90), "p99": pct(tot, 99), "max": max(tot),
            "stdev": round(st.pstdev(tot), 1),
        },
        "seq_vms_per_min": round(60000 / st.mean(tot), 1),
    }
    res = [s["resume_ms"] for s in samples if s.get("resume_ms") is not None]
    if res:
        row["resume_ms"] = {"min": min(res), "p50": pct(res, 50), "mean": round(st.mean(res), 1),
                            "p90": pct(res, 90), "max": max(res)}
    ex = [s["exec_ms"] for s in samples if s.get("exec_ms") is not None]
    if ex:
        row["exec_ms"] = {"min": min(ex), "p50": pct(ex, 50), "max": max(ex)}
    return row

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=50)
    ap.add_argument("--warmup", type=int, default=5)
    ap.add_argument("--json")
    ap.add_argument(
        "--base",
        default=DEFAULT_BASE,
        help="base to boot: a built flavor (base-alpine, base-sqfs) or an "
             "imported image as oci:<name>",
    )
    a = ap.parse_args()

    # environment / provenance (pulled from a real run + /proc)
    probe = one_run([], a.base)
    def readfile(p, pat=None):
        try:
            for line in open(p):
                if pat is None or pat in line:
                    return line.split(":", 1)[-1].strip() if pat else line.strip()
        except OSError: return None
    env = {
        "isopod_version": subprocess.run([ISOPOD, "--version"], capture_output=True, text=True).stdout.strip(),
        "cpu": readfile("/proc/cpuinfo", "model name"),
        "kernel": subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip(),
        "fc_binary": probe.get("fc_binary"),
        "guest_kernel": "vmlinux-6.18.36",
        "vcpus": probe.get("vcpus"), "mem_mib": probe.get("mem_mib"),
        # The base is provenance, not a footnote: a table that does not say
        # which root it booted is a table two runs cannot be compared across.
        "base": a.base,
        "base_reported": probe.get("rootfs_flavor"),
    }

    results = []
    for name, extra in CATS.items():
        print(f"[{name}] warmup x{a.warmup} ...", file=sys.stderr, flush=True)
        for _ in range(a.warmup):
            one_run(extra, a.base)
        samples = []
        t0 = time.monotonic()
        for i in range(a.iters):
            samples.append(one_run(extra, a.base))
            if (i + 1) % 10 == 0:
                print(f"[{name}] {i+1}/{a.iters}", file=sys.stderr, flush=True)
        wall = time.monotonic() - t0
        row = summarize(name, samples)
        row["wall_s"] = round(wall, 1)
        results.append(row)

    out = {"env": env, "base": a.base, "iters": a.iters, "warmup": a.warmup, "results": results}
    js = json.dumps(out, indent=2)
    if a.json:
        open(a.json, "w").write(js)
    print(js)

    # human table -> stderr
    print("\n=== isopod latency (ms) ===", file=sys.stderr)
    print(f"{'category':8} {'path':5} {'n':>3}  {'min':>5} {'p50':>5} {'mean':>5} {'p90':>5} {'p99':>5} {'max':>5}   {'VMs/min':>7}", file=sys.stderr)
    for r in results:
        t = r["total_ms"]
        print(f"{r['category']:8} {r['path']:5} {r['n']:>3}  {t['min']:>5} {t['p50']:>5} {t['mean']:>5} {t['p90']:>5} {t['p99']:>5} {t['max']:>5}   {r['seq_vms_per_min']:>7}", file=sys.stderr)
    for r in results:
        if "resume_ms" in r:
            rm = r["resume_ms"]
            print(f"  {r['category']} resume_ms: min {rm['min']} / p50 {rm['p50']} / mean {rm['mean']} / p90 {rm['p90']} / max {rm['max']}", file=sys.stderr)

if __name__ == "__main__":
    main()
