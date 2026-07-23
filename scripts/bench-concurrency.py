#!/usr/bin/env python3
"""isopod concurrency benchmark — throughput and latency under parallel load.

isopod claims independent network slots, so many disposable microVMs can run at
once. This sweeps a fixed batch of `boot -> exec -> destroy` runs through a bounded
worker pool at increasing concurrency and measures BOTH sides honestly:
  - aggregate throughput (disposable VMs per minute), and
  - per-run latency (does each individual sandbox get slower under load?).

A batch of N runs drained by C workers takes wall time ~ (N/C) * per-run-latency;
throughput = N / wall. We report the speedup vs C=1 and where it stops scaling,
plus any failures or cold-path fallbacks (so saturation is visible, not hidden).

Usage:  python3 scripts/bench-concurrency.py [--batch N] [--levels 1,2,4,6,8]
Prints a JSON summary to stdout and a human table to stderr.
"""
import argparse, json, statistics as st, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

ARGS = ["run", "--stage", "base", "--base", "base-alpine", "--", "echo", "isopod-bench"]

def one_run():
    t0 = time.monotonic()
    p = subprocess.run(["isopod"] + ARGS, capture_output=True, text=True, timeout=180)
    wall_ms = (time.monotonic() - t0) * 1000
    try:
        d = json.loads(p.stdout)
    except json.JSONDecodeError:
        return {"ok": False, "err": (p.stdout or p.stderr)[:160], "client_wall_ms": wall_ms}
    return {"ok": bool(d.get("ok")) and d.get("exit_code") == 0,
            "total_ms": d.get("total_ms"), "path": d.get("path"),
            "slot": d.get("slot"), "client_wall_ms": wall_ms}

def pct(xs, q):
    xs = sorted(xs)
    if not xs: return None
    return xs[min(len(xs) - 1, int(round(q / 100 * (len(xs) - 1))))]

def run_level(concurrency, batch):
    # small warmup so slot/pool state is hot and not counted
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(lambda _: one_run(), range(concurrency)))
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        res = list(ex.map(lambda _: one_run(), range(batch)))
    wall = time.monotonic() - t0
    ok = [r for r in res if r["ok"]]
    tot = [r["total_ms"] for r in ok if r.get("total_ms") is not None]
    warm = sum(1 for r in ok if r.get("path") == "warm")
    return {
        "concurrency": concurrency,
        "batch": batch,
        "completed": len(ok),
        "failed": batch - len(ok),
        "warm": warm, "cold": len(ok) - warm,
        "wall_s": round(wall, 2),
        "throughput_vms_min": round(len(ok) / wall * 60, 1),
        "latency_ms": {
            "p50": pct(tot, 50), "mean": round(st.mean(tot), 1) if tot else None,
            "p90": pct(tot, 90), "p99": pct(tot, 99), "max": max(tot) if tot else None,
        },
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", type=int, default=48)
    ap.add_argument("--levels", default="1,2,4,6,8")
    ap.add_argument("--json")
    a = ap.parse_args()
    levels = [int(x) for x in a.levels.split(",")]

    env = {
        "isopod_version": subprocess.run(["isopod", "--version"], capture_output=True, text=True).stdout.strip(),
        "cpu": next((l.split(":",1)[1].strip() for l in open("/proc/cpuinfo") if "model name" in l), None),
        "host_vcpus": int(subprocess.run(["nproc"], capture_output=True, text=True).stdout.strip()),
        "kernel": subprocess.run(["uname","-r"], capture_output=True, text=True).stdout.strip(),
        "net_slots": None,
    }
    try:
        import glob
        env["net_slots"] = json.load(open(glob.glob(__import__("os").path.expanduser("~/.isopod/net/slots.json"))[0]))["slot_count"]
    except Exception:
        pass

    rows = []
    for c in levels:
        print(f"[c={c}] draining {a.batch} runs through {c} workers ...", file=sys.stderr, flush=True)
        rows.append(run_level(c, a.batch))

    base = next((r["throughput_vms_min"] for r in rows if r["concurrency"] == 1), rows[0]["throughput_vms_min"])
    for r in rows:
        r["speedup_vs_c1"] = round(r["throughput_vms_min"] / base, 2)

    out = {"env": env, "batch": a.batch, "results": rows}
    js = json.dumps(out, indent=2)
    if a.json: open(a.json, "w").write(js)
    print(js)

    print(f"\n=== isopod concurrency (host: {env['host_vcpus']} vCPUs, {env['net_slots']} net slots) ===", file=sys.stderr)
    hdr = f"{'conc':>4} {'done':>4} {'fail':>4} {'wall_s':>6} {'VMs/min':>8} {'speedup':>7} | {'p50':>4} {'p90':>4} {'p99':>4} {'max':>4} (ms)"
    print(hdr, file=sys.stderr); print("-"*len(hdr), file=sys.stderr)
    for r in rows:
        L = r["latency_ms"]
        print(f"{r['concurrency']:>4} {r['completed']:>4} {r['failed']:>4} {r['wall_s']:>6} {r['throughput_vms_min']:>8} {r['speedup_vs_c1']:>6}x | {L['p50']:>4} {L['p90']:>4} {L['p99']:>4} {L['max']:>4}", file=sys.stderr)

if __name__ == "__main__":
    main()
