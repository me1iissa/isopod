#!/usr/bin/env python3
"""Assert that a fixed set of deliberate breakages makes the test suite fail.

Ordinary CI proves the tests pass against correct code. It cannot tell the
difference between a test that checks something and a test that checks nothing,
and this project has shipped the latter repeatedly: a symlink regression test
whose path spelling missed the escape it was named for, an `fstat` guard whose
four fixtures all failed at `open()` before the guard ran, and a `copy_out`
publish path with no test at all — deleting its mode mask outright left the suite
green while a guest-chosen setuid bit reached a host file.

Each mutation below is a one-line edit that reintroduces a defect this project
actually shipped, paired with the test that should catch it. Applying it to a
scratch copy of the tree and running the suite answers the question CI otherwise
cannot: does anything notice?

A mutation that no longer fails means its guard has been removed, weakened, or
refactored past — either the code regressed or the test stopped reaching it.
Both are worth failing a build over.

Usage:
    python3 scripts/mutation-check.py            # all mutations
    python3 scripts/mutation-check.py --list     # names only, no work
    python3 scripts/mutation-check.py --only NAME[,NAME...]
    python3 scripts/mutation-check.py --json     # machine-readable summary

Mutations are applied to a `git archive HEAD` export, not to the working tree —
so a mutation aimed at uncommitted code reports STALE against a file that does
not have it yet. Commit (or stash) before running.

Exit status is 0 only when every mutation was caught.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Long enough for a cold build in the scratch copy on a slow runner; a mutation
# that hangs the suite is itself a finding, so this must not be generous.
BUILD_TIMEOUT_S = 1800
TEST_TIMEOUT_S = 900


@dataclass
class Mutation:
    """One deliberate breakage and the defect it stands for."""

    name: str
    file: str
    # `old` must appear exactly `count` times in `file`, or the mutation is stale
    # and we fail loudly rather than silently testing nothing.
    old: str
    new: str
    defect: str
    count: int = 1
    filter: str = ""
    field_names: tuple = field(default=(), repr=False)


MUTATIONS = [
    Mutation(
        name="copy-out-truncates-early",
        file="crates/core/src/agent.rs",
        old=".write(true)\n        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)\n        .open(dest)",
        new=".write(true)\n        .create(true)\n        .truncate(true)\n        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)\n        .open(dest)",
        defect=(
            "The copy-out gate opens the destination O_CREAT|O_TRUNC again, so a "
            "copy whose guest source does not exist destroys the host file it "
            "names. Shipped in 0.11.0; found by the fourth review pass."
        ),
        filter="agent::",
    ),
    Mutation(
        name="staging-file-leaks",
        file="crates/core/src/agent.rs",
        old="let _ = std::fs::remove_file(path);",
        new="let _ = path;",
        defect=(
            "The staging file's Drop stops unlinking, so every failed copy leaves "
            "a .part file behind — one per attempt, each bounded only by the "
            "copy-out ceiling. Found by the fifth review pass."
        ),
        filter="agent::",
    ),
    Mutation(
        name="copy-out-mode-unmasked",
        file="crates/core/src/agent.rs",
        old="sink.commit(host_mode_for(outcome.mode)).await?;",
        new="sink.commit(outcome.mode).await?;",
        defect=(
            "The guest's chosen mode reaches the host file unmasked, so `chmod "
            "6777` before a copy-out lands setuid and setgid to the operator. The "
            "publish path had no test at all until the fifth pass added one."
        ),
        filter="agent::",
    ),
    Mutation(
        name="staging-name-adopted",
        file="crates/core/src/agent.rs",
        old=".create_new(true)\n        .mode(0o600)",
        new=".create(true)\n        .mode(0o600)",
        defect=(
            "The staging open loses O_EXCL, so it adopts and truncates whatever "
            "sits at the staging name — a leftover from a killed run, or a file "
            "planted there."
        ),
        filter="agent::",
    ),
    Mutation(
        name="staging-name-overflows",
        file="crates/core/src/agent.rs",
        old="    let mut keep = NAME_MAX.saturating_sub(suffix_len + 1).min(base.len());",
        new="    let mut keep = base.len();",
        defect=(
            "The staging name is no longer clamped to NAME_MAX, so a destination "
            "basename the kernel accepts produces a staging name it refuses."
        ),
        filter="agent::",
    ),
    Mutation(
        name="staging-name-splits-utf8",
        file="crates/core/src/agent.rs",
        old="    while keep > 0 && !base.is_char_boundary(keep) {\n        keep -= 1;\n    }\n",
        new="",
        defect=(
            "The name clamp stops walking back to a character boundary, so a "
            "multibyte destination name long enough to clamp panics on a slice. "
            "Caught only by a test that sweeps every suffix length: the "
            "truncation point depends on the pid's digit count, so a single "
            "sampled name passes or fails by luck — this mutation survived CI "
            "once for exactly that reason."
        ),
        filter="agent::",
    ),
    Mutation(
        name="staging-name-unclamped-length",
        file="crates/core/src/agent.rs",
        old="    let mut keep = NAME_MAX.saturating_sub(suffix_len + 1).min(base.len());",
        new="    let mut keep = NAME_MAX.saturating_sub(suffix_len).min(base.len());",
        defect=(
            "The clamp forgets the leading dot, so a staging name lands exactly "
            "one byte over NAME_MAX — the off-by-one that only shows up at the "
            "boundary, on a destination the kernel would have accepted."
        ),
        filter="agent::",
    ),
    Mutation(
        name="device-destination-staged",
        file="crates/core/src/agent.rs",
        old="            if kind.is_file() {",
        new="            if true {",
        defect=(
            "A device destination is staged and renamed over, so a copy-out to "
            "/dev/null replaces the node with a regular file."
        ),
        filter="agent::",
    ),
    Mutation(
        name="slot-lock-not-held",
        file="crates/core/src/net.rs",
        old="if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {",
        new="if true {",
        defect=(
            "Slot claiming stops taking the flock, so two concurrent runs claim "
            "the same tap and /30. The pre-0.11.0 staleness heuristic had exactly "
            "this effect whenever its lockfile parse failed."
        ),
        filter="net::",
    ),
    Mutation(
        name="pinned-host-floor-bypassed",
        file="crates/core/src/net/broker.rs",
        old="        let ok = (spec.allow_loopback && ip.is_loopback())\n            || super::egress::is_dialable(&ip, spec.allow_private);",
        new="        let ok = true;\n        let _ = &ip;",
        defect=(
            "The pinned-host floor accepts every address, so a credential pinned "
            "to the metadata service or to loopback starts a run and spends its "
            "token there. 0.11.0 shipped a version of this guard that skipped any "
            "spelling `IpAddr::from_str` could not parse — decimal, hex and "
            "short-form IPv4 all walked past it."
        ),
        filter="net::",
    ),
    Mutation(
        name="pinned-host-parser-disagrees",
        file="crates/core/src/net/broker.rs",
        old="    if dialed != host {",
        new="    if false {",
        defect=(
            "The guard stops requiring that the URL parser round-trips the stored "
            "host unchanged, so `2852039166` is stored and logged as itself while "
            "the dialer reaches 169.254.169.254. This is the exact defect the "
            "third review pass found."
        ),
        filter="net::",
    ),
    Mutation(
        name="base-skew-accepted",
        file="crates/core/src/stage.rs",
        old="    if stamped == present {",
        new="    if true {",
        defect=(
            "The base check accepts any content id, so a stage forks onto an "
            "image rebuilt since it was committed — the overlay mounts, the run "
            "succeeds, and the chain no longer matches the root beneath it."
        ),
        filter="stage::",
    ),
    Mutation(
        name="base-stamp-not-recorded",
        file="crates/core/src/stage.rs",
        old="        base_sha256: base.sha256.clone(),",
        new="        base_sha256: None,",
        defect=(
            "A commit stops recording the base build it was made on. Nothing "
            "fails at commit time: every stage simply becomes unstamped, which "
            "is indistinguishable from a pre-0.12.0 stage and silently disables "
            "the fork check for good."
        ),
        filter="stage::",
    ),
    Mutation(
        name="layers-mountpoint-not-shipped",
        file="crates/core/src/image/rootfs.rs",
        old='const BASE_OVERLAY_DIRS: &[&str] = &["overlay", "mnt", "layers"];',
        new='const BASE_OVERLAY_DIRS: &[&str] = &["overlay", "mnt"];',
        defect=(
            "The base image stops shipping /layers. The guest mounts a tmpfs "
            "over it to create the per-layer mountpoints, and a read-only "
            "squashfs root cannot grow the directory — so every stage fork "
            "fails to assemble its overlay and silently boots the bare base "
            "instead, which is finding #26's failure mode with a new cause."
        ),
        filter="image::",
    ),
    Mutation(
        name="owner-token-format-drifts",
        file="crates/core/src/vm/registry.rs",
        old='        Some(started) => format!("{pid} {started}"),',
        new='        Some(started) => format!("{pid}:{started}"),',
        defect=(
            "The token writer changes separator while the parser still splits "
            "on whitespace, so every owner.pid reads as a bare pid — the weaker "
            "check this pairing exists to replace. Nothing errors; `vm gc` just "
            "starts trusting recycled pids again."
        ),
        filter="vm::registry::",
    ),
    Mutation(
        name="base-skew-opt-in-covers-flavors",
        file="crates/core/src/stage.rs",
        old="                if flavor_skew || !allow_base_skew {",
        new="                if !allow_base_skew {",
        defect=(
            "The opt-out for a rebuilt base starts excusing a different base "
            "*flavor* too, so a busybox chain can be stacked onto an Alpine one. "
            "The escape hatch is for layers that are stale, not for layers that "
            "belong to another root."
        ),
        filter="stage::",
    ),
]


def run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str]:
    """Run a command, returning (exit status, combined output)."""
    try:
        p = subprocess.run(
            cmd,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, out + f"\n[timed out after {timeout}s]"


def worktree(dest: Path) -> None:
    """Export the committed tree, so uncommitted edits cannot skew a run."""
    tar = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=REPO,
        stdout=subprocess.PIPE,
        check=True,
    )
    dest.mkdir(parents=True, exist_ok=True)
    subprocess.run(["tar", "-x", "-C", str(dest)], input=tar.stdout, check=True)


def apply(mut: Mutation, tree: Path) -> None:
    """Apply one mutation, or raise if it no longer matches the source."""
    path = tree / mut.file
    text = path.read_text()
    found = text.count(mut.old)
    if found != mut.count:
        raise LookupError(
            f"{mut.name}: pattern occurs {found} time(s) in {mut.file}, expected "
            f"{mut.count}. The code moved; update the mutation rather than "
            f"deleting it — a stale mutation tests nothing."
        )
    path.write_text(text.replace(mut.old, mut.new))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print mutation names and exit")
    ap.add_argument("--only", default="", help="comma-separated subset to run")
    ap.add_argument("--json", action="store_true", help="emit a JSON summary")
    args = ap.parse_args()

    if args.list:
        for m in MUTATIONS:
            print(f"{m.name}\n    {m.defect}\n")
        return 0

    selected = MUTATIONS
    if args.only:
        want = {n.strip() for n in args.only.split(",") if n.strip()}
        unknown = want - {m.name for m in MUTATIONS}
        if unknown:
            print(f"unknown mutation(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2
        selected = [m for m in MUTATIONS if m.name in want]

    root = Path(tempfile.mkdtemp(prefix="isopod-mutation-"))
    results = []
    try:
        tree = root / "tree"
        print(f"exporting HEAD to {tree}", flush=True)
        worktree(tree)

        # Warm the build once so each mutation pays only for what it changed.
        print("warming the build cache (cold build, this is the slow part)", flush=True)
        rc, out = run(["cargo", "test", "--workspace", "--no-run"], tree, BUILD_TIMEOUT_S)
        if rc != 0:
            print(out[-4000:], file=sys.stderr)
            print("FAIL: the unmutated tree does not build", file=sys.stderr)
            return 1

        rc, out = run(["cargo", "test", "--workspace"], tree, TEST_TIMEOUT_S)
        if rc != 0:
            print(out[-4000:], file=sys.stderr)
            print("FAIL: the unmutated tree does not pass its own tests", file=sys.stderr)
            return 1
        print("baseline green\n", flush=True)

        pristine = {}
        for m in selected:
            pristine.setdefault(m.file, (tree / m.file).read_text())

        for m in selected:
            print(f"--- {m.name}", flush=True)
            try:
                apply(m, tree)
            except LookupError as e:
                print(f"    STALE: {e}", flush=True)
                results.append({"name": m.name, "outcome": "stale", "detail": str(e)})
                continue

            cmd = ["cargo", "test", "--workspace"]
            if m.filter:
                cmd = ["cargo", "test", "-p", "isopod-core", "--lib", m.filter]
            rc, out = run(cmd, tree, TEST_TIMEOUT_S)
            (tree / m.file).write_text(pristine[m.file])

            if rc == 124:
                # A mutant that hangs is not caught: CI wedges instead of failing.
                print("    NOT CAUGHT (the suite hung rather than failing)", flush=True)
                results.append({"name": m.name, "outcome": "hung"})
            elif rc == 0:
                print("    NOT CAUGHT (suite still green)", flush=True)
                results.append({"name": m.name, "outcome": "survived"})
            elif "error[E" in out or "error: could not compile" in out:
                # A mutation that stops compiling proves nothing about the tests.
                print("    STALE (mutated tree does not compile)", flush=True)
                results.append({"name": m.name, "outcome": "stale", "detail": "no compile"})
            else:
                killers = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)))
                shown = ", ".join(killers[:3]) or "(suite failed)"
                print(f"    caught by {shown}", flush=True)
                results.append({"name": m.name, "outcome": "caught", "by": killers})
    finally:
        shutil.rmtree(root, ignore_errors=True)

    bad = [r for r in results if r["outcome"] != "caught"]
    print()
    if args.json:
        print(json.dumps({"results": results, "ok": not bad}, indent=2))
    caught = len(results) - len(bad)
    print(f"{caught}/{len(results)} mutations caught")
    for r in bad:
        print(f"  {r['outcome'].upper():9} {r['name']}")
    if bad:
        print(
            "\nA surviving mutation means the guard it breaks is not defended by any "
            "test.\nA stale one means the code moved and the mutation needs updating — "
            "not deleting.",
            file=sys.stderr,
        )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
