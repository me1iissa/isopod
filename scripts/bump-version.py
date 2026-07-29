#!/usr/bin/env python3
"""Bump the workspace version, or verify the one that is already there.

The Version guard in CI enforces three things that are easy to get wrong by
hand, and this script exists so they are got right by construction instead:

1. The workspace version and `.claude-plugin/plugin.json` move together.
2. The version goes UP, by exactly one step of the level you asked for.
3. The tag lands on the commit that carries the bump.

(3) is the one that has actually bitten. `git tag -a vX.Y.Z` with no commit
argument tags whatever HEAD happens to be, and when work spans git worktrees
that is frequently a different branch. On 2026-07-29 it put v0.13.1 on v0.13.0's
commit: the release shipped .deb and .rpm packages declaring the previous
version inside a tarball named for the new one, and CI then failed four times
with "code changed but the version was not bumped" — which was true, and
pointed at a bump that had already been made.

Usage:
    scripts/bump-version.py patch|minor|major   # bump, leave the commit to you
    scripts/bump-version.py --check             # verify the current state
    scripts/bump-version.py --tag               # tag HEAD, only if HEAD is the bump

Pre-1.0 semantics, per CONTRIBUTING.md: minor = features or breaking changes,
patch = fixes.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CARGO = ROOT / "Cargo.toml"
PLUGIN = ROOT / ".claude-plugin" / "plugin.json"
CHANGELOG = ROOT / "CHANGELOG.md"

VER_RE = re.compile(r'^version = "([^"]+)"', re.M)
# Pre-release spellings such as 0.13.0-preview.1 are valid here; the preview
# branch relies on them, so the parser must not reject what the repo ships.
SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$")


def fail(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    raise SystemExit(1)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    ).stdout.strip()


def read_workspace_version() -> str:
    m = VER_RE.search(CARGO.read_text())
    if not m:
        fail(f"no `version = ` line in {CARGO}")
    return m.group(1)


def read_plugin_version() -> str:
    return json.loads(PLUGIN.read_text())["version"]


def parse(v: str) -> tuple[int, int, int, str | None]:
    m = SEMVER_RE.match(v)
    if not m:
        fail(f"{v!r} is not a version this script understands")
    return int(m[1]), int(m[2]), int(m[3]), m[4]


def bumped(v: str, level: str) -> str:
    major, minor, patch, pre = parse(v)
    # A pre-release resolves to its own release rather than stepping past it:
    # 0.13.0-preview.1 --patch is 0.13.0, not 0.13.1. Anything else silently
    # skips the version the preview line was previewing.
    if pre:
        return f"{major}.{minor}.{patch}"
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def newest_tag() -> str | None:
    tags = [t[1:] for t in git("tag", "-l", "v*").splitlines() if t.startswith("v")]
    if not tags:
        return None
    return sorted(tags, key=lambda t: parse(t)[:3])[-1]


def check(expect: str | None = None) -> int:
    """Verify lockstep, monotonicity and tag placement. Returns an exit code."""
    ws, plug = read_workspace_version(), read_plugin_version()
    problems: list[str] = []

    if ws != plug:
        problems.append(f"plugin.json says {plug}, Cargo.toml says {ws} — they move together")
    if expect and ws != expect:
        problems.append(f"expected {expect}, found {ws}")

    latest = newest_tag()
    if latest:
        if parse(ws)[:3] < parse(latest)[:3]:
            problems.append(f"version {ws} is lower than already-tagged v{latest}")
        # The check that matters: if this version is tagged, the tag must sit on
        # a commit that declares it.
        sha = git("rev-list", "-n1", f"v{ws}")
        if sha:
            tagged = VER_RE.search(git("show", f"{sha}:Cargo.toml"))
            tv = tagged.group(1) if tagged else "<unreadable>"
            if tv != ws:
                problems.append(
                    f"tag v{ws} points at {sha[:7]}, which declares {tv} — "
                    f"the tag is on the wrong commit"
                )

    if f"## [{ws}]" not in CHANGELOG.read_text():
        problems.append(f"CHANGELOG.md has no `## [{ws}]` section")

    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if not problems:
        print(f"ok: {ws}, plugin.json in lockstep, changelog present, tag placement sound")
    return 1 if problems else 0


def write_version(new: str) -> None:
    cargo = CARGO.read_text()
    old = read_workspace_version()
    if cargo.count(f'version = "{old}"') != 1:
        fail(f'expected exactly one `version = "{old}"` in Cargo.toml')
    CARGO.write_text(cargo.replace(f'version = "{old}"', f'version = "{new}"', 1))

    plugin = PLUGIN.read_text()
    if plugin.count(f'"version": "{old}"') != 1:
        fail(f'expected exactly one `"version": "{old}"` in plugin.json')
    PLUGIN.write_text(plugin.replace(f'"version": "{old}"', f'"version": "{new}"', 1))

    subprocess.run(
        ["cargo", "update", "--manifest-path", str(CARGO), "--workspace", "--offline"],
        check=False,
        capture_output=True,
    )


def do_tag() -> int:
    """Tag HEAD — but only if HEAD is the commit that carries this version."""
    ws = read_workspace_version()
    head = git("rev-parse", "HEAD")
    declared = VER_RE.search(git("show", f"{head}:Cargo.toml"))
    if not declared or declared.group(1) != ws:
        fail(
            f"HEAD ({head[:7]}) declares "
            f"{declared.group(1) if declared else '<unreadable>'}, not {ws}. "
            "Commit the bump first; tagging the wrong commit is the whole reason "
            "this script exists."
        )
    if git("rev-list", "-n1", f"v{ws}"):
        fail(f"v{ws} already exists at {git('rev-list', '-n1', f'v{ws}')[:7]}")
    # Explicit sha, never a bare `git tag -a vX.Y.Z`.
    subprocess.run(["git", "-C", str(ROOT), "tag", "-a", f"v{ws}", head, "-m", ws], check=True)
    landed = git("rev-list", "-n1", f"v{ws}")
    if landed != head:
        fail(f"tag landed on {landed[:7]}, expected {head[:7]}")
    print(f"tagged v{ws} at {head[:7]} (verified)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("level", nargs="?", choices=["patch", "minor", "major"])
    ap.add_argument("--check", action="store_true", help="verify the current state and exit")
    ap.add_argument("--tag", action="store_true", help="tag HEAD if it carries this version")
    args = ap.parse_args()

    if args.check:
        return check()
    if args.tag:
        return do_tag()
    if not args.level:
        ap.error("give a level (patch|minor|major), or --check, or --tag")

    old = read_workspace_version()
    if read_plugin_version() != old:
        fail(f"plugin.json ({read_plugin_version()}) and Cargo.toml ({old}) disagree; fix that first")

    new = bumped(old, args.level)
    write_version(new)
    print(f"{old} -> {new}  (Cargo.toml, plugin.json, Cargo.lock)")
    print(f"next: add a `## [{new}]` CHANGELOG section, commit, then")
    print("      scripts/bump-version.py --tag")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
