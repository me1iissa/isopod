#!/usr/bin/env python3
"""Assemble the digest CI posts on every pull request.

Lives in `.github/` rather than `scripts/` on purpose. `scripts/` is listed in
CI's CODE_PATHS, so a change there demands a workspace version bump; CI
plumbing is not a code wave and should not force one.

Everything reported here is derived from artefacts the PR jobs already produce.
Nothing is fetched, nothing is uploaded to a third party, and no number is
invented: a section whose input is missing says so rather than printing a zero.
Reads its inputs from argv, writes Markdown to stdout, and exits non-zero only
if it was given something it cannot parse — a broken digest must not be able to
redden a build whose code is fine.

Deliberately NOT reported: binary-size deltas. Measuring one honestly means
building the base ref as well as the head, which doubles the wall-clock of
every pull request to track a number that moves on toolchain updates as readily
as on a change to this tree.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

MARKER = "<!-- isopod-ci-digest -->"


def read_packages(path: Path) -> dict[str, str]:
    """Map every EXTERNAL locked package to its version, or {} when absent.

    The workspace's own crates are excluded. They carry the workspace version,
    so every release bump would otherwise report nine "dependency changes" that
    tell a reviewer nothing — burying the one line that matters. Cargo marks
    them by omission: a package with no `source` key was resolved from a path,
    which for this lockfile means it is a member of this workspace.

    The base lockfile is fetched from the merge base and may legitimately not
    exist (a first commit, a shallow fetch that missed it). That is a reason to
    omit the dependency section, not to fail.
    """
    if not path or not path.is_file():
        return {}
    with path.open("rb") as fh:
        doc = tomllib.load(fh)
    return {
        p["name"]: p.get("version", "?")
        for p in doc.get("package", [])
        if "name" in p and "source" in p
    }


def dependency_section(base: dict[str, str], head: dict[str, str]) -> str:
    if not base or not head:
        return (
            "### Dependencies\n\n"
            "_Not compared — a lockfile for one side was unavailable._\n"
        )

    added = sorted(set(head) - set(base))
    removed = sorted(set(base) - set(head))
    changed = sorted(n for n in set(base) & set(head) if base[n] != head[n])

    if not (added or removed or changed):
        return f"### Dependencies\n\nUnchanged — {len(head)} locked crates.\n"

    lines = ["### Dependencies", ""]
    if added:
        lines.append(f"**Added ({len(added)})**")
        lines += [f"- `{n}` {head[n]}" for n in added]
        lines.append("")
    if removed:
        lines.append(f"**Removed ({len(removed)})**")
        lines += [f"- `{n}` {base[n]}" for n in removed]
        lines.append("")
    if changed:
        lines.append(f"**Version changed ({len(changed)})**")
        lines += [f"- `{n}` {base[n]} → {head[n]}" for n in changed]
        lines.append("")
    lines.append(
        f"Total locked crates: {len(base)} → {len(head)}. "
        "Every addition widens the trusted computing base of a tool whose whole "
        "job is isolation; `cargo deny` gates licences and sources, not intent."
    )
    return "\n".join(lines) + "\n"


# `cargo llvm-cov --summary-only` prints a fixed-width table whose last row is
# TOTAL, with four percentages in column order: regions, functions, lines,
# branches. Parsing positionally would break the first time a column is added,
# so pull the percentages out and index them by count.
PCT = re.compile(r"(\d+\.\d+)%")


def coverage_section(path: Path | None, code_changed: bool) -> tuple[str, str | None]:
    """Return (markdown, headline_line_pct)."""
    if not code_changed:
        return (
            "### Coverage\n\n"
            "_Not measured — this pull request changes no code under `crates/`._\n",
            None,
        )
    if not path or not path.is_file():
        return (
            "### Coverage\n\n"
            "_Not measured — the coverage step produced no summary._\n",
            None,
        )

    total = next(
        (ln for ln in path.read_text(errors="replace").splitlines() if ln.startswith("TOTAL")),
        None,
    )
    if not total:
        return (
            "### Coverage\n\n_Not measured — no TOTAL row in the summary._\n",
            None,
        )

    pcts = PCT.findall(total)
    if len(pcts) < 3:
        return (
            "### Coverage\n\n_Not measured — the TOTAL row did not parse._\n",
            None,
        )

    regions, functions, lines_pct = pcts[0], pcts[1], pcts[2]
    branches = pcts[3] if len(pcts) > 3 else None

    body = [
        "### Coverage",
        "",
        "| | Covered |",
        "|---|---|",
        f"| lines | **{lines_pct}%** |",
        f"| functions | {functions}% |",
        f"| regions | {regions}% |",
    ]
    if branches:
        body.append(f"| branches | {branches}% |")
    body += [
        "",
        "> This number is **advisory and structurally low**. The `#[ignore]`d "
        "suite — real boots, the jail, VM lifecycle, the egress-enforcement "
        "ledger — does not run in this job, so the best-defended paths in the "
        "tree are absent from it. Not for want of `/dev/kvm`: a hosted runner "
        "has one, and the full-boot probe booted a guest on it in 84 ms. "
        "Reaching those tests costs a vendored Firecracker build and four guest "
        "images, which does not belong on the pull-request path. Nothing gates "
        "on this percentage, and nothing should.",
    ]
    return "\n".join(body) + "\n", lines_pct


def badge_json(line_pct: str) -> str:
    """A shields.io endpoint document for the line-coverage badge.

    The label is `coverage (unit)`, not `coverage`. A badge is four words wide
    and cannot carry the caveat the digest spells out, so the qualification goes
    in the label itself where it cannot be separated from the number. Reading
    `coverage (unit) 85%` and concluding the sandbox is 85% proven is a mistake
    the label at least makes visible.

    Thresholds are set here rather than left to a default, which would colour an
    advisory number as a pass or a failure it was never measuring.
    """
    pct = float(line_pct)
    if pct >= 80:
        colour = "brightgreen"
    elif pct >= 70:
        colour = "green"
    elif pct >= 60:
        colour = "yellow"
    else:
        colour = "orange"
    import json

    return json.dumps(
        {
            "schemaVersion": 1,
            "label": "coverage (unit)",
            "message": f"{pct:.1f}%",
            "color": colour,
        }
    )


def version_section(base_ver: str, head_ver: str, code_changed: bool) -> str:
    if base_ver == head_ver:
        if code_changed:
            verdict = (
                f"⚠️ Code changed but the version is still `{head_ver}`. "
                "The Version guard job fails on this — bump with "
                "`python3 scripts/bump-version.py --patch` (or `--minor`)."
            )
        else:
            verdict = (
                f"No bump needed. The version stays `{head_ver}` because nothing "
                "under `crates/`, `Cargo.toml`, `Cargo.lock`, `vendor/` or "
                "`scripts/` changed."
            )
    else:
        verdict = f"Bumped `{base_ver}` → `{head_ver}`."
        if not code_changed:
            verdict += " (No code changed, so this bump was not required.)"

    return f"### Version\n\n{verdict}\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-lock", type=Path)
    ap.add_argument("--head-lock", type=Path)
    ap.add_argument("--base-version", default="")
    ap.add_argument("--head-version", default="")
    ap.add_argument("--coverage", type=Path)
    ap.add_argument("--code-changed", default="false")
    ap.add_argument("--run-url", default="")
    ap.add_argument(
        "--badge-out",
        type=Path,
        help="Also write a shields.io endpoint document here. Written only when a "
        "percentage was actually parsed, so a failed coverage run leaves the "
        "previous badge standing rather than replacing it with a lie.",
    )
    args = ap.parse_args()

    code_changed = args.code_changed.strip().lower() in {"true", "1", "yes"}

    cov_md, headline = coverage_section(args.coverage, code_changed)

    if args.badge_out and headline:
        args.badge_out.write_text(badge_json(headline))

    out = [MARKER, "## CI digest", ""]
    if headline:
        out.append(f"**{headline}% line coverage** · advisory, see the caveat below.")
        out.append("")
    out.append(version_section(args.base_version, args.head_version, code_changed))
    out.append(dependency_section(read_packages(args.base_lock), read_packages(args.head_lock)))
    out.append(cov_md)
    if args.run_url:
        out.append(f"\n---\n\n[Full run and job summaries]({args.run_url}) · "
                   "this comment is rewritten in place on every push.")

    sys.stdout.write("\n".join(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
