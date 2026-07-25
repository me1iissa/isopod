#!/usr/bin/env python3
"""Build the isopod documentation site into `_site/`.

The repo's Markdown is the single source of truth: this script renders it, it
never owns it. No YAML front matter is injected into `docs/*.md`, because GitHub
renders front matter as a stray table at the top of the file and the docs must
stay pleasant to read in the repository itself. Page titles and ordering live
here instead.

Output is flat (`_site/getting-started.html`, not `_site/getting-started/`) so
every page can reference `assets/style.css` and its siblings with a plain
relative path. That makes the site work identically at a user site, a project
site under `/isopod/`, and `file://` during local review — no `baseurl` to get
wrong.

One-shot, non-interactive, prints a JSON summary. Run it with no arguments:

    python3 scripts/build-docs-site.py [--out _site] [--check]

`--check` verifies every internal link resolves and exits non-zero if not, which
is what CI runs before deploying.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import markdown
except ImportError:  # pragma: no cover - guidance, not logic
    print(
        json.dumps(
            {
                "ok": False,
                "error": "python-markdown is not installed: pip install markdown pygments",
            }
        )
    )
    sys.exit(1)

REPO = Path(__file__).resolve().parent.parent
SITE = REPO / "site"


@dataclass(frozen=True)
class Page:
    """One rendered documentation page."""

    source: str  # repo-relative Markdown path
    slug: str  # output basename, without .html
    title: str  # nav + <title>
    group: str  # sidebar grouping
    blurb: str = ""  # <meta name="description">


# Order here is the order in the sidebar. Groups are emitted in first-seen order.
PAGES: list[Page] = [
    Page("docs/getting-started.md", "getting-started", "Get started", "Start",
         "Install isopod, build its guest images, provision host networking, and make your first sandboxed run."),
    Page("docs/mcp-usage.md", "mcp-usage", "MCP usage", "Start",
         "Register isopod as an MCP server for Claude Code and drive it with sandbox_run."),
    Page("docs/sandbox-build.md", "sandbox-build", "Building in isopod", "Start",
         "Building isopod inside its own sandboxes."),

    Page("SECURITY.md", "security", "Security model", "Security",
         "isopod's threat model, isolation boundary, what holds, and what is explicitly not claimed."),
    Page("docs/egress-ledger.md", "egress-ledger", "Egress ledger", "Security",
         "Ten attempted egress bypasses run against a real microVM, and which layer caught each one."),
    Page("docs/security-assessment.md", "security-assessment", "Breakout assessment", "Security",
         "The pre-publication breakout assessment: live escape attempts and an adversarial review of host-side code."),

    Page("BENCHMARKS.md", "benchmarks", "Benchmarks", "Reference",
         "Measured boot, resume and concurrency numbers with full distributions and methodology."),
    Page("PLAN.md", "plan", "Design notes", "Reference",
         "The architecture plan and milestone log, kept as an engineering record."),

    Page("CONTRIBUTING.md", "contributing", "Contributing", "Project",
         "How to build, test and version changes to isopod."),
    Page("CHANGELOG.md", "changelog", "Changelog", "Project",
         "Release history: what landed in each version and why."),
    Page("docs/dogfood-findings.md", "dogfood-findings", "Dogfood findings", "Project",
         "The running ledger of issues found by using isopod for real work."),
    Page("docs/feasibility.md", "feasibility", "Feasibility spike", "Project",
         "The M0 spike results."),
    Page("docs/m4-verify.md", "m4-verify", "Network verification", "Project",
         "M4 network verification notes."),
]

BY_SOURCE = {p.source: p for p in PAGES}

# The README's role on the site is played by the hand-authored landing page, so
# in-repo links to it resolve there rather than 404ing or bouncing to GitHub.
ALIASES = {"README.md": "index"}

HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — isopod</title>
<meta name="description" content="{blurb}">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="masthead">
  <a class="wordmark" href="index.html">isopod</a>
  <nav>
    <a href="getting-started.html">Get started</a>
    <a href="security.html">Security</a>
    <a href="mcp-usage.html">MCP</a>
    <a href="benchmarks.html">Benchmarks</a>
    <a href="https://github.com/me1iissa/isopod">GitHub</a>
  </nav>
</header>
<div class="docs">
<aside class="sidebar">
{sidebar}
</aside>
<article class="doc" id="main">
{body}
<p class="doc-foot">Rendered from <a href="https://github.com/me1iissa/isopod/blob/main/{source}"><code>{source}</code></a> on the main branch.</p>
</article>
</div>
{mermaid}
</body>
</html>
"""

MERMAID = """<script type="module">
import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
const dark = window.matchMedia('(prefers-color-scheme: dark)').matches;
mermaid.initialize({ startOnLoad: true, theme: dark ? 'dark' : 'neutral' });
</script>"""


def build_sidebar(current: Page) -> str:
    """Sidebar HTML with the current page marked. Groups keep declaration order."""
    out: list[str] = []
    seen: list[str] = []
    for page in PAGES:
        if page.group not in seen:
            if seen:
                out.append("</ul>")
            seen.append(page.group)
            out.append(f"<h2>{html.escape(page.group)}</h2><ul>")
        mark = ' aria-current="page"' if page.slug == current.slug else ""
        out.append(
            f'<li><a href="{page.slug}.html"{mark}>{html.escape(page.title)}</a></li>'
        )
    out.append("</ul>")
    return "\n".join(out)


# Matches an inline Markdown link target. Rewriting happens on the rendered HTML
# rather than the Markdown so that reference-style links are covered too.
HREF = re.compile(r'href="([^"]+)"')


def rewrite_links(body: str, source: str) -> tuple[str, list[str]]:
    """Point in-repo Markdown links at their rendered siblings.

    Returns the rewritten body and any unresolved internal targets, which
    `--check` turns into a build failure. Links that leave the repo, anchors,
    and mailto: are passed through untouched.
    """
    here = Path(source).parent
    unresolved: list[str] = []

    def fix(match: re.Match[str]) -> str:
        target = match.group(1)
        if target.startswith(("http://", "https://", "#", "mailto:")):
            return match.group(0)
        anchor = ""
        if "#" in target:
            target, anchor = target.split("#", 1)
            anchor = "#" + anchor
        if not target:  # a bare "#frag"
            return match.group(0)
        if not target.endswith(".md"):
            # A link to a non-Markdown repo file: send it to GitHub, where it
            # actually exists. Rendering it here would 404.
            resolved = (here / target).as_posix().lstrip("./")
            return f'href="https://github.com/me1iissa/isopod/blob/main/{resolved}{anchor}"'
        # Normalise "../SECURITY.md" and "docs/x.md" alike to a repo-relative path.
        repo_rel = (here / target).resolve().relative_to(REPO).as_posix() \
            if (here / target).exists() else (here / target).as_posix()
        if repo_rel in ALIASES:
            return f'href="{ALIASES[repo_rel]}.html{anchor}"'
        page = BY_SOURCE.get(repo_rel)
        if page is None:
            unresolved.append(f"{source} -> {target}")
            return f'href="https://github.com/me1iissa/isopod/blob/main/{repo_rel}{anchor}"'
        return f'href="{page.slug}.html{anchor}"'

    return HREF.sub(fix, body), unresolved


# Mermaid fences are lifted out BEFORE Markdown conversion. Post-processing the
# rendered HTML instead does not work: codehilite wraps blocks as
# `<div class="hl"><pre><span></span><code>` and HTML-escapes the body, so the
# diagram source would arrive at mermaid.js already mangled.
MERMAID_FENCE = re.compile(r"^```mermaid[ \t]*\n(.*?)^```[ \t]*$", re.M | re.S)
MERMAID_TOKEN = "xIsopodMermaidBlock{}x"


def lift_mermaid(text: str) -> tuple[str, list[str]]:
    """Replace mermaid fences with placeholders, returning the sources."""
    blocks: list[str] = []

    def take(match: re.Match[str]) -> str:
        blocks.append(match.group(1))
        return f"\n\n{MERMAID_TOKEN.format(len(blocks) - 1)}\n\n"

    return MERMAID_FENCE.sub(take, text), blocks


def drop_mermaid(body: str, blocks: list[str]) -> str:
    """Put the diagram sources back as elements mermaid.js will pick up."""
    for i, src in enumerate(blocks):
        token = MERMAID_TOKEN.format(i)
        # Markdown wraps a bare line in <p>; match with or without it.
        element = f'<pre class="mermaid">{html.escape(src)}</pre>'
        body = body.replace(f"<p>{token}</p>", element).replace(token, element)
    return body


def render(page: Page) -> tuple[str, list[str], bool]:
    """Render one page. Returns (html, unresolved links, uses_mermaid)."""
    text = (REPO / page.source).read_text(encoding="utf-8")
    text, mermaid_blocks = lift_mermaid(text)
    md = markdown.Markdown(
        extensions=["fenced_code", "tables", "attr_list", "sane_lists", "codehilite"],
        extension_configs={
            "codehilite": {"css_class": "hl", "guess_lang": False},
        },
    )
    body = md.convert(text)

    body = drop_mermaid(body, mermaid_blocks)
    uses_mermaid = bool(mermaid_blocks)

    body, unresolved = rewrite_links(body, page.source)
    return body, unresolved, uses_mermaid


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="_site", help="output directory (default: _site)")
    ap.add_argument(
        "--check",
        action="store_true",
        help="fail if any in-repo Markdown link has no rendered destination",
    )
    args = ap.parse_args()

    out = REPO / args.out
    if out.exists():
        shutil.rmtree(out)
    (out / "assets").mkdir(parents=True)

    shutil.copy2(SITE / "assets" / "style.css", out / "assets" / "style.css")

    # The landing page is hand-authored HTML and never goes through the Markdown
    # pipeline, so it cannot pick up the loader the way a rendered page does. It
    # can still carry a `<pre class="mermaid">` block, so apply the same rule by
    # hand: ship the loader only when the page actually has a diagram.
    landing = (SITE / "index.html").read_text(encoding="utf-8")
    if 'class="mermaid"' in landing:
        landing = landing.replace("</body>", f"{MERMAID}\n</body>", 1)
    (out / "index.html").write_text(landing, encoding="utf-8")

    written: list[str] = []
    all_unresolved: list[str] = []
    missing: list[str] = []

    for page in PAGES:
        if not (REPO / page.source).is_file():
            missing.append(page.source)
            continue
        body, unresolved, uses_mermaid = render(page)
        all_unresolved.extend(unresolved)
        doc = HEAD.format(
            title=html.escape(page.title),
            blurb=html.escape(page.blurb),
            sidebar=build_sidebar(page),
            body=body,
            source=page.source,
            mermaid=MERMAID if uses_mermaid else "",
        )
        (out / f"{page.slug}.html").write_text(doc, encoding="utf-8")
        written.append(f"{page.slug}.html")

    # GitHub Pages serves Jekyll by default and would swallow files it does not
    # recognise; .nojekyll turns that off and publishes the tree verbatim.
    (out / ".nojekyll").write_text("", encoding="utf-8")

    ok = not missing and not (args.check and all_unresolved)
    print(
        json.dumps(
            {
                "ok": ok,
                "out": str(out.relative_to(REPO)),
                "pages": len(written),
                "written": written,
                "missing_sources": missing,
                "unresolved_links": sorted(set(all_unresolved)),
            },
            indent=2,
        )
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
