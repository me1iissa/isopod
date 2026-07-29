---
name: release
description: Bump the isopod workspace version and tag a release correctly. Use whenever a change touches crates/, Cargo.toml, Cargo.lock, vendor/ or scripts/ — CI's Version guard requires a bump for any of those — or when asked to cut, tag or release a version. Also use to diagnose a failing "Version guard" job.
---

# Cutting a release

CI's Version guard fails any push that changes `CODE_PATHS` without a version bump.
`CODE_PATHS` is `crates/ Cargo.toml Cargo.lock vendor/ scripts/`. Everything else —
`.github/`, `docs/`, `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md` — is exempt and
needs no bump.

**Never run a bare `git tag -a vX.Y.Z`.** It tags whatever HEAD happens to be, which
across git worktrees is frequently a different branch. That is how v0.13.1 landed on
v0.13.0's commit: the release shipped `.deb` and `.rpm` packages declaring the previous
version, and CI then failed four times with a message about a bump that had already
been made. Use the script; it passes an explicit sha and verifies where the tag landed.

## The sequence

```sh
scripts/bump-version.py patch      # or minor / major
# add a `## [<new>] — <date>` section to CHANGELOG.md
git add -A && git commit           # bump + changelog + the change, one commit
scripts/bump-version.py --tag      # tags HEAD, refuses if HEAD is not the bump
git push origin main --follow-tags
```

`--tag` refuses unless HEAD's own `Cargo.toml` declares the version being tagged, then
re-reads the tag to confirm it landed where intended.

## Choosing the level

Pre-1.0 semantics, per `CONTRIBUTING.md`:

| Level | When |
|---|---|
| `major` | not used before 1.0 |
| `minor` | features, new report fields, new modules, anything breaking |
| `patch` | fixes, performance, dependency upgrades, test-only changes |

A dependency upgrade that closes a security advisory is still a patch. A new field on
`RunReport` is a minor even though nothing breaks, because consumers gain a surface.

## The commit carries the bump

One commit holds the change, the version, `plugin.json`, the refreshed `Cargo.lock` and
the CHANGELOG entry. Do not defer the changelog to "the commit that closes the wave" —
there is no such thing, because the guard runs on every push. That mistake cost a red
build and a follow-up commit on 2026-07-28.

## Verifying, and diagnosing a red guard

```sh
scripts/bump-version.py --check
```

Checks lockstep with `plugin.json`, that the version is not below the newest tag, that a
CHANGELOG section exists, and — the one that is easy to miss — that if this version is
already tagged, the tag sits on a commit whose `Cargo.toml` declares it.

**When "Version guard" fails, check where the newest tag points before concluding a bump
is missing.** The guard diffs against the *tag's* commit, not the previous push, so a
misplaced tag reports as "code changed but the version was not bumped" — true, and
misleading. `git rev-list -n1 vX.Y.Z` and `git show <sha>:Cargo.toml` settle it in two
commands.

To repair a misplaced tag that has already been pushed:

```sh
gh release delete vX.Y.Z --yes          # only if a release was published
git push origin :refs/tags/vX.Y.Z
git tag -d vX.Y.Z
git tag -a vX.Y.Z <sha-of-the-bump> -m X.Y.Z
git rev-list -n1 vX.Y.Z                 # confirm before pushing
git push origin refs/tags/vX.Y.Z
```

## The preview line

`preview` carries `X.Y.Z-preview.N` with `plugin.json` in lockstep, and is never released
from — no tags, no packages. `bump-version.py` resolves a pre-release to its own release
rather than stepping past it: `0.13.0-preview.1 --patch` gives `0.13.0`, not `0.13.1`.
