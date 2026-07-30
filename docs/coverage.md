# Coverage, and what it does not mean

The README carries a badge reading **`coverage (unit)`**. The qualification is in the
label because a badge is four words wide and cannot hold a caveat, and the number
without its caveat is misleading in a specific, predictable direction.

## What the number measures

Line coverage from `cargo llvm-cov` over `cargo test --workspace` — the tests that run
on a GitHub-hosted runner on every push to `main` and every pull request that touches
code.

## What it leaves out

The `#[ignore]`d suite. That is fifteen tests, and they are the ones that matter most:

| | |
|---|---|
| `fc-client/tests/live_boot.rs` | a real Firecracker boot |
| `guest-agent/tests/live_net.rs` | guest networking, end to end |
| `guest-agent/tests/live_overlay.rs` | the overlay/pivot topology |
| `guest-agent/tests/live_agent.rs` | the vsock agent protocol |
| `jail/tests/live_jail.rs` | the unprivileged-userns jail |
| `core/tests/live_inject.rs` | credential injection |
| `oci-registry/src/registry_tests.rs` | a live registry pull |

Real boots, the jail, VM lifecycle, and the egress-enforcement ledger. **The
best-defended paths in the tree contribute nothing to the percentage**, so the number
is structurally lower than the project's actual test coverage — and it is lowest
exactly where the code is most security-relevant.

### Not for want of `/dev/kvm`

This document used to say hosted runners cannot run those tests. That was false. A free
`ubuntu-latest` runner has `/dev/kvm` (as `root:kvm 0660`; a udev rule puts the runner
in the group), and the full-boot probe booted a real guest on one in **84 ms**, then
completed a privileged `isopod setup` — twelve taps, an `inet isopod` nftables table,
`ip_forward=1`.

They are absent because reaching them costs a vendored Firecracker build and four guest
images — some twenty minutes — which does not belong on the pull-request path. That is a
scheduling constraint, and it is being worked on. See `.github/workflows/full-boot-probe.yml`.

## Why nothing gates on it

A threshold on this number would punish the wrong code. It moves on refactors, on
`#[cfg]` blocks, and on generic instantiation counts, none of which change whether the
sandbox holds. Worse, because the ignored suite is excluded, a change that *improved*
the live tests and touched nothing else would move the badge down.

The gate that does mean something is the **mutation harness**
(`scripts/mutation-check.py`): a fixed set of deliberate breakages, each one a defect
this project actually shipped, every one of which must make the suite fail. That asks
"would the tests notice if this broke", which is the question coverage only gestures at.

## What the report is genuinely for

Finding the module or branch that **no** test executes at all. The mutation harness only
interrogates code it has a mutation for; coverage is the cheap way to find the file
nobody wrote a mutation for because nobody wrote a test for it.

The full `lcov.info` is uploaded as an artifact on every `main` run (14-day retention),
which is the right granularity for that hunt — far more useful than the headline.

## Where the number comes from

`.github/ci-digest.py` parses the `TOTAL` row of `cargo llvm-cov --summary-only`. The
same parser produces the pull-request digest comment and the badge endpoint, so the two
cannot disagree. If the summary fails to parse, no badge is written and the previous one
stands — a stale number is better than a confident wrong one.
