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
    # `package` narrows the run to one crate; `filter` narrows it further to one
    # module path. An empty filter with a package set runs that crate's whole
    # lib suite, which is the right trade when the crate is small and the guard
    # is defended from several directions at once.
    package: str = "isopod-core"
    filter: str = ""
    # Cargo target selector used alongside `package`. `--lib` fits a library
    # crate; the guest agent is a binary crate, where `--lib` does not narrow
    # the run but refuses it outright ("no library targets") — a non-zero exit
    # with no compile error, which the harness would misread as "caught".
    target: str = "--lib"
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
        name="stage-hash-feeds-the-whole-buffer",
        file="crates/core/src/stage.rs",
        old="        hasher.update(&buf[..n]);",
        new="        hasher.update(&buf);",
        defect=(
            "The commit hash loop feeds the hasher its whole read buffer "
            "rather than the bytes the read returned, so any file whose "
            "apparent size is not a buffer multiple gets a different digest "
            "than the streamed hash every existing stage id was derived from. "
            "Nothing errors: commits keep succeeding, forks keep resolving — "
            "the store is simply re-identified out from under every user, "
            "which is the one way the buffered-read optimisation (0.12.4) "
            "was allowed to go wrong."
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
        file="crates/core/src/vm/mod.rs",
        old="        v @ stage::BaseCheck::WrongFlavor(_) => bail!(\"{}\", v.message().unwrap_or_default()),",
        new=(
            "        v @ stage::BaseCheck::WrongFlavor(_) if allow_skew => {\n"
            "            eprintln!(\"{}\", v.message().unwrap_or_default());\n"
            "            Ok(())\n"
            "        }\n"
            "        v @ stage::BaseCheck::WrongFlavor(_) => bail!(\"{}\", v.message().unwrap_or_default()),"
        ),
        defect=(
            "The opt-out for a rebuilt base starts excusing a different base "
            "*flavor* too, so busybox layers boot on the Alpine root. The escape "
            "hatch is for layers that are stale, not for layers that belong to "
            "another root — and 0.12.0's first cut shipped exactly this, "
            "contradicting every doc that described it."
        ),
        filter="vm::",
    ),
    Mutation(
        name="fork-check-never-consulted",
        file="crates/core/src/vm/mod.rs",
        old="    enforce_base_compat_with(verdict, allow_base_skew)?;",
        new="    let _ = &verdict;",
        defect=(
            "The run path stops consulting the base check it defines. Every "
            "policy test still passes — they call the policy directly — while "
            "no fork is ever actually refused. This survived the whole suite "
            "when 0.12.0 was first written."
        ),
        filter="vm::",
    ),
    Mutation(
        name="fork-check-sees-only-the-tip",
        file="crates/core/src/vm/mod.rs",
        old="    let verdict = stage::check_base_chain_in(stages_root, &meta, &base_id)?;",
        new="    let verdict = stage::check_base(&meta, &base_id);",
        defect=(
            "The fork check goes back to judging only the chain's tip, so one "
            "unstamped link launders every ancestor behind it: a chain whose "
            "oldest layer was built over a vanished root boots silently."
        ),
        filter="vm::",
    ),
    Mutation(
        name="commit-always-allows-skew",
        file="crates/core/src/vm/mod.rs",
        old="        base,\n        *allow_base_skew,\n    )?;",
        new="        base,\n        true,\n    )?;",
        defect=(
            "Every commit behaves as though the operator had opted into base "
            "skew, so a mixed-build chain is recorded by an ordinary run. The "
            "decision must come from the plan, which is where it was made."
        ),
        filter="vm::",
    ),
    Mutation(
        name="stale-stamp-outlives-its-image",
        file="crates/core/src/image/rootfs.rs",
        old="    let sidecar = image_meta_path(dest);\n    match std::fs::remove_file(&sidecar) {",
        new="    let sidecar = image_meta_path(&dest.with_extension(\"never\"));\n    match std::fs::remove_file(&sidecar) {",
        defect=(
            "A rebuild stops clearing the old stamp before replacing the image, "
            "so a failure between the two leaves a sidecar vouching for an image "
            "that is gone — and the pre-boot check then passes a stage onto a "
            "root it was never built over, silently."
        ),
        filter="image::",
    ),
    Mutation(
        name="pack-superblock-time-not-pinned",
        file="crates/core/src/image/rootfs.rs",
        old='        .args(["-mkfs-time", IMAGE_EPOCH])\n',
        new="",
        defect=(
            "The squashfs superblock takes its creation stamp from the clock "
            "again, so rebuilding an unchanged tree mints a new image id — "
            "which retires every stamped stage on that flavor and orphans the "
            "warm-pool snapshot keyed on it, for a root that did not change."
        ),
        filter="image::",
    ),
    Mutation(
        name="pack-file-times-not-pinned",
        file="crates/core/src/image/rootfs.rs",
        old='        .args(["-all-time", IMAGE_EPOCH])\n',
        new="",
        defect=(
            "File timestamps are copied out of the assembly directory, which is "
            "built fresh on every run, so the image id moves even with the "
            "superblock pinned. Each half of the pin is separately sufficient "
            "to break it, which is why both are asserted."
        ),
        filter="image::",
    ),
    Mutation(
        name="pack-inherits-an-ambient-source-date-epoch",
        file="crates/core/src/image/rootfs.rs",
        old='        .env_remove("SOURCE_DATE_EPOCH");',
        new='        .env_remove("ISOPOD_RESERVED_NOT_SOURCE_DATE_EPOCH");',
        defect=(
            "SOURCE_DATE_EPOCH reaches the packer, which refuses to run at all "
            "when it is set alongside the timestamp flags. An operator whose "
            "shell exports it — the ordinary reproducible-build environment — "
            "cannot build an image, and the failure names neither isopod nor "
            "the variable."
        ),
        filter="image::",
    ),
    Mutation(
        name="warmpool-build-unlocked",
        file="crates/core/src/snapshot.rs",
        old="    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {",
        new="    if true {",
        defect=(
            "The build lock stops locking, so two runs of the same warm shape "
            "both build into one directory and one can publish a memory file "
            "the other is still writing — the only warm-pool defect that "
            "publishes corrupt state rather than merely wasting work."
        ),
        filter="snapshot::",
    ),
    Mutation(
        name="warmpool-waiter-ignores-a-published-snapshot",
        file="crates/core/src/snapshot.rs",
        old="        if artifacts.is_complete() {\n            return Ok(None);\n        }\n        if std::time::Instant::now() >= deadline {",
        new="        if std::time::Instant::now() >= deadline {",
        defect=(
            "The waiter stops noticing that the winner published, so every "
            "concurrent second call sits out the full 90 s timeout and then "
            "cold-boots — turning the fix for a race into a stall."
        ),
        filter="snapshot::",
    ),
    Mutation(
        name="warmpool-ensure-skips-the-lock",
        file="crates/core/src/snapshot.rs",
        old="    let _lock = match acquire_build_lock(&artifacts, wait).await? {",
        new="    let _lock: Option<std::fs::File> = None;\n    match Some(()) {",
        defect=(
            "`ensure` stops taking the lock at all. The primitive still works "
            "and its own tests still pass — which is the point: a policy "
            "nothing calls holds in the test suite and nowhere else."
        ),
        filter="snapshot::",
    ),
    # --- isopod-guest-agent -----------------------------------------------
    # A binary crate: its unit tests live in the bin target, hence `--bins`.
    Mutation(
        name="loopback-left-down-without-a-nic",
        file="crates/guest-agent/src/main.rs",
        old="    net::ensure_loopback_up();\n",
        new="",
        defect=(
            "Boot stops bringing `lo` up unconditionally, so it comes up only "
            "inside the network-config path — which returns early when the "
            "kernel command line has no `isopod.net` token. That is exactly "
            "the `--no-network` boot, and the breakage is partial: bind() on "
            "127.0.0.1 still succeeds (binding never needed the link up), so "
            "a workload gets a port and fails only when something dials it, "
            "far from the cause. Finding #49: 18 of isopod's own tests failed "
            "this way inside a guest, none of them anywhere near an interface."
        ),
        package="isopod-guest-agent",
        target="--bins",
    ),
    Mutation(
        name="docker-coexistence-forgets-the-reply-leg",
        file="crates/core/src/net/setup.rs",
        old='''        // Replies to it, and nothing else.
        finish(vec![
            "-o".into(),
            TAP_WILDCARD.into(),
            "-d".into(),
            SLOT_SUPERNET.into(),
            "-m".into(),
            "conntrack".into(),
            "--ctstate".into(),
            "RELATED,ESTABLISHED".into(),
        ]),''',
        new='''        // Replies to it, and nothing else.
        finish(vec!["-o".into(), TAP_WILDCARD.into()]),''',
        defect=(
            "The reply rule loses its scoping, becoming a blanket accept for "
            "anything forwarded toward an isopod tap. This is the shape of "
            "mistake that looks like a simplification and is a widening: the "
            "rule lives in a chain isopod does not own, so an unscoped accept "
            "there admits traffic isopod's own supernet and conntrack checks "
            "were the only thing bounding. Finding #51 needed BOTH rules — a "
            "single inbound accept loses every reply packet to Docker's policy "
            "DROP, so not even a handshake completes — which makes the reply "
            "rule easy to treat as a formality and edit carelessly."
        ),
        package="isopod-core",
        filter="net::setup",
    ),
    Mutation(
        name="a-broken-host-resolver-looks-like-a-missing-domain",
        file="crates/core/src/net/broker.rs",
        old="""        Resolution::Failed => {
            return Some(build_dns_response(&query, RCODE_SERVFAIL, &[]));
        }""",
        new="""        Resolution::Failed => Vec::new(),""",
        defect=(
            "The gateway resolver stops distinguishing 'this host could not "
            "resolve' from 'this name has no A record', and answers both "
            "NOERROR-with-no-records. A guest is then told the domain exists "
            "but has no addresses, which is a terminal answer — resolvers stop "
            "retrying and fall back to nothing — when the truth is that the "
            "host's own resolver failed and a retry might well succeed. It is "
            "also the exact reading that sent this project chasing a resolver "
            "bug for half a day when the real fault was a packet filter."
        ),
        package="isopod-core",
        filter="net::broker",
    ),
    Mutation(
        name="a-guest-that-never-took-its-resolver-says-nothing",
        file="crates/core/src/image/rootfs.rs",
        old='nameserver 127.53.53.53\n',
        new='nameserver 1.1.1.1\n',
        defect=(
            "The image goes back to baking a public resolver. On its own that "
            "reads harmless — the agent overwrites the file at boot — but it is "
            "the difference between a guest that resolves NOTHING when that "
            "write fails and one that resolves EVERYTHING through Cloudflare "
            "while the host, the operator and the run's egress record all "
            "report that gateway DNS policy is in force. The public-slot "
            "redirect is deliberately pinned to the gateway address, so traffic "
            "aimed at a public resolver keeps its own masqueraded path: exactly "
            "the path an unconfigured guest takes. A loopback tombstone cannot "
            "leave the VM at all."
        ),
        package="isopod-core",
        filter="image::rootfs",
    ),
    Mutation(
        name="an-unsupported-kernel-is-reported-as-a-jail-bug",
        file="crates/jail/src/sys.rs",
        old="""                kernel_too_old_message(kernel_release().as_deref()),""",
        new="""                "mount_setattr failed".to_string(),""",
        defect=(
            "A host whose kernel predates mount_setattr(2) is told only that "
            "something failed, with no mention of the 5.12 requirement, what this "
            "host actually runs, or that dropping ISOPOD_JAIL=1 starts an "
            "unjailed VM. The jail still refuses to start — correctly — but the "
            "operator has no way to tell an unsupported kernel from a bug in the "
            "jail, and will go looking in the wrong place."
        ),
        package="isopod-jail",
        # The jail's tests live in its binary target, so the suite must be run
        # with --bins for the harness to name the test that caught this.
        target="--bins",
    ),
    # --- isopod-oci-unpack ------------------------------------------------
    # This crate writes attacker-authored bytes onto the host as the operator's
    # user, before any VM exists, so every guard below is load-bearing on its
    # own. The whole crate suite runs for each rather than a module filter: the
    # tree-walk guards are reached from several directions (entry paths, hard
    # link targets, whiteout targets, the cleanup on refusal) and narrowing the
    # run would hide which direction stopped being defended.
    Mutation(
        name="oci-parent-walk-follows-symlinks",
        file="crates/oci-unpack/src/sys.rs",
        old="    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;",
        new="    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC;",
        defect=(
            "The directory-fd walk drops O_NOFOLLOW, so a symbolic link an "
            "earlier layer planted is followed by a later one. This is the "
            "cross-layer image escape: layer 1 ships `foo -> /home/user`, layer "
            "2 ships `foo/.bashrc`, and each layer is innocent on its own."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-hardlink-follows-symlink",
        file="crates/oci-unpack/src/sys.rs",
        old="                d.as_ptr(),\n                0,\n            )",
        new="                d.as_ptr(),\n                libc::AT_SYMLINK_FOLLOW,\n            )",
        defect=(
            "`linkat` starts following the source symbolic link, so a hard link "
            "whose target is a link becomes a second name for an inode outside "
            "the tree. Confining the target's *parent* chain is not enough, and "
            "afterwards no path check can see the sharing at all."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-name-cannot-address-a-parent",
        file="crates/oci-unpack/src/sys.rs",
        old=' || bytes == b"." || bytes == b".."',
        new="",
        defect=(
            "The syscall layer stops refusing `.` and `..` as component names. "
            "A whiteout marker spelled `.wh...` yields the target `..`, which "
            "reaches the delete walk without passing through the entry-name "
            "component loop — and `..` from the staging root is the caller's "
            "destination directory. Found by attacking this crate, not by "
            "reading its design."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-dotdot-normalised-away",
        file="crates/oci-unpack/src/name.rs",
        old='            "" | "." => {}',
        new='            "" | "." | ".." => {}',
        defect=(
            "`..` is silently collapsed instead of refused, so "
            "`foo/../../etc/passwd` becomes the in-root `foo/etc/passwd`. "
            "Nothing escapes, and that is the trap: the extractor's idea of the "
            "path and the archive's now differ, so every later whiteout and "
            "duplicate comparison is made against a path nobody wrote."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-absolute-path-accepted",
        file="crates/oci-unpack/src/name.rs",
        old="    if name.starts_with('/') {",
        new="    if false {",
        defect=(
            "An absolute entry name is re-rooted instead of refused, so an "
            "image naming `/etc/passwd` silently gets a file in the image root "
            "— an import that quietly differs from the archive it came from."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-whiteout-target-escapes-upward",
        file="crates/oci-unpack/src/name.rs",
        old='        if target == ".." {',
        new="        if false {",
        defect=(
            "The whiteout target stops being checked for `..`, leaving only the "
            "syscall-layer guard between `.wh...` and a recursive delete of the "
            "staging root's parent. The pairing is deliberate, and this "
            "mutation is what proves the outer guard is not decorative."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-whiteout-prefix-not-recognised",
        file="crates/oci-unpack/src/name.rs",
        old='const WH: &str = ".wh.";',
        new='const WH: &str = ".wh.never-matches.";',
        defect=(
            "`.wh.` markers are treated as ordinary files, so nothing is "
            "deleted and the markers themselves are materialised. The image "
            "works and contains every file its author removed — including "
            "whatever a `RUN rm` was supposed to have taken out."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-setuid-reaches-the-host",
        file="crates/oci-unpack/src/lib.rs",
        old="const fn host_mode(raw: u32) -> u32 {\n    raw & 0o777\n}",
        new="const fn host_mode(raw: u32) -> u32 {\n    raw & 0o7777\n}",
        defect=(
            "setuid, setgid and sticky bits reach the host tree. A Debian-"
            "derived base image carries about fifteen setuid binaries, so "
            "importing one would drop attacker-authored setuid files into the "
            "operator's home directory before any VM exists."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-setuid-survives-its-own-removal",
        file="crates/oci-unpack/src/lib.rs",
        old="            self.special_modes.remove(&path);\n        }\n        // Anything other than a directory landed on this path",
        new="            let _ = &path;\n        }\n        // Anything other than a directory landed on this path",
        defect=(
            "A layer that rewrites a path WITHOUT the setuid bit no longer "
            "clears the earlier layer's recording, so the pack step re-arms a "
            "privilege the image's own author took away. `RUN chmod -s` in a "
            "Dockerfile becomes a no-op the moment isopod imports the image."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-setuid-survives-a-type-change",
        file="crates/oci-unpack/src/lib.rs",
        old="        if kind != EntryType::Directory {\n            self.forget_subtree(&path);\n        }",
        new="        if false {\n            self.forget_subtree(&path);\n        }",
        defect=(
            "A directory of setuid binaries replaced by a file or a symbolic "
            "link keeps every recording inside it, so the pack step applies a "
            "vanished subtree's modes to whatever now occupies those paths."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-setuid-outlives-a-whiteout",
        file="crates/oci-unpack/src/lib.rs",
        old="        self.drop_vanished_special_modes()?;",
        new="        if false {\n            self.drop_vanished_special_modes()?;\n        }",
        defect=(
            "Paths deleted by a whiteout or hidden by an opaque marker stay in "
            "the report the pack step and the operator both read, so the image "
            "is described as carrying setuid files it does not have."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-opaque-keeps-lower-content",
        file="crates/oci-unpack/src/lib.rs",
        old="        if !keep.contains(&key) {",
        new="        if false {",
        defect=(
            "An opaque whiteout stops deleting anything, so a directory the "
            "layer declared empty keeps every lower-layer file in it."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-opaque-prune-stops-at-one-level",
        file="crates/oci-unpack/src/lib.rs",
        old="        if sys::is_dir(&st) {\n            let sub = dir.open_dir(&child)?;",
        new="        if false {\n            let sub = dir.open_dir(&child)?;",
        defect=(
            "The opaque prune keeps a whole subtree whenever the layer wrote "
            "one file inside it, instead of applying the rule again one level "
            "down. The subtle half of the whiteout contract: the image looks "
            "right and still carries the lower layer's secret."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-image-env-overrides-the-run",
        file="crates/core/src/image/base.rs",
        old="            .filter(|(k, _)| !named.contains(k.as_str()))",
        new="            .filter(|(k, _)| named.contains(k.as_str()) || true)",
        defect=(
            "An imported image's Env wins over the run's own, so a base image "
            "silently overrides the PATH, proxy settings or credentials the "
            "caller explicitly set. The config is meant to be a DEFAULT: the "
            "run names it, the run gets it."
        ),
    ),
    Mutation(
        name="oci-working-dir-overrides-the-run",
        file="crates/core/src/image/base.rs",
        old="        if cwd.is_none() {\n            cwd.clone_from(&self.cwd);\n        }",
        new="        if true {\n            cwd.clone_from(&self.cwd);\n        }",
        defect=(
            "The image's WorkingDir replaces a cwd the run asked for, so a run "
            "that names a directory silently executes somewhere else."
        ),
    ),
    # --- isopod-oci-registry ----------------------------------------------
    # The network half of an import. Its guards are not about tar at all: they
    # are about where a credential may travel and where a request may be aimed.
    Mutation(
        name="oci-registry-token-crosses-an-origin",
        file="crates/oci-registry/src/auth.rs",
        old="    from.scheme() == to.scheme()\n        && from.host_str() == to.host_str()\n        && from.port_or_known_default() == to.port_or_known_default()",
        new="    let _ = (from, to);\n    true",
        defect=(
            "The Authorization header follows a redirect to another origin. "
            "Registries redirect blob downloads to object storage as the "
            "ordinary path, so this hands the operator's registry token to "
            "whatever host the registry named — on every single pull, not in "
            "some edge case."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-hub-credential-goes-everywhere",
        file="crates/oci-registry/src/lib.rs",
        old="    if reference.is_default_registry() {\n        if key == HUB_LEGACY_KEY {\n            return true;\n        }\n    } else if key == HUB_LEGACY_KEY {\n        // Never a fallback for anyone else.\n        return false;\n    }",
        new="    if key == HUB_LEGACY_KEY {\n        return true;\n    }",
        defect=(
            "The Docker Hub credential is offered to every registry again. Any "
            "operator who has run `docker login` sends their Hub credential to "
            "whatever registry they name next — on the first request, before "
            "any challenge, and in the clear to a local one."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-pinned-digest-unverified-when-cached",
        file="crates/oci-registry/src/lib.rs",
        old="            if actual != want.encoded() {",
        new="            if actual != want.encoded() && false {",
        defect=(
            "A pinned `repo@sha256:X` reference stops being verified against "
            "the bytes that came back. It only shows when the blob is already "
            "cached — the write path skips a blob that is present and correct, "
            "so the substituted body is never hashed while the descriptors "
            "driving the rest of the pull are parsed out of it."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-realm-is-unfloored",
        file="crates/oci-registry/src/auth.rs",
        old="        if !destination_is_allowed(&realm, allow_local) {",
        new="        if realm.scheme() != \"https\" && !is_loopback_url(&realm) {",
        defect=(
            "The token realm goes back to its own weaker check — https-or-"
            "loopback with the loopback half ungated — so any registry can "
            "point a credentialed request at the operator's loopback, their "
            "private network, or the cloud metadata endpoint."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-credential-returns-after-a-hop",
        file="crates/oci-registry/src/lib.rs",
        old="                carry_credential &= auth::may_carry_credential(&current, &next);",
        new="                carry_credential = auth::may_carry_credential(&current, &next);",
        defect=(
            "The credential flag is recomputed per hop instead of latching, so "
            "a second redirect INSIDE the attacker's origin re-attaches the "
            "token the first hop dropped. Two redirects instead of one defeat "
            "the origin rule entirely."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-challenge-honoured-off-origin",
        file="crates/oci-registry/src/lib.rs",
        old="            if status == reqwest::StatusCode::UNAUTHORIZED && !challenged && carry_credential {",
        new="            if status == reqwest::StatusCode::UNAUTHORIZED && !challenged {",
        defect=(
            "A host reached by redirect can challenge the client, so a CDN the "
            "registry named gets to choose a token realm and be paid in the "
            "operator's ~/.docker/config.json credential."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-ipv6-spelling-bypasses-the-floor",
        file="crates/oci-registry/src/auth.rs",
        old="            if let Some(v4) = embedded_ipv4(v6) {\n                return ipv4_is_allowed(v4, allow_local);\n            }",
        new="            if let Some(v4) = embedded_ipv4(v6) {\n                let _ = v4;\n            }",
        defect=(
            "The floor judges an IPv6 literal's spelling rather than the IPv4 "
            "address it names, so `[::ffff:169.254.169.254]` — the cloud "
            "metadata endpoint — walks through a check written to block "
            "`169.254.169.254`."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-refusal-names-the-wrong-address",
        file="crates/oci-registry/src/auth.rs",
        old="            bad.ip()\n        ));",
        new="            addrs[0].ip()\n        ));",
        defect=(
            "A name answering with a public record and a floored one is "
            "refused — correctly — but the refusal names the first record "
            "rather than the one that caused it. The floor still holds, so "
            "every assertion about dialling passes; what breaks is the only "
            "thing that tells an operator whether they hit DNS rebinding or "
            "their own split-horizon resolver, and it sends them to the record "
            "that is fine. This shipped: the suite asserted `is_err()` alone, "
            "and the message the function's own doc calls load-bearing was "
            "pinned by nothing."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-redirect-is-unfloored",
        file="crates/oci-registry/src/auth.rs",
        old="pub fn destination_is_allowed(to: &Url, allow_local: bool) -> bool {",
        new="pub fn destination_is_allowed(to: &Url, allow_local: bool) -> bool {\n    if true {\n        let _ = (to, allow_local);\n        return true;\n    }",
        defect=(
            "A registry can aim a blob fetch anywhere, including "
            "169.254.169.254 and the operator's own loopback. Digest "
            "verification stops content being injected that way; it does not "
            "stop the request, and the request is what an SSRF is."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-blob-written-unverified",
        file="crates/oci-registry/src/lib.rs",
        old="    if actual != expect.encoded() {",
        new="    if false {",
        defect=(
            "A downloaded blob is renamed to its content-addressed name without "
            "being hashed, so the blob store can contain a file that is not the "
            "blob it is named for — which every later reader assumes it cannot."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-registry-port-read-as-a-tag",
        file="crates/oci-registry/src/reference.rs",
        old="        let (registry, rest) = match head.split_once('/') {",
        new="        let (registry, rest) = match Some((head, head)).filter(|_| false) {",
        defect=(
            "The registry is no longer split off before the tag, so "
            "`localhost:5000/nginx` parses as the repository `localhost` at tag "
            "`5000/nginx` — and the request goes to Docker Hub instead of the "
            "registry the operator named."
        ),
        package="isopod-oci-registry",
    ),
    Mutation(
        name="oci-digest-becomes-a-path-unchecked",
        file="crates/oci-unpack/src/digest.rs",
        old="        if encoded.len() != *len\n",
        new="        if false\n",
        defect=(
            "A descriptor's digest stops being checked for length and alphabet "
            "before it is turned into `blobs/<algorithm>/<encoded>`. A manifest "
            "naming `sha256:../../../etc/shadow` then addresses whatever it "
            "likes — read on the host, as the operator's user, before any layer "
            "is looked at."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-blob-is-trusted-rather-than-verified",
        file="crates/oci-unpack/src/layout.rs",
        old="        if actual != d.digest.encoded() {\n            return Err(LayoutError::DigestMismatch {\n                expected: d.digest.to_string(),\n                actual,\n            });\n        }\n        Ok(())\n    }\n}",
        new="        let _ = actual;\n        Ok(())\n    }\n}",
        defect=(
            "A layer blob's bytes stop being checked against the digest that "
            "named them, so a layout whose blob store has been altered unpacks "
            "whatever is in it. Content addressing that is not verified is "
            "just a filename."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-descriptor-size-wraps-instead-of-refusing",
        file="crates/oci-unpack/src/layout.rs",
        old='    let size = u64::try_from(size).map_err(|_| malformed("a descriptor has a negative size"))?;',
        new="    let size = size as u64;",
        defect=(
            "A negative size in a descriptor wraps to an enormous unsigned one "
            "instead of being refused. JSON has no unsigned integers, and every "
            "ceiling in the reader is a comparison against this number — one "
            "that is absurd rather than small sails past all of them."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-implicit-directory-takes-the-umask",
        file="crates/oci-unpack/src/lib.rs",
        old=(
            "                    // `mkdirat`'s mode is masked by the umask; the image's\n"
            "                    // layout must not depend on the operator's shell.\n"
            "                    made.chmod(DIR_MODE).map_err(|e| io(&e))?;\n"
        ),
        new="",
        defect=(
            "A directory the extractor creates on its own goes back to taking "
            "its mode from `mkdirat`, which the kernel masks with the process "
            "umask. Under `umask 077` every implicit directory in the image "
            "comes out 0o700, so the same source image imports to a different "
            "image — and therefore a different content id — on two hosts."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-image-root-takes-the-umask",
        file="crates/oci-unpack/src/lib.rs",
        old="        if let Err(e) = root.chmod(DIR_MODE) {",
        new="        if let Err(e) = root.chmod(0o700) {",
        defect=(
            "The root of the unpacked image gets a mode of its own rather than "
            "the one every other implicit directory has. `create_dir` asks for "
            "0o777 and gets it masked, so without an explicit mode the image "
            "root is whatever the operator's shell was set to."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-deferred-mode-refuses-a-usrmerge-link",
        file="crates/oci-unpack/src/lib.rs",
        old="                Err(Refusal::SymlinkEscape { .. }) => continue,",
        new="",
        defect=(
            "A deferred directory mode whose path a later layer replaced with "
            "a symbolic link refuses the image again. `/lib -> usr/lib` is how "
            "every usrmerge image is shaped, so an ordinary import fails at the "
            "very last step, after every layer has been unpacked, with a "
            "message accusing the author of hand-crafting an escape."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-entry-bytes-unbounded",
        file="crates/oci-unpack/src/lib.rs",
        old="            if this_entry + n64 > self.limits.max_entry_bytes {",
        new="            if false {",
        defect=(
            "The per-entry ceiling stops firing, so a few kilobytes of gzip "
            "expand to whatever the archive declared. The counter sits on the "
            "decompressed stream precisely so the declared size never matters."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-refusal-leaves-a-staging-tree",
        file="crates/oci-unpack/src/lib.rs",
        old="        if self.promoted {\n            return;\n        }",
        new="        if true {\n            return;\n        }",
        defect=(
            "A refused image stops discarding its staging tree, so a partly "
            "applied stack of untrusted layers survives on disk beside the "
            "destination — invariant 9, which is what makes every other "
            "refusal safe to be total."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-teardown-cannot-unlock-what-finish-locked",
        file="crates/oci-unpack/src/lib.rs",
        old="            let _ = dir.chmod_child(name, 0o700);\n",
        new="",
        defect=(
            "The teardown stops relaxing a directory's mode before descending "
            "into it, so it cannot remove a tree that `finish` has already "
            "locked down on the image's behalf — 0o000 refuses the open, 0o500 "
            "refuses the unlink. Invariant 9 would then hold for every refusal "
            "except one that happens after the modes are applied."
        ),
        package="isopod-oci-unpack",
    ),
    Mutation(
        name="oci-dangling-destination-adopted",
        file="crates/oci-unpack/src/lib.rs",
        old="        if std::fs::symlink_metadata(dest).is_ok() {",
        new="        if dest.exists() {",
        defect=(
            "The destination check goes back to `exists()`, which follows a "
            "symbolic link and reports false when its target is absent — so a "
            "dangling link at the destination is adopted and the promoting "
            "rename lands somewhere the caller never named. The same shape as "
            "the copy-out escape found in 0.11.0."
        ),
        package="isopod-oci-unpack",
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


# Progress narration. Under `--json` it goes to stderr, because stdout then
# carries exactly one thing — the JSON document — and a caller that pipes it to
# a parser must not have to strip a preamble out of the way first. This was a
# dogfood finding in its own right: `--json` output did not parse.
_NARRATE = sys.stdout


def narrate(msg: str = "") -> None:
    """Emit progress to whichever stream is not carrying the result."""
    print(msg, file=_NARRATE, flush=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--list", action="store_true", help="print mutation names and exit")
    ap.add_argument("--only", default="", help="comma-separated subset to run")
    ap.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON summary on stdout (progress moves to stderr)",
    )
    args = ap.parse_args()

    if args.json:
        global _NARRATE
        _NARRATE = sys.stderr

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
        narrate(f"exporting HEAD to {tree}")
        worktree(tree)

        # Warm the build once so each mutation pays only for what it changed.
        narrate("warming the build cache (cold build, this is the slow part)")
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
        narrate("baseline green\n")

        pristine = {}
        for m in selected:
            pristine.setdefault(m.file, (tree / m.file).read_text())

        for m in selected:
            narrate(f"--- {m.name}")
            try:
                apply(m, tree)
            except LookupError as e:
                narrate(f"    STALE: {e}")
                results.append({"name": m.name, "outcome": "stale", "detail": str(e)})
                continue

            cmd = ["cargo", "test", "--workspace"]
            if m.package:
                cmd = ["cargo", "test", "-p", m.package, m.target]
                if m.filter:
                    cmd.append(m.filter)
            rc, out = run(cmd, tree, TEST_TIMEOUT_S)
            (tree / m.file).write_text(pristine[m.file])

            if rc == 124:
                # A mutant that hangs is not caught: CI wedges instead of failing.
                narrate("    NOT CAUGHT (the suite hung rather than failing)")
                results.append({"name": m.name, "outcome": "hung"})
            elif rc == 0:
                narrate("    NOT CAUGHT (suite still green)")
                results.append({"name": m.name, "outcome": "survived"})
            elif "error[E" in out or "error: could not compile" in out:
                # A mutation that stops compiling proves nothing about the tests.
                narrate("    STALE (mutated tree does not compile)")
                results.append({"name": m.name, "outcome": "stale", "detail": "no compile"})
            else:
                killers = sorted(set(re.findall(r"^test (\S+) \.\.\. FAILED", out, re.M)))
                # Name at most three, but say so when there are more: a bare list
                # reads as "these are the tests that cover this", and a reader
                # deciding whether a guard is defended needs to know the list was
                # cut. The full set is in the JSON `by` field either way.
                shown = ", ".join(killers[:3]) or "(suite failed)"
                if len(killers) > 3:
                    shown += f" (+{len(killers) - 3} more)"
                narrate(f"    caught by {shown}")
                results.append({"name": m.name, "outcome": "caught", "by": killers})
    finally:
        shutil.rmtree(root, ignore_errors=True)

    bad = [r for r in results if r["outcome"] != "caught"]
    narrate()
    if args.json:
        print(json.dumps({"results": results, "ok": not bad}, indent=2))
    caught = len(results) - len(bad)
    narrate(f"{caught}/{len(results)} mutations caught")
    for r in bad:
        narrate(f"  {r['outcome'].upper():9} {r['name']}")
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
