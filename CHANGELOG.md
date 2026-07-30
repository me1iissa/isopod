# Changelog

All notable changes to isopod. The format follows
[Keep a Changelog](https://keepachangelog.com/) loosely; versions follow
[Semantic Versioning](https://semver.org/) with pre-1.0 semantics (minor =
features or breaking changes, patch = fixes). See CONTRIBUTING.md §
Versioning for the policy.

## [0.16.0] — 2026-07-30

Part two of the gateway DNS resolver; 0.15.0 provisioned the rules, this builds
the resolver that answers on them. Still nothing points a guest at it — that is
part three — so no guest behaves differently yet.

### Added — a DNS resolver for NAT slots, and an honest failure mode

`DnsForwarder` answers on a slot's gateway through **the host's own resolution
path**, so a guest resolves exactly what the host resolves — including
split-horizon and internal names a public resolver can never see, and without
sending every lookup to a third party regardless of the operator's DNS policy.
Same lifecycle as the egress broker: two tokio tasks in the supervisor's process,
aborted on drop, dead with the run. No new process, no new port.

**It never falls back to a public resolver.** A host that cannot resolve gives
its guests `SERVFAIL`. The alternative — quietly retrying against 1.1.1.1 —
would defeat the privacy property on exactly the networks where nobody expects
it, and would do so invisibly.

`SERVFAIL` rather than "no records" is the point of a new `Resolution` type.
`resolve_v4` collapsed "the resolver failed" and "the name has no A record" into
an empty vector, which is right for a caller about to dial something and wrong
for one about to synthesise a reply: answering NOERROR-empty tells a guest the
domain exists but has no addresses, which is terminal — resolvers stop retrying.
A broken host resolver would have been indistinguishable from a missing domain,
which is the exact confusion that sent this project chasing a resolver bug for
half a day when the real fault was a packet filter.

The resolver answers **one** sandbox. It binds a host address, so without the
peer gate any local process could use it as a general-purpose resolver — and, on
a filtered slot, learn what that sandbox looked up.

### Changed — DNS over TCP no longer competes with proxy traffic

The filtered broker served DNS-TCP through the same accept loop and the same
`MAX_CONCURRENT_CONNS` permits as SOCKS and HTTP tunnels, so a run that saturated
its tunnels could starve its own name resolution — a stall that presents as a DNS
timeout and points nowhere near the cause. DNS now has its own accept loop.

The responder is one type with a mode switch rather than two servers: the
transport, parser and encoder were already policy-free, and only two points in
`answer_dns` ever cared. Filtered mode is unchanged in behaviour — allowlist,
ledger event, remembered answers for attribution — and its 41 tests still pass
untouched.

## [0.15.0] — 2026-07-30

### Added — provisioning for a gateway DNS resolver (inert until the runtime half lands)

`isopod setup` now installs, for every **public** (NAT) slot, a `daddr`-pinned
redirect of gateway-addressed DNS to port 5353, plus the matching input accept.
The manifest records the port as `gateway_dns_port`.

**Nothing uses these rules yet, and nothing changes for any guest.** They only
match traffic aimed at a slot's own gateway on port 53, and no guest is pointed
there — every guest still resolves through the public resolvers in its image. The
rules are installed first, deliberately, because provisioning happens once as root
and the runtime cannot open a hole for itself later. The forwarder that answers on
5353, and the plumbing that points guests at it, are the next change.

**Why bother.** The hardcoded `1.1.1.1` / `8.8.8.8` in every guest image work on a
permissive network and fail on a restrictive one, and either way they send every
guest lookup to a third party regardless of the operator's own DNS policy — and
internal or split-horizon names can never resolve. A resolver on the slot gateway,
answering through the host's own resolution path, fixes all three. This was
briefly mistaken for the cause of a CI egress failure; it was not (that was
Docker's FORWARD policy, fixed in 0.14.0), so this is a portability and privacy
improvement rather than a bug fix.

**The `daddr` pin is load-bearing twice.** It keeps NAT semantics — a guest that
deliberately queries `1.1.1.1:53` still takes its direct masqueraded path — and it
makes the rollout order-independent: an older binary on a newer provisioning keeps
using public resolvers, and the new rules are completely inert for it rather than
hijacking its queries into a port with no listener. `gateway_dns_port` is read the
same fail-closed way as `broker_tcp_ports`: unrecorded means "no resolver here",
and the runtime falls back to the public list rather than guessing.

Public slots open **only** 5353, never the broker's four-port set — no broker
listens on a NAT gateway, and the input chain is the only thing between a guest and
host services.

### Changed — the provisioning format is versioned, and its regression gate with it

`no_filtered_slots_is_byte_identical_to_0_8_1` asserted that an install with no
filtered slots emitted the pre-0.9 table verbatim. That is deliberately no longer
true, so it is replaced by
`the_ruleset_matches_the_checked_in_provisioning_fixture` against new 0.15
fixtures. The 0.8.1 fixtures stay in the tree as the record of what the old format
was.

The fixtures are generated by `build_nft_ruleset` itself, through an `#[ignore]`d
`regenerate_the_provisioning_fixtures`, never typed out — a fixture hand-written to
match what the author believed the writer emits pins the belief, not the behaviour.
It stays `#[ignore]`d so CI can never rewrite the thing it compares against.

## [0.14.0] — 2026-07-30

### Fixed — a coexisting Docker install silently swallowed all guest egress

Docker sets the iptables `ip filter` FORWARD policy to DROP and jumps to a
`DOCKER-USER` chain containing only `RETURN`, so every guest→WAN packet fell
through to that drop. **Any host running Docker had broken NAT egress, and
nothing said so:** `isopod setup` reported complete success throughout — taps
created, nft table installed, `ip_forward=1`, guest addressed — because nothing
in setup looked at whether another tool had already claimed the forward hook.
Dogfood finding #51.

The first symptom is a timeout inside a guest, usually a DNS lookup, which reads
as a resolver problem. It read as one here, and was diagnosed as one — a
hardcoded-public-resolver bug — confidently and wrongly, until a guest handed a
literal IP with no DNS anywhere in the path failed too, while the host reached
both `1.1.1.1` and `8.8.8.8`. Host traffic goes through OUTPUT and guest traffic
through FORWARD; only one of those was dropped.

`setup` now inserts two accept rules into `DOCKER-USER` when that chain exists.
Two, not one: the reply arrives on the WAN interface and dies on the same policy
DROP, so a single inbound accept never completes a TCP handshake.

**Why this cannot weaken the sandbox.** Per nft(8), an accept verdict ends
evaluation of *the current base chain* and the packet advances to the next base
chain, whereas a drop ends the whole ruleset. `inet isopod`'s forward chain is a
separate base chain at the same hook, so accepting in Docker's table removes
Docker's drop and none of isopod's — tap↔tap isolation, anti-spoof, the IPv6
deny, the RFC1918 guard, the filtered-slot drop and the closing
`iifname "isopod-tap*" drop` default-deny all still apply. Measured in throwaway
network namespaces rather than assumed: with the accepts live, a drop in a
separate `inet` chain still blocked the connection and its counter showed the
packets arriving. The rules are accept-only and scoped to isopod's own taps and
its own `10.107.0.0/16`.

Docker publishes no persistence contract for that chain, so a daemon restart or
a network creation may flush it. That is fail-closed — egress stops, nothing
opens — and the remedy is re-running `sudo isopod setup`, the same doctrine
already published for a flushed nftables ruleset.

### Added — `setup` reports what it did about the forward hook

`isopod setup`'s JSON gains `docker_user`: `installed`, `already-present`,
`chain-absent`, `iptables-missing`, `lock-busy`, `skipped` or `removed`. The
failure this addresses is invisible to every other field in that report, so the
answer is stated rather than left to be inferred from whether the network happens
to work. A lock timeout reports `lock-busy` and not `chain-absent`, because
conflating them would read as "nothing to do" on precisely the busy Docker hosts
where there is most to do.

`--no-docker-user` declines the mechanism for anyone curating that chain
themselves. A kernel without `xt_comment` falls back to unmarked rules rather
than failing a `setup` that succeeds today, and teardown matches both spellings
so neither can orphan.

## [0.13.3] — 2026-07-30

### Added — CI reports what it learned, on the pull request, while it can still matter

Every pull request now gets a single digest comment, rewritten in place rather
than appended to: the version-guard verdict in words, the third-party dependency
delta, and line coverage. Coverage previously ran only on pushes to `main` — a
number nobody saw until after the merge cannot inform the merge.

The digest is written to the run summary first and mirrored into the comment
second, so it still renders for pull requests from forks, whose tokens are
read-only by design. It is deliberately absent from `ci-ok`'s `needs`: a report
must not be able to block a merge whose code is fine.

Workspace crates are excluded from the dependency delta. They carry the
workspace version, so without that filter every release bump reported nine
"dependency changes" and buried the one line that mattered.

### Added — a coverage badge, labelled for what it actually measures

`coverage (unit)`, not `coverage`. A badge cannot carry a caveat, so the
qualification lives in the label where it cannot be separated from the number.
`docs/coverage.md` is new and says the rest: which fifteen `#[ignore]`d tests are
excluded, why the number is lowest exactly where the code is most
security-relevant, and why nothing gates on it.

The badge endpoint is rendered by the same parser that produces the digest, so
the two cannot disagree, and it is written only when the summary actually parsed
— a failed coverage run leaves the previous badge standing rather than replacing
a real number with a wrong one.

### Fixed — a false claim about hosted runners, in four places

`coverage.yml`, `ci.yml`, and the CI research notes all stated that the
`#[ignore]`d suite *cannot run on GitHub-hosted runners*. That was false when
written: it repeated a pre-April-2024 assumption without checking one. A free
`ubuntu-latest` runner has `/dev/kvm`, and the full-boot probe booted a real
guest on one in 84 ms and completed a privileged `isopod setup`. The suite is
absent from the pull-request path because reaching it costs a vendored
Firecracker build and four guest images — a scheduling constraint, not a
capability one.

## [0.13.2] — 2026-07-29

### Fixed — a tag on the wrong commit published packages declaring the wrong version

`v0.13.1` was created with a bare `git tag -a v0.13.1`, which tags whatever `HEAD`
happens to be. Work at the time spanned several git worktrees and the primary
checkout was on another branch, so the tag landed on `v0.13.0`'s commit. The
release built from that tree and published `isopod_0.13.0-1_amd64.deb` and
`isopod-0.13.0-1.x86_64.rpm` inside a tarball named `isopod-0.13.1`. A binary
that reports a version it is not is a support problem, so the release and the
tag were deleted and re-cut at the commit carrying the bump.

**The Version guard was right and was disbelieved.** It failed four consecutive
pushes with "code changed since v0.13.1 but the workspace version was not
bumped", which was true — it diffs against the *tag's* commit, and the tag was a
commit early. The message sent the reader looking for a missing bump that had
already been made. The guard now checks tag placement directly: if the workspace
version is already tagged, the tagged commit's own `Cargo.toml` must declare that
version, and the failure names the offending sha and what it actually declares.

### Added — `scripts/bump-version.py` and a `release` skill, so this is mechanical

Three things the guard enforces were being done by hand and by memory: the
workspace version and `.claude-plugin/plugin.json` moving together, the version
going up by one step of the right level, and the tag landing on the commit that
carries the bump.

`scripts/bump-version.py patch|minor|major` performs the first two and refreshes
`Cargo.lock`. `--tag` performs the third: it refuses unless `HEAD`'s own
`Cargo.toml` declares the version being tagged, passes an explicit sha rather
than relying on `HEAD`, and re-reads the tag afterwards to confirm where it
landed. `--check` verifies the whole state, including tag placement, and is what
to run first when the guard goes red.

A pre-release resolves to its own release rather than stepping past it —
`0.13.0-preview.1 --patch` gives `0.13.0`, not `0.13.1` — because the preview
line depends on that and anything else skips the version it was previewing.

The `release` skill in `.claude/skills/` documents the sequence, which level to
pick, and the two commands that diagnose a red Version guard. What neither buys:
the script does not commit, does not push, and does not write the changelog
entry — those stay deliberate.

## [0.13.1] — 2026-07-29

### Fixed — 0.13.0 shipped unformatted

One `Attr::Bucket` call in the new copy-out instrumentation exceeded the line
width, so `cargo fmt --check` failed on the release commit. The tag built and
released green — `Release` and `CI` are separate workflows, and formatting has
no bearing on a binary — but `main` was red from the moment 0.13.0 landed.

The gap was procedural: the branch was rebased onto a `main` that had moved, and
the merge was verified with clippy and the test suite but not with
`cargo fmt --check`. Rebasing reflows nothing by itself; the offending line was
inside a hunk the rebase carried across, and only the formatter's line-width
rule noticed.

## [0.13.0] — 2026-07-29

### Added — spans over the phases nobody could see, and six report fields to match

Internal `tracing` instrumentation over the run path, and six additive
`RunReport` fields: `boot_ms`, `teardown_ms`, `copy_out_ms`,
`snapshot_build_ms`, and the split of the existing `commit_ms` into
`commit_hash_ms` + `commit_copy_ms`. Each field is absent when its phase did
not happen, so every existing consumer sees the exact JSON it always did.
`resume_ms` and `commit_ms` themselves are unchanged.

What the numbers showed once they existed:

- **Teardown costs ~140 ms on every run** — 27% of a 509 ms cold run, second
  only to the kernel boot — and had been folded into a "boot" figure nobody
  computed directly. Of ~470 ms non-exec time the kernel boot proper is
  ~210 ms: the number an operator would have read as boot was about twice the
  real thing.
- **Copy-out moves ~52 MB/s** over the base64-in-JSON vsock path, and runs
  after the `timeout_s` budget has stopped protecting the caller.
- **`commit_ms` is now split, not diagnosed.** The hash and copy passes are
  separately visible; on real commits they are the same order of magnitude,
  with end-to-end time dominated by writeback of the just-written scratch (see
  0.12.5 below for the measured numbers and the buffered-read fix they led to).

What this does NOT buy: it is instrumentation, not telemetry. There is no
exporter, no network path, and no `opentelemetry` dependency in any build.
With `RUST_LOG` unset the binaries install no subscriber and write zero bytes;
`RUST_LOG=isopod=debug` prints the spans to stderr and nowhere else. Span
attributes pass through a sealed `Attr` type whose only string carriers are
`&'static str` and the host-minted `vm_id`, and guest-influenced magnitudes
appear only as log2 buckets. `exec_ms` still folds vsock output streaming into
compute time. The two spans written blind while the host's taps were down —
`isopod.run.snapshot_ensure` and the warm `isopod.run.resume` — have since run
live: a first-warm run reported `snapshot_build_ms: 4238` / `resume_ms: 72`
with both spans on stderr, and a second run of the same shape reported
`resume_ms: 61` with `snapshot_build_ms` correctly absent.

## [0.12.5] — 2026-07-29

### Fixed — the commit hash pass read a gigabyte 8 KiB at a time

`stage_id_for` streamed `layer.ext4` through `std::io::copy`, whose stack buffer
is 8 KiB: 131 072 `read()` calls per apparent GiB, each also zero-filling its
slice wherever the sparse scratch has a hole. It now reads through a 4 MiB heap
buffer — 256 reads per GiB — retrying `EINTR` as `io::copy` did.

**The measurement that motivated this did not reproduce, and the claim is
corrected rather than repeated.** One instrumented run showed the hash pass at
10.81 s against 0.38 s for the sparse copy of the same file, and that state did
not appear again. Real end-to-end commits of the same shape ran 987/881/1018 ms
before and 923/888/992 ms after: indistinguishable, and dominated by writeback
of the scratch that had just been written.

What survives measurement, on a real committed layer of 1 GiB apparent and
64 MiB allocated, warm cache, isolated pass: **0.90 s before, 0.47 s after.**
So the claim is 1.9× on the pass, plus a 512× cut in `read()` calls — which is
what bounds the pathological case. Per-call overhead has only to reach ~80 µs
for the old loop to cost 10 s/GiB, where the new loop stays under a second.
That is worth having on a contended machine even though today's commits do not
show it.

**The digest does not change, and that is the whole constraint.** Stage ids are
content-addressed, and the id is BLAKE3 over the file's full apparent bytes,
holes included as the zeros they read back as. Skipping the holes would have
been faster again — and would have silently re-identified every stage in every
existing store, breaking forks with no error anywhere. A new test keeps the old
`std::io::copy` implementation in place as the definition and asserts the
buffered pass is byte-identical to it, over a fixture shaped for every loop
boundary and over a real `make_scratch_ext4` image.

A plain revert to `io::copy` is invisible to any test by design, since identical
bytes is the contract; so mutation `stage-hash-feeds-the-whole-buffer` breaks
the seam the loop actually has — feeding the hasher its whole buffer rather than
the bytes read — and two tests catch it from different directions.

`blake3`'s `mmap` and `rayon` features cut the isolated pass a further ~4×,
measured, and are declined: six crates and a thread pool in a sandbox tool, none
of them in the guest build stage's cargo cache, so offline in-guest builds would
stop working. The stake is ~0.35 s per apparent GiB that writeback absorbs
today.

## [0.12.4] — 2026-07-29

### Security — the S3 XML parser carried two denial-of-service defects in its dependency

`quick-xml` 0.39.4 is subject to two RustSec advisories, and isopod's one use
of it — `quick_xml::de::from_str` parsing S3 `ListObjectsV2` responses during
kernel selection (`crates/core/src/image/s3.rs`) — reaches both defective
paths. That was established by reading the 0.39.4 source, not by assuming the
serde surface was insulated:

- **RUSTSEC-2026-0194**, quadratic attribute duplicate checking. The serde
  deserializer probes every start tag for `xsi:nil` through the default,
  checks-on attribute iterator, which compares each attribute name against
  every previous one in the same tag — O(N²), pure computation, so no I/O
  timeout on the consumer can interrupt it. A single crafted tag with enough
  attributes stalls the parse for minutes.
- **RUSTSEC-2026-0195**, unbounded namespace allocation. `de::from_str` is
  built on `NsReader`, which copies every `xmlns` declaration into resolver
  heap before the consumer ever sees the event; a crafted start tag forces
  allocations at a multiple of its own size, with no cap and no knob to add
  one.

What reachable means here, and what it does not: the only bytes that parser
ever sees come from `https://s3.amazonaws.com/spec.ccfc.min` — Firecracker's
public kernel bucket — over TLS, on the blocking one-shot `image` import path.
Exploiting either defect requires that endpoint, or the TLS path to it, to
turn hostile, and the blast radius is a hung or OOM-killed `isopod image`
command in the operator's terminal. No sandbox, no guest, and no long-lived
process parses this XML. This was a real defect in a parser of remote input,
not a reachable compromise of anything isopod isolates.

`quick-xml` moves to 0.41.0, which fixes both: a hash pre-filter replaces the
quadratic scan, and a start tag declaring more than 256 namespace bindings is
rejected instead of allocated. No isopod source changed — the crate crosses
two 0.x minors, but the API churn was elsewhere; the `de` surface and the
`serialize` feature are intact, and the lockfile holds exactly one copy of the
crate. `cargo deny check advisories` fails on the tree before this commit and
passes after it.

The upgrade's own risk is behavioural drift in deserialization, and the
fixtures in `s3.rs` stand guard over every shape isopod parses — the
pagination fields (including the `Option` continuation token), the
`CommonPrefixes` roll-up, the `Contents` keys, each under the real bucket's
namespace declaration. All pass unchanged. The one behaviour 0.41 adds —
rejecting more than 256 namespace declarations on one element — cannot fire on
a well-formed S3 listing, which declares one.

## [0.12.3] — 2026-07-29

### Fixed — a guest booted with no NIC left loopback down, so it could not talk to itself

The only loopback bring-up lived inside the network-config `apply()`, which is
reached only after `configure_if_requested` finds an `isopod.net` token on the
kernel command line — and the whole point of `--no-network` / `network: false`
is that there is none. The guest's one interface stayed `state DOWN`, so `lo`
came up in every boot except the one that had nothing else.

The failure is expensive because it is partial. `bind()` on `127.0.0.1`
succeeds — binding never required the link to be up — so a workload gets a
socket and a port number and fails later, far from the cause, when something
dials it. Measured with isopod's own suite as the workload (finding #49):
`network: false` gave isopod-core 363 passed / 18 failed, every failure a
broker test that listens and then dials itself; one `ip link set lo up` first
gave 381 / 0.

Loopback is now a boot duty, not network configuration: the agent's `main()`
brings `lo` up unconditionally (`net::ensure_loopback_up`), before any network
decision, and `apply()` shares the helper so a runtime reconfigure is still a
full replacement on its own. `configure_if_requested` keeps its contract of
being a no-op absent the token. `--no-network` still means what it says about
egress — no NIC is attached and nothing leaves the guest; loopback is the
guest's own plumbing, not a way out.

This changes the agent binary, not the protocol: `PROTO_VERSION` stays 3, and
an existing guest image keeps the old agent until rebuilt. The agent-hash
freshness check exists for exactly this shape of change — once the host
binaries are rebuilt, every agent-carrying image reports stale and the run
path refuses it, naming the fix: `isopod image build-all` for the built
flavors, a re-import (local, from cached blobs) for OCI bases.

Mutation `loopback-left-down-without-a-nic` deletes the unconditional call and
pairs with the boot-order assertion in the agent's tests, so the duty cannot
be refactored away in silence.

## [0.12.2] — 2026-07-29

### Fixed — the refusal named an address, but nothing made it name the right one

`screen_resolved` refuses a name when any address it resolves to is floored, and
that function's own doc calls naming the address load-bearing: the message
reaches an operator's terminal about their own machine, and it is the only thing
that tells them whether they hit a rebinding payload or their own split-horizon
DNS.

Nothing pinned it. Replacing `bad.ip()` with `addrs[0].ip()` — a refusal that
fires correctly and then points at the wrong record — left all 31 tests green.
That was established by applying the change and running the suite, not by
reading it.

**The unit level is the only level that reaches it.** The integration test
asserts against the addresses the host actually resolved, which is right for
what it covers and cannot cover this: `localhost` answers with loopback and
nothing else, so every address it resolves is itself an offender and the match
holds under either implementation. A record that passes and a record that is
floored only coexist in the unit test's pairs.

The assertion now has two halves and the second is the load-bearing one: the
message must name the offender, and must **not** name the record that passed.
Naming `addrs[0]` satisfies the first half in three of the four pairs — only the
good-record-first case catches it, and only the negative half catches it there.
Put in operator terms, what `addrs[0]` does is send someone debugging a
split-horizon resolver to look at the one record that is fine.

Addresses are compared by parsing the literal and printing it back, rather than
by searching for the spelling the table typed, because the two differ: `std`
prints an IPv4-mapped address in mixed notation and a NAT64 one in hex, so a
table's `64:ff9b::169.254.169.254` would never be found in a message that says
`64:ff9b::a9fe:a9fe`.

Mutation `oci-registry-refusal-names-the-wrong-address` pairs with the assertion
so it cannot be refactored away in silence.

### Fixed — the in-sandbox build recipe encoded a payload that was already encoded

`docs/sandbox-build.md` told you to `base64 -w0` a source tarball before handing
it to `--stdin-file`. The channel is binary-safe on both the CLI and the MCP
surface — the bytes are base64'd inside the protocol frame either way — so
encoding them first only inflated the payload by a third, against a ceiling that
is already the binding constraint. The recipe now sends the tarball raw and
states that ceiling: `PutFile` is a single frame capped at `MAX_FRAME_LEN`, so
roughly 6 MiB of raw input, and there is no inbound equivalent to the streamed,
unbounded `copy_out`.

## [0.12.1] — 2026-07-28

### Fixed — a test asserted the host's resolver configuration, not the floor

`the_client_dials_only_addresses_the_floor_allows` checked that the refusal
message named `127.0.0.1`. Which loopback address `localhost` answers with is
the host's business: this developer machine says `127.0.0.1`, GitHub's runners
say `::1` first. The floor behaved correctly on both — the assertion did not,
and the test failed the first time it ran anywhere but the machine it was
written on.

It now asserts against the addresses the host actually resolved rather than
against hardcoded spellings: it asserts the *property* instead of the host. That
is not strictly stronger than the literal it replaced — it deliberately accepts
one thing the old assertion rejected, namely a correct refusal naming `::1`,
which was the false positive. It is unambiguously stronger than the two-way
disjunction that would have been the lazy fix, since that is merely two host
assumptions where there was one.

The old assertion was worse than brittle: it was **inverted with respect to the
v6 floor**. Had the IPv6 loopback branch of `address_is_allowed` been broken,
the first floored record would have been `127.0.0.1`, the message would have
named it, and the test would have **passed** on the very runner where correct
code made it fail.

The listener now binds to whichever address `localhost` answers with first.
That is hardening, not a fix: happy-eyeballs falls back to the other family, and
three sibling tests bind v4 and dial by name on a `::1`-first runner without
trouble. What it buys is that the connector reaches the listener on the family
it tries first, so the test's 500 ms "was the socket connected anyway?" check
catches a broken floor immediately rather than after a fallback.

## [0.12.0] — 2026-07-27

### Added — `image ls` lists imported bases, and `image rm` removes them

`image ls` enumerated the built flavors and nothing else, so an imported base was
invisible to it — while `BaseRef::parse`'s refusal for an unknown base told the
operator to run that very command. A doc and a surface disagreeing is a defect
here, and this was one.

One list, not two: `image ls` answers "what can I pass to `--base`?", and that is
a single namespace — `BaseRef::parse` takes either spelling and a stage records
either in one string. Rows gain `kind` (`builtin`/`imported`) and `source_ref`,
and an imported base gets the **identical** freshness computation a built one
gets, which matters more for imports because every guest-agent rebuild
invalidates them.

`isopod image rm <name> [--force]` implements design decision 5: it refuses while
a stage records that base, names the stages, and a forced removal reports what it
broke. The sidecar is removed **after** the image — the opposite order to
publishing, because here the bytes never change, so the dangerous failure is a
live image left unstamped rather than a new image vouched for by an old stamp.

Over MCP, `image_list` is new and read-only. Import and rm stay CLI-only: nothing
a model asks for can pull bytes onto the host or take a base out from under a
stage.

**The blob cache key was a real defect, not just untidy.** It was
`slug_for(reference)`, which maps every run of non-alphanumerics to one dash, so
`a/b:c` and `a-b-c` collided. A cache directory is an OCI *layout* — the blobs
are content-addressed and safely shared, but the single `index.json` is not. Two
concurrent imports of colliding references could interleave into an image packed
from the *other* reference's manifest, while its sidecar recorded the reference
that was asked for. Every digest still verified, because nothing was substituted
at the blob level: digests answer "are these the bytes that were named", and the
key has to answer "whose layout is this". Now keyed on a readable prefix plus 16
hex of the reference's sha256. Existing `oci-blobs/<slug>` directories are
orphaned but inert; a re-import re-downloads once.

### Fixed — a registry name is judged by the address it resolves to

The destination floor screened URLs and IP literals, so `https://blob.evil/`
resolving to `169.254.169.254` walked straight through, and a name that checked
out could be re-resolved before the socket opened. `SECURITY.md` carried that as
an explicit non-claim.

The client now installs a `reqwest` DNS resolver that applies the address rules
to **every** address a name answers with — one floored record refuses the whole
name rather than filtering it, because unlike the broker's operator-written
allowlist, this name is as likely as not the registry's own text. The check and
the lookup are one act: the connector dials what the resolver returned and
performs no lookup of its own, so there is no interval for an answer to change
in. `dns_resolver` rather than `resolve_to_addrs` precisely because the latter
takes its map at client-build time, and half the hosts a pull dials — redirect
targets, the token realm — arrive mid-pull. TLS still verifies against the name.

A registry named as a floored address literal never reaches a resolver at all, so
`isopod image import 169.254.169.254/x/y` is now refused at construction. The
floor also gained `fec0::/10`, which the guest broker already refused — the two
floors disagreeing was the thing being fixed.

`SECURITY.md`'s non-claim was **replaced with three narrower ones, not deleted**;
the honest remaining gap is the system-proxy path, where the host is handed to a
proxy and nothing resolves locally.

`Reference::is_local` was also wrong for IPv6: it split the authority on `:`, so
`[::1]:5000` yielded `"["` and a bare `::1` yielded `""` — meaning the `"::1"` arm
was **unreachable**, a case listed as supported that could never match. It failed
closed, so an IPv6 loopback registry was refused rather than over-trusted.

### Fixed — two concurrent warm-pool builds could publish each other's bytes

Dogfood finding #32, the only open HIGH and the only one that could publish
corrupt state rather than merely waste work. `snapshot::ensure` created the
snapshot directory and wrote `vmstate.partial` / `memfile.partial` — **fixed
names, no lock**. Two runs of the same warm shape both saw an incomplete
snapshot, both dumped several hundred MiB into those two paths, and both
renamed, so one could publish a memory file the other was still writing. Every
later resume of that shape would then get it.

This is not a contrived race. Any image rebuild empties the pool for *every*
shape at once, and the MCP tool description actively invites concurrent
sandboxes from separate agents — so two runs arriving together on a cold pool is
the ordinary case, and the window is the several-second memory dump.

An exclusive per-keyhash `flock` now guards the build, in the shape
`net::claim_lock` already uses (`O_NOFOLLOW`, regular-file check, `LOCK_EX |
LOCK_NB`, so a crashed owner's lock is simply gone and needs no staleness
heuristic). A second arrival waits up to 90 s, **notices the moment the winner
publishes, and reuses that snapshot** rather than building a second one; if the
wait expires it cold-boots, which is what a cache miss does anyway. The lock
lives inside the keyhash directory, because `warmpool rm` removes directories
and skips plain files — a lock beside them would survive every prune forever.

Staging names now carry the pid as well, which the finding named as the
fallback: with the lock gone, a loser can still only destroy its own bytes.

Tested at the primitive *and* at the call site. `ensure` grew an `ensure_at`
seam so the wait-then-reuse path is exercised without booting a VM and without
touching the process-global `$ISOPOD_HOME` — a trap this codebase has fallen
into twice. All three tests fail if the `flock` is removed; three mutations.

### Measured — an imported image boots like a base isopod built itself

The wave-2 exit benchmark, in `BENCHMARKS.md`. 30 samples per cell, one shadow
`$ISOPOD_HOME`, same host, same guest agent, same 1 vCPU / 512 MiB, same
warm/cold path.

| Base | Origin | On disk | warm p50 | `resume_ms` p50 |
|---|---|--:|--:|--:|
| `base-sqfs` | built (busybox) | 1.54 MB | 238–254 ms | 43–50 ms |
| `oci:alpine-3.20` | imported | 3.82 MB | 230–235 ms | 43–45 ms |
| `oci:python-3.12-alpine` | imported | 17.11 MB | 238 ms | 43 ms |
| `base-alpine` | built (py/node/gcc) | 150.72 MB | 318 ms | 48 ms |

The like-for-like pair — the two minimal bases — **tie**. They are reported as
ranges because they were measured twice and the first `base-sqfs` sample was an
outlier with a fat tail (254 ms, p90 320) that did not reproduce (238 ms, p90
262). At this sample size importing costs nothing at boot; it is not faster, and
the changelog does not claim it is.

What moves is content, not origin: the 150 MB toolchain base pays ~80 ms more on
a warm run, and nearly all of it is `exec_ms` (106 ms vs 34) rather than resume.
**`resume_ms` is flat at 43–50 ms across all four** — the snapshot restore does
not care what the base is or how big it is.

Import cost, which is the number an operator feels first: `alpine:3.20` 1.7 s
cold and 1.0 s with blobs cached; `python:3.12-alpine` (4 layers) 3.5 s and
2.4 s. The cached figure is what a re-import costs after a guest-agent rebuild
invalidates every imported base.

`scripts/bench.py` gains `--base`, so a built base and an imported one are
measured by one harness rather than two.

### Fixed — five credential and SSRF defects in the registry client

An adversarial pass scoped to `isopod-oci-registry`, the wave-2 exit criterion.
The crate had never had one. Six attackers over separate surfaces, every serious
finding then handed to a skeptic told to refute it. Each defect below was
reproduced before it was fixed.

**The Docker Hub credential was sent to every registry.** `docker_config_auth`
tried three keys and returned the first hit; the third was Docker Hub's legacy
`https://index.docker.io/v1/` key, tried **unconditionally**. So any operator who
had ever run `docker login` sent that credential to whatever registry they named
next — `isopod image import evil.example.com/x/y` handed it over on the *first*
request, before any challenge, with no redirect and no hostile-registry
behaviour required. For a `localhost` reference the scheme is `http`, so it went
in the clear. Measured with a config containing only the Hub key: all six
references tested came back with the Hub credential. The legacy key is now
consulted only when the reference actually names Hub, and keys are matched to
the host they name — `ghcr.io.evil.com` is not `ghcr.io`.

**A token realm had no destination floor.** `Challenge::parse` required only
that the realm be https *or* loopback — and the loopback half was ungated, while
the identical exemption on the redirect path was gated on the operator having
named a local registry. So a remote registry could answer `401` with
`realm="http://localhost:5000/token"` and have the client post the operator's
credential, in the clear, to whatever was listening on their own machine; or
name `https://169.254.169.254/`, which is https and is the cloud metadata
endpoint. The realm now goes through the same predicate a redirect target does.
One floor, not two, because the second one was the weaker one and it was on the
path that carries a credential.

**A credential dropped at one hop came back at the next.** `carry_credential`
was recomputed per hop from `may_carry_credential(current, next)`, which compares
the two ends of one hop. Once a redirect had taken the client to the attacker's
origin, the next hop compared their host to their host, said yes, and
re-attached the token the first hop correctly dropped. Two redirects instead of
one defeated the origin rule entirely. It is now a latch. The predicate was
never wrong — the loop threw its answer away — so this is caught by a
fake-registry test that redirects twice, not by a unit test of the predicate.

**A host reached by redirect could start the token dance.** The `401` branch did
not consult `carry_credential`, so a CDN the registry redirected to could
challenge the client, name a realm, and be paid in the operator's
`~/.docker/config.json` credential. A CDN has no business challenging us; the
pull now fails with its 401.

**IPv6 spellings walked through the SSRF floor.** The floor screened
`169.254.169.254` and matched IPv6 by prefix, so `[::ffff:169.254.169.254]` —
the same address, IPv4-mapped — was allowed, as were the IPv4-compatible and
NAT64 (`64:ff9b::`) spellings, and CGNAT space. An IPv6 literal is now reduced
to the IPv4 address it names before the rules are applied. The crate's own doc
had claimed this was "the same destination floor the guest egress broker
applies"; the broker handles mapped spellings and this did not, so the claim was
false as well as the code being wrong.

**A pinned digest went unverified when the blob was already cached.**
`repo@sha256:X` is a promise about exact bytes, and the by-digest fetch *inside*
the index branch checked it — the top-level one did not. It only showed on a
re-pull: the write path skips a blob that is already present and correct, so a
substituted body was never hashed, while the config and layer descriptors
driving the rest of the pull were parsed straight out of it. The same rule now
applies to both, before anything reads the bytes.

`SECURITY.md` gains an import section stating what holds and what is not
claimed — in particular that this floor judges the URL, not the resolved
address, so it is not equivalent to the broker's resolved-address gate.

One existing test asserted a vulnerable behaviour (`http://localhost:5000` as an
acceptable realm) and now asserts the fix, which is the second time this session
a test had encoded the defect it was named for.

### Added — a run can boot an imported base, and its config becomes run defaults

`--base oci:<name>` (and the same over MCP) boots an imported image. Verified
live: `alpine:3.20` pulled from Docker Hub, imported and cold-booted in ~0.8 s
running a command as root, then committed as a stage and forked — the stage
records `oci:alpine-3.20` with the image's content id, and the fork resolves it
back without `--base`.

Base selection is now a `BaseRef`: a closed type at the CLI and MCP edge, plain
`(slug, digest)` strings everywhere the choice is persisted. `StageMeta::base`,
`BaseId` and `SnapshotKey::base` were already strings, so nothing stored
changed and no stage needed migrating — a `RootfsFlavor::Imported` variant would
have rippled through every match on the enum instead. The `oci:` prefix is
required: a bare name would collide with the flavor slugs the moment somebody
imported an image called `base-alpine`, and an unknown base now says how an
imported one is spelled.

The image config becomes **defaults, never behaviour**. `Env` is merged *under*
the run's own environment and `WorkingDir` is used only when the run names no
cwd, so a `python:3.12` base finds `python` on `PATH` without the caller
restating it, while a run that sets `PATH` still wins. Verified both ways, with
a built-in base as the control: it keeps the agent's baseline `PATH` and picks
up nothing.

The defaults come from the base the run **actually resolved**, not from the
`--base` field. A fork boots the base its stage recorded and ignores `--base`,
so reading the caller's field would apply one image's environment to a run
booting a different image. A `WorkingDir` of `/` or `""` is treated as "no
opinion" rather than forced onto the run, and an `Env` entry with no `=` is
skipped rather than half-guessed.

### Added — `isopod image import`

Three ways in, one path after that:

```bash
isopod image import alpine:3.20
isopod image import --oci-layout ./layout --name my-base
isopod image import --docker-save ./saved.tar --name my-base
```

Pull (or read) an image layout, verify every blob, unpack the layers through the
confined extractor, adapt the tree, pack it and stamp it. Verified live against
Docker Hub: `alpine:3.20` and `busybox:1.36` both import and pack, and the same
image imported from a registry, from a local layout and from a tarball produces
the **same content id** — three sources converging on one image, which is what
makes the layout and tarball paths worth having rather than merely present.

Blobs are cached under `~/.isopod/images/oci-blobs/`, so a re-import is local.
That is not a nicety: an imported base is stamped with the guest-agent hash it
was built against, and every agent rebuild invalidates every imported base.

A legacy `docker save` archive — the pre-OCI format, a top-level `manifest.json`
naming `<hash>/layer.tar` — is refused by name, with the `skopeo` command that
converts it. It is not an image layout, and the layout reader's own "no
`oci-layout`" is accurate and useless for the operator holding one. Failures
name the path the operator actually typed, not the temporary directory a tarball
was extracted into.

Not yet wired: an imported base cannot be selected with `--base`. The run path
resolves bases through the built-in flavor enum, and widening that is the next
step, with the image config becoming run defaults at the same time.

### Added — an unpacked OCI tree becomes a base isopod can boot

The adaptation half of an image import. It takes the directory tree the
extractor produces and adds the few things the guest agent needs in order to be
PID 1: the agent at `/.isopod/init` with `/init` pointing at it relatively, the
three empty overlay mountpoints (`/overlay`, `/mnt`, and a `/layers` that must
stay empty), the pseudo-filesystem mountpoints an image happens not to ship, and
a `/tmp` if there is none. The image's own `/sbin/init` is left alone — on a
Debian-derived image that is systemd, and the kernel boots `init=/init`, so
`/init` is the only path isopod has to own. An image that ships its own `/init`
has it replaced, and the sidecar records that it did.

**isopod runs your image's filesystem, with isopod's init** — not "isopod runs
your container". An imported image's `ENTRYPOINT` can never be PID 1, because
PID 1 is the agent that does the overlay mounts, the pivot and the RPC. The
entrypoint, command and `USER` are recorded and never acted on, and the ones
that are *ignored* rather than merely unused say so in the command's own output.

An image with no `/bin/sh` is refused by name at import time, with the shape of
image that does work. Distroless and scratch images cannot be run by a surface
whose exec is `/bin/sh -c`, and the alternative to refusing is an exit 127
inside a VM, long after the import looked like it worked. The check resolves
`/bin/sh` **within the image**: `Path::exists()` follows an absolute link like
`/bin/sh -> /bin/busybox` against the *host's* root, so on an ordinary machine a
distroless image would have passed.

The pack is the built-in flavors' pinned `mksquashfs` invocation plus a
pseudo-file carrying the setuid, setgid and sticky bits — which is the only
place those bits are ever applied. They are never written to the host tree,
where they would sit on attacker-authored files in the operator's home before
any VM exists. Every path in that pseudo-file is quoted and escaped: the format
is space-delimited with a type field in second position, so a tar entry named
`evil c 0666 0 0 1 3` would otherwise render a line that reads "create a
character device". And because `mksquashfs` *silently* ignores a pseudo-file
line naming a path it cannot find — exit 0, no diagnostic — the pack verifies
that as many special-mode entries came out of the image as went in, rather than
treating a successful exit as evidence.

The sidecar gains an `oci` section recording the reference, the resolved
platform, the manifest and config digests and every layer digest, so a re-import
is a local operation. That matters more than it sounds: the freshness check
compares the *agent hash*, not only the protocol version, so every guest-agent
rebuild invalidates every imported base.

No CLI surface yet — `isopod image import` is the next step, and the
documentation lands with the command rather than ahead of it.

### Fixed — a setuid bit does not survive its own removal

`Report::setuid_paths` is what the pack step reapplies inside an imported
image, and it was the *union* of what every layer set rather than a description
of the finished tree. Three ways an image could get back a privilege it had
given up:

- A layer that rewrites a path **without** the bit left the earlier layer's
  recording in place, so `RUN chmod -s /bin/su` in a Dockerfile became a no-op
  the moment isopod imported the image. This is the one that matters: it re-arms
  setuid on a binary whose author disarmed it.
- A path a later layer replaced with a **directory or a symbolic link** kept the
  old file's mode, so the pack step would have applied a vanished file's `04755`
  to whatever now occupied the path.
- A path deleted by a **whiteout**, or hidden by an **opaque marker**, stayed in
  the list. `mksquashfs` ignores a pseudo-file line naming a path it cannot
  find — silently, and with exit 0 — so the image was unharmed, but the report
  an operator reads named files the image does not contain.

The set is now resolved as the layers are applied: a bit is recorded when an
entry carries it and dropped when an entry replaces that path without it, and
the deletions are reconciled at `finish()` by *asking the tree* rather than by
reimplementing the whiteout and opaque rules a second time — a second
implementation of a deletion rule is a second chance to disagree with the first.
`setuid_paths` is now documented as a snapshot rather than a per-layer delta,
sorted by path, and both the per-layer report and the running total carry the
same resolved answer instead of two different meanings for one field.

Found while building the pack step that consumes it, which is the first code to
ever read the field for its stated purpose. Two of the suite's own assertions
had encoded the defect — one expected a whited-out file to stay in the list.

Stages now record which *build* of the base image their layers were made over,
and a fork refuses a base that has been rebuilt since. Existing stages are
unaffected: they carry no stamp, so there is nothing to disagree with, and they
fork exactly as they did.

### Fixed — a base image built twice from one tree is the same image

`mksquashfs` wrote the current time into the superblock and copied each file's
mtime out of the assembly directory, which is created fresh on every build. So
`isopod image build-rootfs --force` over an *unchanged* tree minted a new content
id: measured, two runs four seconds apart produced two different images of the
same root filesystem. (Three runs inside one second produced one, which is what
made it look reproducible.)

Nothing about that id is cosmetic. It is what a stage records as the base its
layers were made over and what the warm pool keys a snapshot on, so a rebuild
that changed nothing retired every stamped stage on the flavor and orphaned a
512 MiB snapshot — and `image build-all` is documented as *required* after a
`PROTO_VERSION` bump, which made the mandatory operation the expensive one.

The pack now pins both halves of the clock, `-mkfs-time` for the superblock and
`-all-time` for the files. Each alone still moves the id; together the same tree
packs to the same bytes across any gap, while a real content change still moves
it. 1980-01-01 rather than the epoch, because it is the earliest instant a
DOS/ZIP date field can represent and a guest that archives something it copied
out of the base should get a valid date. Nothing in the guest reads base
timestamps: `base-alpine` ships hash-based bytecode caches (PEP 552), and every
file a run writes lands in the overlay upper with a real, strictly newer mtime.

`SOURCE_DATE_EPOCH` is removed from the packer's environment rather than
honoured. squashfs-tools reads it itself and treats it as competing with the
flags — with both present it exits `SOURCE_DATE_EPOCH and command line options
can't be used at the same time to set timestamp(s)` and builds nothing, so an
operator whose shell exports it, which is the ordinary reproducible-build
environment, could not build an image at all. It also settles what the variable
would otherwise raise: an image id that moves with the ambient environment is the
defect the pin exists to close.

This is a **behaviour change to a guarantee, not only a speedup**: a rebuild is
no longer proof that a base has moved, so the prose that said "any rebuild
counts" is now wrong and has been corrected in `README.md`,
`docs/getting-started.md`, `docs/mcp-usage.md` and the `Unverifiable` refusal —
which used to promise that re-stamping a sidecar-less image would always mint a
new build, and now says it restores the same id when the tree has not changed.
The ext4 dev flavors are deliberately untouched: they are not stage bases, so no
content id is keyed on them.

### Added — a stage records the base build, and a fork checks it

`StageMeta` gains `base_sha256`: the content id (the image sidecar's sha256) of
the base image the run actually booted. Every commit stamps it; `isopod stage
list` / `stage info` and the MCP `stage_list` / `stage_info` surface it.

The flavor slug was never enough to identify a base. `isopod image build-all`
replaces `base-alpine` with a different root under the same name — new Alpine
packages, a new guest agent — and a stage's layers are overlay **upperdirs over
that build**. They still mount: the merge succeeds, the run starts, and the
breakage arrives later as a chain whose contents no longer match what is beneath
them (site-packages whose interpreter moved is the usual shape). Nothing in the
0.11.0 run path could tell the two apart.

`isopod run --stage <ref>` now compares the stamp against the image on this host
before anything boots, and refuses a mismatch, naming both content ids and both
ways out. **Every stage in the chain is checked, not just the one named**: the
layers of every ancestor are mounted too, and checking only the tip let a single
unstamped link launder everything behind it. The same comparison runs in the
store, so a stacked commit cannot record a chain that mixes *known-different*
builds unless the operator opts in below.

Two cases deliberately do **not** refuse:

- **A stage with no stamp** — everything committed before this release. Nothing
  was recorded, so there is nothing to compare; it forks unchecked, as before.
- **An image with no build sidecar.** The run warns that the check could not be
  made and points at `isopod image build-all`, rather than refusing to boot over
  a missing stamp.

One case refuses in **every** case, including under the override below: a
**flavor mismatch**. Those layers are not stale, they belong to a different root.

`ISOPOD_ALLOW_BASE_SKEW=1` overrides the refusal, loudly. It covers the commit as
well as the boot on purpose: rebuilding the guest images changes the base of
every stage at once, and an escape hatch that boots the fork but then refuses to
save what it produced would strand exactly the work it exists for. It is an
escape for a run, not a repair: the layer it commits records the new image while
its ancestors keep their own stamps, and since the check walks every link, the
stage it produces still needs the variable to boot. Rebuilding the stage on the
current image is what clears it; the store keeps the evidence either way.

Eight mutations were added to `scripts/mutation-check.py` covering the new
guards: accepting any content id, dropping the stamp at commit time (which fails
nothing at the time and silently disables the check for good), letting the
override excuse a flavor mismatch, the run path never consulting the check at
all, the check seeing only the chain's tip, the commit path always allowing
skew, and a rebuild leaving a stamp that outlives the image it describes.

### Fixed — in this release's own new code, before it shipped

An adversarial pass over the above found five defects in it. They are listed
because the pattern is the finding: three of them were places where the tests
covered the policy and nothing covered the code that calls it.

- **One unstamped link laundered every ancestor behind it.** The fork check read
  only the chain's tip and the commit check only the immediate parent, so a
  stage committed while the image happened to be unstamped vouched for
  everything under it — permanently, and reachable without touching anything by
  hand (a pre-0.12.0 binary sharing the same `$ISOPOD_HOME` writes exactly that
  link, and the MCP server routinely runs an older inode than the CLI). Both
  sites now judge the whole chain.
- **The override excused a flavor mismatch at boot**, which this changelog and
  both docs said it never does — one `Mismatch` variant, one `if allow_skew`
  arm. `BaseCheck` now distinguishes `RebuiltBase` from `WrongFlavor`, so the
  policy cannot be written that way again.
- **The whole check could be deleted from the run path with the suite green.**
  Every test drove the policy function directly; nothing proved the run path
  consulted it. `resolve_stage_plan` is now root-parameterized and tested, and
  the skew opt-in is resolved once into the boot plan instead of being re-read
  from the environment at commit time.
- **A rebuild replaced the image before stamping it**, so any failure in between
  left a new image vouched for by the old sidecar — which reads as *verified*
  and is not. The stamp is now cleared before the image is replaced (failure
  lands on "unstamped", which is reported) and written atomically.
- **A non-ASCII content id panicked the pre-boot check**, because the id was
  truncated by bytes for the message. Ids come off disk unvalidated.

### Changed — the base image ships one mountpoint, not ten

Base images carried `/rom` and ten numbered `/layers/0..9` directories. Since the
guest started mounting a **tmpfs** over `/layers` and creating `/layers/<i>` per
layer at boot (0.11.x, dogfood finding #26), the baked directories have decided
nothing — the off-by-one they caused is gone, and any depth the chain cap permits
works without them. `/rom` had no reader at all. Both are dropped: a base image
now ships `overlay`, `mnt`, and an empty `layers`.

An image only picks this up when it is rebuilt, and an image still carrying the
old directories is harmless — the tmpfs masks them. There is no need to rebuild
for this reason alone.

### Included from the unreleased 0.11.1

`scripts/mutation-check.py` itself, which asserts that a fixed set of deliberate
breakages makes the suite fail — CI proves the tests pass, not that they check
anything. It failed on its first run: the `copy_out` staging-name test sampled a
single name where the clamp point depends on the pid's digit count, so whether
it caught a mid-character split was decided by luck. That test now sweeps every
UTF-8 width at every suffix length the real caller can produce.

### Added — `isopod-oci-unpack`, the layer extractor, on its own

A new workspace crate that applies OCI image layer tars onto a directory tree.
**Nothing depends on it yet, and it is wired into no command** — that is the
point. It is the one component whose failure writes attacker-authored bytes into
the operator's home directory *before any VM exists*, so it exists and gets
attacked on its own before anything dials out to a registry.

Confinement is a directory-fd walk from the destination root with `O_NOFOLLOW`
on every open, rather than a check against a resolved path. The difference is
the cross-layer symlink: layer 1 ships `foo -> /home/you`, layer 2 ships
`foo/.bashrc`, and each layer is innocent read alone. It is also why a
*dangling* link — the shape that escaped `copy_out` in 0.11.0 — needs no special
case here: nothing ever looks at a link's target.

Also enforced, each with a test and a mutation: `..` and absolute names refused
rather than normalised; hard-link targets confined by the same walk, and linked
without `AT_SYMLINK_FOLLOW` so a link-to-a-link cannot share a host inode;
device and FIFO entries skipped and reported; setuid, setgid and sticky bits
recorded for the pack step and never written to the host; `.wh.` and
`.wh..wh..opq` whiteouts applied so that nothing an image author deleted
survives; cumulative anti-bomb ceilings measured on the decompressed stream; and
a staging directory that is discarded on drop, so a refused image leaves nothing
behind at all.

Attacking the crate during development found one escape that the design did not
anticipate: a whiteout marker spelled `.wh...` yields the delete target `..`,
which is the only name that reaches the delete walk without going through the
entry-name component loop. At the top of the tree that names the staging root's
parent — the caller's own destination directory — and the recursive delete
emptied it. Refused now in both the name planner and the syscall layer, with a
mutation for each so the pairing cannot quietly become decorative.

A second pass, scoped to the crate alone before anything is wired to it — the
wave-1 exit criterion — found **no escape**. The directory-fd walk, the
hard-link confinement, the whiteout and opaque rules and the teardown all held
against the inputs built against them, including the delete paths, which refuse
a planted link exactly as the write path does. What it did find were two defects
either side of the confinement, both the shape the previous three passes kept
finding: a fix that covered the branch that worked.

- **The operator's umask reached the image.** `mkdirat`'s mode argument is
  masked by the process umask. The regular-file path already knew that and set
  its mode explicitly; the directories created on the way to it did not, and
  neither did the staging root. Under `umask 077` every directory no entry
  describes came out `0o700` instead of `0o755` — and since the pack step turns
  this tree into an image whose sha256 *is* its identity, one source image would
  have imported to two different images on two hosts.
- **A usrmerge link was reported as an escape.** A directory mode held back
  because the directory denies its owner write access is applied at `finish`, by
  which time the path may be something else. Gone and replaced-by-a-file were
  handled; replaced by a *symbolic link* was not, and refused the whole image at
  the very last step. `/lib -> usr/lib` is how every usrmerge image is shaped, so
  this was an ordinary image rejected with a message accusing its author of
  hand-crafting an attack.

The umask test cannot set a umask — it is per-process and Rust runs tests as
threads — so it re-executes the test binary under `umask 077` and asserts on
what that child produced.

## [0.11.0] — 2026-07-26

A hardening release. An adversarial review of shipped 0.10.0 — 34 agents, no
design framing supplied, findings verified by exploiting them rather than by
reading — turned up eleven real defects. Two of them invalidated 0.10.0's stated
threat model outright, so they are fixed here rather than deferred. **Existing
hosts must re-provision before their next filtered run** (see the kernel guard
below); public-slot runs are unaffected.

A second adversarial pass — this one over the fixes themselves, before they were
pushed — found nine more defects, several of them *in* the new code. Those are
folded in below rather than listed separately, but three are worth calling out
because the first version of this release claimed they were closed and they were
not:

- **`copy_out` escaped the confinement through a dangling symlink.** `Path::exists`
  follows a link and returns false when its target is absent, so a link to a
  not-yet-existing file outside the root fell past the "resolve it outright"
  branch, was treated as an ordinary new file, and passed — after which
  `File::create` followed it and wrote the guest's bytes outside, while the result
  reported the in-root path. The test suite missed it because every symlink case
  it covered had an *existing* target, which is the branch that worked.
- **The confinement never excluded isopod's own state directory.** The root
  defaults to the server's working directory, and `$HOME` is an ordinary working
  directory for an MCP registration — which put `~/.isopod` *inside* the
  confinement and handed back the exact credential-store read this release is
  about. The state directory is now refused for every root, and with the
  confinement switched off.
- **`vm_gc` stopped collecting anything under MCP.** `owner.pid` records the
  supervisor's pid, which for the CLI is the run's own process and for MCP is the
  *long-lived server* — so every record the server ever wrote reported `live`
  forever. Observed on a real host: 12 of 33 records live with one VM running.

A **third** pass, over the second pass's fixes, found four more. Two of them were
in the second pass's own new code, and both are stated here rather than folded in,
because the pattern is the finding: a fix that closes the case it was shown is not
the same thing as a fix that closes the class.

- **0.11.0's own `copy_out` confinement had a second escape, one spelling away
  from the first.** The dangling-symlink guard above calls
  `std::fs::symlink_metadata(path)` — and `symlink_metadata("link/")` returns
  `ENOTDIR`, because a trailing separator forces directory resolution. So the
  guard never ran. `Path::file_name()`/`parent()` then normalised the separator
  away again, the walk-up returned the bare in-root path, the prefix test passed,
  and `File::create` followed the link. Four spellings did it — `link/`, `link//`,
  `link/.`, `link/./` — and they **overwrote** an existing host file, not merely
  created one, which put `~/.isopod/credentials.json` back within reach through a
  planted link and defeated the state-directory carve-out. The result still
  reported the in-root path in `copied[].host`, so the operator saw a path inside
  the root while the bytes landed outside. Demonstrated end to end against a real
  `isopod-mcp`. The regression test the second pass added missed it because it
  built the destination with no trailing separator — the one spelling that already
  worked.

  The fix is in two places on purpose. The destination is normalised before any
  guard runs — trailing separators and `.` components dropped, a `..` below the
  deepest existing directory refused outright and any other `..` resolved against
  the existing prefix and re-tested against the root — so no guard can be shown a
  different final component from the one that will be opened. And the write itself
  now opens with **`O_NOFOLLOW`**, so it refuses to traverse a link whatever the
  check concluded — because a path check and a `File::create` are two lookups of
  one name, and a symlink planted between them defeats any amount of checking.
  `O_NONBLOCK` goes on with it, so a FIFO destination fails instead of blocking a
  thread forever. This is on the shared path, so the CLI gets it too: `isopod run
  --copy-out g:/host/p` now writes to `/host/p` or fails, rather than through
  `/host/p` to wherever it points. That is a statement about the **final
  component**; a symlink among the parent directories is still followed, which
  `SECURITY.md` records as an explicit non-claim. The read path (`stdin_file`) was
  verified unaffected — it canonicalises, and both spellings were already refused.
- **The pinned-host floor checked a different parser than the dialer uses.** The
  guard added earlier in this release classified a credential's pinned host with
  `host.parse::<IpAddr>()` and skipped anything that failed, reasoning that a name
  goes through the floored resolver. But the upstream leg is
  `format!("https://{host}{path}")` handed to `reqwest`, whose URL crate uses the
  **WHATWG** host parser — which reads decimal, hex and short-form IPv4 as
  addresses and normalises them to a dotted quad *before* hyper sees the
  authority, so no resolver is ever consulted. `2852039166`, `0xa9fea9fe`,
  `2130706433`, `127.1`, `0177.0.0.1` and `0x0a6b0801` all failed
  `IpAddr::from_str`, all skipped the guard, and all dial `169.254.169.254`,
  `127.0.0.1` or a sibling run's broker gateway. The guard now classifies the host
  with the same parser the dialer uses, and additionally refuses any pinned host
  the parser rewrites at all — `egress.denied` recorded `host: "2852039166"`,
  which an operator cannot grep for `169.254.169.254`, so the store, the log and
  the destination are now required to be one string. A pinned *name* that the URL
  parser accepts is untouched and still floored at resolution; one whose last
  label is all digits or `0x`-hex (`api.123`) takes the parser's address branch,
  fails there, and is refused at startup — `reqwest` could not have dialled it
  either, so the credential could never have been spent.
- **Three lockfile shapes the `flock` claim stopped handling.** Replacing
  `O_CREAT|O_EXCL` with `O_CREAT` (necessary — the lockfile is now durable)
  incidentally dropped the refusal `O_EXCL` was providing. A **FIFO** at
  `slot-<i>.lock` made the claim block in `open` forever, with no timeout on that
  path, which under the MCP server wedges a blocking-pool thread for good; a
  **symlink** was followed, putting the `flock` on an inode outside the `0700`
  state directory; a **directory** failed the entire pool with every other slot
  free. The claim now opens with `O_NOFOLLOW|O_NONBLOCK` and `fstat`s the
  descriptor, refusing anything that is not a regular file, and a slot that cannot
  be opened is skipped with a warning instead of failing the scan — the exhaustion
  error says how many were skipped and why. Not guest- or MCP-reachable (the
  directory is `0700` and `hostio` refuses `~/.isopod` for every root), so this is
  robustness rather than a boundary crossing, but the hang was new in this release.
- **`SECURITY.md` claimed a property the code does not have.** The `flock` bullet
  said the slot was "reclaimable immediately with nothing to sweep and no liveness
  guess". The *lock* is — the kernel drops it, `kill -9` included, verified. The
  *slot* is not: a `kill -9` of the supervisor leaves its Firecracker holding the
  tap, and the next run's `registry::reap_orphans` has to SIGKILL it first, on a
  pid-and-start-time liveness test. Reproduced: the lock read free within 2 s while
  the orphaned VMM still held `isopod-tap0`. Both that bullet and the CHANGELOG's
  "correct the instant after" now say what actually happens.

A **fourth** pass, over the third pass's fixes, found no way to escape the
confinement — three independent reviews, 42 end-to-end escape attempts all
refused with no filesystem delta, a 2,770,211-host fuzz of the pinned-host
classifier with zero invariant violations, and 36 concurrent slot claimants with
zero double-claims. It found one behavioural defect and a cluster of prose that
overstated the code, all fixed here:

- **A failed `copy_out` destroyed the file it was aimed at.** The destination was
  opened `O_TRUNC` before the guest had said whether the source existed, and
  unlinked again on the error path — so naming any writable file and producing no
  bytes deleted it. Reproduced end to end: a `--copy-out` of a nonexistent guest
  path removed 23 bytes of unrelated host data. Bytes are now staged in a sibling
  `.<name>.isopod-<pid>-<n>.part` and renamed onto the destination only once the
  guest reports the file complete, so a failure leaves it byte-identical and a
  success replaces it in one step with no half-written window. A device or a
  reader-backed FIFO is still written straight through — renaming onto `/dev/null`
  would replace the node with a regular file.
- **Prose that claimed more than the code did**, in eleven places, all introduced
  by this release's own fixes. `docs/m4-verify.md` told an operator to conclude
  "slot 0 is free" from `flock -n`, the exact inference this release documents as
  false; it also called the lockfiles "always present" when they are created
  lazily. `net.rs`'s module doc, `claim()`'s contract and `claim_network()`'s —
  the wrapper one frame above it — all said crash recovery needs no step, while
  both callers run `reap_orphans()` first for the reason the contract denied.
  `SECURITY.md` and the CHANGELOG said `..` is "refused" when it is resolved and
  re-tested. The CLI's `--copy-out` help promised bytes "land on the path you named
  or nowhere", which the parent chain and the truncation defect both contradicted.
  `docs/credentials.md` said a pinned host is used "exactly as it will be dialled"
  (case and one trailing dot are normalised first) and that a pinned name is
  "untouched" (one whose last label is all digits is refused at startup). None of
  these was a hole; all of them were the defect class this release spent three
  commits fixing, so they are fixed rather than deferred.

A **fifth** pass, over the staging fix itself, found the pattern had not stopped.
The new "a failed copy leaves nothing behind" invariant had one hole: a malformed
base64 chunk returned straight out of the stream loop past the cleanup, and since
every attempt takes a fresh sequence number, a guest repeating it leaked one
staging file per attempt rather than reusing one name — unbounded host disk, in a
function whose neighbouring comment exists because "a malicious agent could stream
forever and fill the host disk". The staging path now owns its own `Drop`, so the
invariant holds for every early return rather than the ones written so far. Also
fixed: the staging suffix could push a legal destination name past `NAME_MAX`; the
publish half of the copy had **no test at all**, so deleting the mode mask kept the
suite green; the `flock` line added to `docs/m4-verify.md` two commits earlier
described flags that do not do what it said (`flock(1)` always creates the file,
and `-E 1` is the default); and an eleventh contract, on the `claim_network()`
wrapper, still said crash recovery needs no step.

A **sixth** pass found no defect in the drop guard — 24 concurrent copies with 12
aimed at one destination left every success byte-intact and no residue, and the
pass-5 leak is gone (five malformed chunks left five staging files before, zero
now). What it found was one operational hazard and two false claims:

- **The installed binaries predated every fix.** `~/.local/bin/isopod` and
  `isopod-mcp` were 14 hours older than the first of them, so the running MCP
  server — whose host-I/O root is the source tree — still held the delete
  primitive while the repository was green and pushed. "CI green" is not "in
  force"; the binaries are now reinstalled and a canary survives.
- **A test docstring claimed coverage that did not exist**, contradicting a code
  comment 1030 lines away that had it right: removing `O_NOFOLLOW` from the
  staging open changes nothing observable, because `O_CREAT|O_EXCL` already
  returns `EEXIST` on a symlink. Only `O_EXCL` is pinned, and the docstring now
  says so.
- **The `tokio::time::timeout` added to the FIFO test was inert.** `tokio::fs`
  hands the open to `spawn_blocking`; cancelling the future does not cancel a
  thread parked in `open(2)`, and the test runtime's drop then waits for it —
  measured, the suite wedged identically with and without the timeout. The open
  now runs on a detached thread joined through `recv_timeout`, and dropping
  `O_NONBLOCK` makes the suite go red in ten seconds instead of hanging.

Four mutants that survived a mutation survey are now killed: publishing before
the rename rather than after, classifying a device as staged, dropping the
character-boundary walk-back in the name clamp (a reachable panic — the
destination is caller-supplied and may be multibyte), and widening the staging
file's in-flight mode. The staging error hint no longer tells every failure that
the directory must be writable when the cause was a leftover file or a missing
directory. And a guest-chosen mode is no longer applied to a `Direct`
destination: carrying the exec bit exists so an artifact isopod created arrives
runnable, and a device or FIFO the operator already owns is not that.

Pass 4 also produced one new **non-claim** rather than a fix. `copy_out` keeps the
executable bit by design — a binary built in the sandbox should arrive runnable —
and the default host-I/O root is the server's working directory, i.e. a project
containing `.git/hooks/`. A copy-out to `.git/hooks/pre-commit` therefore lands
executable and runs on the operator's next `git commit`, outside any VM;
demonstrated against a running server. Stripping the bit by default would break
artifact extraction, and enumerating which files a project treats as code is not
something isopod can do — `.envrc`, a `Makefile`, a CI config and a
`node_modules/.bin` entry are all the same shape. `SECURITY.md` states the limit
plainly instead: nothing in a writable root is safe from being made executable.

### Fixed — the MCP surface could read and write arbitrary host files

`sandbox_run`'s two arguments that name a **host** path, `stdin_file` (read) and
`copy_out[].host` (write), were used verbatim. That was demonstrated end to end:
`stdin_file: "~/.isopod/credentials.json"` returned the credential store in
`stdout`, and `copy_out` wrote guest-authored bytes anywhere, creating parent
directories. Either one undoes the premise the credential design rests on — that
the caller is a model whose context the sandboxed code may have written, and so
may name an alias but never a secret.

Both paths are now resolved and confined to a **host-I/O root**, defaulting to
the server's working directory, with symlinks resolved *before* the check so a
link planted inside cannot reach out (including one whose target does not exist
yet — see the note above). `ISOPOD_MCP_HOST_IO_ROOT` moves the root
(`/` restores the old behaviour, explicitly); `ISOPOD_MCP_HOST_IO`,
`ISOPOD_MCP_STDIN_FILE` and `ISOPOD_MCP_COPY_OUT` set to `off` refuse the
arguments outright. The startup log line says which is in force. The CLI is
deliberately unaffected — there the caller is the operator.

The confinement is a path check, so it is also given the things a path check
cannot infer. A **dangling symlink** is refused rather than written through (where
the write would land cannot be resolved, so it cannot be checked), and a
**multiply-linked file** is refused outright (a hard link is a second name for an
inode and resolves to itself, so no prefix test can see it). The destination is
**normalised before any guard runs** — trailing separators and `.` components
dropped, `..` still refused — so no guard can be shown a different final component
from the one that will be opened. And the write opens the final component with
**`O_NOFOLLOW`**, so it refuses to traverse a symlink whatever the check
concluded; a check and an open are two lookups of one name, and only the syscall
can close the gap between them. isopod's own state
directory is refused whatever the root is, including with the confinement off.
An empty `ISOPOD_MCP_HOST_IO_ROOT` no longer reads as a root — `Path::starts_with("")`
is true for every path, so it admitted everything while the log said "confined to " —
and a switch set to anything not recognisably affirmative now reads as *off* rather
than staying open.

`stdin_file` also gained the guards the credential loader already had: regular
files only (a FIFO blocks the read forever, `/dev/zero` grows the buffer until
the host is out of memory) and a 4 MiB ceiling enforced on the read, not just on
the stat.

`copy_out` no longer applies the guest's reported mode verbatim. The exec bit
still travels — that is why the mode travels at all — but setuid, setgid, sticky
and group/other write are cleared, and owner read/write is always granted. A
sandbox could otherwise land a setuid-to-the-operator binary in the project
directory with `chmod 6777`.

### Fixed — the broker dialled from the host with no destination floor

The broker resolves and connects on the guest's behalf **as a host process**, so
the packet filter's public-only-egress rule — which governs *forwarded* traffic —
never applied to it. An allowlist entry that resolved inward was a confused
deputy with host-level reach: `allow_cidrs: ["169.254.169.254/32"]` reached cloud
instance metadata, `allow_hosts: ["localhost"]` reached the host's own services,
and `10.107.0.0/16` reached sibling runs' brokers — including their credential
endpoints.

Every destination is now checked **after resolution**: loopback, link-local,
multicast, broadcast, IPv4-mapped spellings of those, and isopod's own slot
supernet are refused outright; private and CGNAT ranges follow the host's
`--allow-lan-egress`, which until now was recorded in the manifest and never
consulted. The same floor applies to the DNS answers the broker synthesises and
to the credential endpoint's upstream leg (via a custom `reqwest` resolver — that
leg does its own resolution, so a pinned host whose DNS answered `127.0.0.1`
would otherwise have received an `Authorization` header). Refusals are recorded
as `non_public_address`, and the explanation names `--allow-lan-egress`.

### Fixed — every broker listener served every process on the host

All four listeners bind the slot gateway, which is a *host* address: packets a
host process sends there are delivered locally and never cross the
`iifname "isopod-tap<i>"` input rule that gates guest access. So while a run with
`--inject` was live, any local account could `curl http://10.107.8.1:3129/github/user`
and spend the operator's token, with the calls landing in the flight recorder as
though the sandbox had made them. Each listener now serves only its own slot's
guest address, TCP and UDP alike, and closes anything else before reading a byte.
The first refusal explains itself on the supervisor's stderr.

### Added — a filtered slot's enforcement is verified at run time

Nothing checked that the nftables ruleset was still loaded. `slots.json` existing
and the taps existing were the whole test, and taps created with `ip tuntap add`
outlive `nft flush ruleset` — which a firewalld reload performs — so a "filtered"
run would boot on a wide-open slot while its broker held a live token.

`sudo isopod setup` now also clears `net.ipv4.conf.isopod-tap<i>.forwarding` for
every filtered tap. That makes the kernel refuse to forward what arrives there
independently of the ruleset, and — the point — it is **world-readable**, so the
unprivileged runtime can confirm it. Every filtered run checks the whole filtered
pool before anything boots, and the claimed slot again after, and fails closed
with the re-provisioning command. **This is why an existing host must re-run
`sudo isopod setup`:** its taps predate the flag.

`SECURITY.md` now states plainly what this does *not* cover — the guest→host half
of the guarantee still rests on the nftables input chain, and an unprivileged
process cannot read the live ruleset to confirm it.

### Fixed — resource and lifecycle defects

- **The broker's connection bound was not a bound.** The concurrency permit was
  acquired *inside* the spawned task, so every connection was accepted
  immediately and became a task plus a host file descriptor merely *waiting* for
  capacity. A guest opening sockets in a loop exhausted the supervisor's file
  descriptors — which, over MCP, are the server's. The permit is now taken before
  `accept`, so at capacity connections stay in the kernel backlog.
- **An accept error busy-looped.** Under `EMFILE` the error recurs instantly and
  a bare `yield_now` saturated the runtime thread the whole run shares. Now a
  50 ms backoff, on the UDP path too.
- **`vm_gc` collected live runs.** Age was the only protection, and it is a guess:
  the MCP tool passes 60 s against a permitted timeout of an hour. Collecting a
  live run's directory unlinked the vsock socket its remaining RPCs needed and the
  scratch `commit_as` was to freeze — and the missing `owner.pid` then read to the
  reaper as proof of orphanhood, so the next pass SIGKILLed the VMM. gc now skips
  any record with a live owner pid or a running VMM, and `vm_list` reports `live`.

  `owner.pid` now records the pid **and that pid's start time**. A pid alone is
  not an identity: these records outlive their runs by design, so on a busy host a
  finished run's pid is reused and a bare `/proc/<pid>` test reports that run as
  live forever. Records written by an earlier isopod carry only a pid and keep the
  old, weaker check — reading them as dead would collect live runs, which is the
  failure this path exists to prevent.
- **`vm_gc` deleted by a path from `meta.json`.** The record's `vm_id` came from
  the file rather than the directory, so `"vm_id": "../../.."` in any writable
  `meta.json` made `remove_dir_all` traverse out of the vms root — reachable
  through a `copy_out` destination. The directory name is now authoritative.
- **A network slot is now claimed with `flock`, and the staleness heuristic is
  gone.** A run holds an exclusive `flock` on `~/.isopod/net/slot-<i>.lock` for
  its whole lifetime. That deletes the entire class of bug this release spent
  three attempts on: there is no staleness to decide, no write grace, and no
  unlink — the kernel releases the lock when the owning process dies, `kill -9`
  included, so the *lock* is free the instant its owner dies, with nothing to
  reconcile. The *slot* is a separate question and always was: a `kill -9` of the
  supervisor leaves its Firecracker alive and still holding the tap, so the next
  run's `registry::reap_orphans` still has to SIGKILL it before it can boot, and
  that check is a pid-and-start-time liveness test. What is gone is deciding
  *occupancy* by guessing; what remains is killing a process that is demonstrably
  still there. `flock` also belongs to
  the **open file description** rather than the process, so two concurrent runs
  under one MCP server are told apart for free; `fcntl` record locking would have
  handed the second one a lock the first still needed. The lockfiles now carry no
  contents at all, and are no longer unlinked. `net::sweep_stale` is removed.

  **This release introduced a regression that this change closes.** Earlier in
  0.11.0 the claim started writing a `<pid> <nonce>` token into the lockfile so a
  release could tell a sibling run's lock from its own — but the staleness parser
  was left reading the file as a bare pid. Every real lockfile therefore failed to
  parse, took the "unparseable" branch, and was declared stale **five seconds
  after it was written, with its owner alive and its VM on the tap**. Since every
  claim swept first, the next run unlinked a live lock and took the occupied slot;
  the loser's firecracker died on `Open tap device failed … Device or resource
  busy` cold, or `Failed to restore devices … Net:` on a warm resume. Two runs
  more than five seconds apart collided reliably. It failed closed — firecracker
  will not open a tap twice — so it was a reliability defect and not a crossing of
  the isolation boundary, but it was a live one. The tests missed it because they
  claim and release in milliseconds, inside the grace period, and because the one
  test that built a lockfile by hand wrote the bare pid the code had stopped
  writing. No fixture stands in for a *held* lock any more — the regression test
  ages a real lock, taken through the claiming path, past the old grace before
  re-claiming. The two tests that still write a lockfile by hand do so precisely
  to prove an unheld file's contents are never read.

  Also fixed with it, and previously listed here as not fixed: deciding staleness
  and unlinking were two operations, so two claimants reading the same dead pid
  could both proceed, the second unlinking what the first had just written.
- **A run outlived its own timeout.** `getaddrinfo` has no cancellation, and
  dropping the run's tokio runtime waits for every blocking thread with no bound —
  so a name whose nameserver never answered held the `sandbox_run` request (and a
  server thread) for the full resolver budget after the report was built. Both
  resolution paths are now bounded at 5 s and the teardown at 250 ms.
- **The state tree was re-chmodded to `0755` on every call.** Not at create time —
  every call, so `chmod 700 ~/.isopod/vms` was silently undone by the next run,
  and every run's `console.log`, `exec-*.log` and `egress.jsonl` were readable by
  any local account. Directories are now created `0700` and tightened if found
  looser, never loosened.

### Fixed — smaller correctness

- **A failed `--commit-as` no longer destroys the run.** The commit is the last
  thing a run does — after the command has succeeded and after the scratch has been
  cleaned up — and its error was propagated, so a mistyped label discarded the exit
  code, the output and the log paths of work that had already been done. It is now
  reported on stderr and in a `commit_error` field on the report (and on the MCP
  result), with the run's own result intact. This release *introduced* the way to
  hit it, by making a reused label an error.
- **The credential leg's destination floor had a hole for IP literals.** The floor
  is installed as `reqwest`'s DNS resolver, and hyper dials an address literal
  directly without consulting a resolver — so a credential whose store entry pinned
  `169.254.169.254` would have sent the operator's token to the metadata service.
  A run whose credential is pinned to an address the broker will not dial is now
  refused before the broker starts, naming the alias and the address.
- **`vm_list` reports `live`, and `sandbox_run` reports `commit_error`.** Both were
  added to the core report and then not carried through the MCP surface's own
  hand-written projections — so the field existed everywhere except where the tool
  that needs it could see it.
- **Credential aliases are now case-insensitive everywhere.** They were lower-cased
  when resolved but compared case-sensitively against the guest's URL path segment,
  so an alias declared `GitHub` was reachable only as `/github/…`. Folding the
  guest's segment fixed that half and left the other: the *store lookup* was still
  exact, so `--inject GitHub` — the operator's own spelling — did not resolve at
  all. One rule now covers the store key, the flag and the path segment. A store
  declaring two aliases that differ only in case is refused whole, because
  `--inject gh` would otherwise name two different pinned hosts and picking either
  silently is exactly the ambiguity a credential system must not resolve for you.
- `stage: ""` resolved: the empty string is a prefix of every label, so it forked
  whatever single stage was in the store. Now refused.
- `commit_as` could take a label that already referred to another stage, and
  `resolve_in` prefers an exact label match over a prefix — so committing
  `commit_as: "my"` silently redirected every later `stage: "my"` away from the
  stage labelled `myenv`. Reusing a label is now refused.
- Committing byte-identical content under a *different* label reported success
  while recording nothing (the store is content-addressed), so the requested
  label never existed and every later reference to it failed to resolve. Same
  label, same content is still idempotent; a different label is now an error that
  names the existing one.
- **A claim that was too strong, in three places.** `inject.rs`, `SECURITY.md` and
  `docs/credentials.md` all said guest bytes never reach the wire. The path, the
  query string, two header values and the body do cross — what never crosses is
  anything that decides where the request goes or who it is from. Corrected to say
  that instead, including in the 0.10.0 entry above.
- Credential resolution now happens in the early-validation block, ahead of the
  warm-pool snapshot build, so "nothing boots before a credential problem is
  reported" is literally true rather than nearly true.

## [0.10.0] — 2026-07-25

- **Credential injection — a run can spend a credential without ever holding
  it.** A run names an *alias*; the operator declares on the host which secret
  it is, the single host it may be sent to, and — mandatorily — which requests
  it may authorise. `isopod run --inject github` / `sandbox_run(inject:
  ["github"])`. The guest calls `$ISOPOD_CREDENTIAL_ENDPOINT/<alias>/<path>`
  and the host attaches the token, but only for a method and path the operator
  wrote down. See [docs/credentials.md](docs/credentials.md).

  The endpoint is **not a reverse proxy**: the guest does not compose the
  request. It reads a stated intent and constructs a new request from its own parts — its
  own `Host`, its own `Authorization`, a normalised path, and at most two
  allowlisted headers. **Redirects are disabled** on the upstream leg, because
  following one would carry the credential to a host the operator never named,
  chosen by a party who is not the operator. The client also ignores the host's
  own `*_PROXY` variables: those are exactly what isopod exports into a filtered
  guest, so an isopod running inside an isopod sandbox would otherwise route its
  credential leg through its parent's broker.

  `--inject` lives **inside** the egress policy rather than beside it, so naming
  a credential switches the run to a filtered slot. As a sibling field, `--inject
  github` with no `--allow-host` would have left the run on a *public* slot with
  full NAT egress and nothing enforcing the credential's `allow` list — the one
  combination the feature must never produce.

  The pinned host is deliberately not allowlisted, and a direct connection to it
  is refused as `pinned_credential_host` rather than a generic denial: the fix is
  to use the endpoint, not to widen a list.

- **The broker's port set is recorded in the manifest, and a run fails closed
  without it.** The credential endpoint needs port 3129 open on a filtered
  slot's gateway, and that hole is baked into nftables once, as root. A host
  provisioned by 0.9.x has no such rule and the unprivileged runtime cannot add
  one, so `slots.json` now records which ports each provisioning opened.
  `--inject` on an older host errors **before any VM boots**, naming the exact
  re-provisioning command — structurally the same trap `filtered_from` closed in
  0.9.0, where an absent field must never be read as a permissive default.

- **A credential rule matches the path only.** `allow: ["GET /repos/*/*/issues"]`
  now covers `?state=open&page=2`. Previously the query was part of the string
  the glob matched, so every paginated or filtered API call was refused —
  fail-closed, but it pushed operators toward `readonly` purely to make query
  strings work, which is a real loss of scoping. A fragment in a request target
  is now rejected outright: `#` ends the path for a URL parser but not for a
  rule matcher, and that disagreement is the whole class of bug this layer
  exists to prevent.

- **A refusal survives a request that had a body.** The endpoint refuses before
  reading a body — that is the point — but closing a socket with unread data
  queued sends RST rather than FIN, and the RST discarded the `403` before the
  guest could read it. Every refused `POST` surfaced as "connection reset by
  peer" instead of the explanation naming which `allow` list to widen. Found by
  the live wire test, which is now in the tree (`tests/live_inject.rs`) and
  asserts against what a real upstream received rather than what this process
  believed it sent.

- **`Secret::expose` call sites are now enforced, not merely documented.** The
  module claimed a test asserted it; there was none. A test now walks the crate
  source and fails on any call outside `net/secret.rs` and `net/broker.rs`. A
  leak does not begin as a leak — it begins as one reasonable-looking `.expose()`
  in a logging path.

- **The gateway is excluded from `NO_PROXY` in the guest.** Every broker endpoint
  lives on the gateway, so without this a client asked for
  `http://10.107.<i>.1:3129/...` would send it to the HTTP proxy on the same
  address as an absolute-form request — which the broker then evaluates as a
  connection to a literal address and refuses. The credential endpoint would have
  looked broken for reasons unrelated to credentials.

- **A model learns nothing about the credential store itself.** Only the
  per-alias refusal was being collapsed for MCP callers, so "no store here",
  "your store is world-readable" and "your store declares version 2" all reached
  the caller **carrying the store's absolute path** — naming any alias read back
  the operator's home directory and whether a store existed at all. Every
  failure now renders identically for a model; the operator gets the specific
  one on stderr.

- **Traversal survives no amount of decoration.** The dot-segment check was
  exact string equality, so `%252e%252e` (no literal `%2e` in it, decodes to
  one), `..;` (a path parameter some servers strip before routing), `..%00` and
  `..%20` all passed both the normaliser and the rule matcher. Every remaining
  percent-escape must now decode to an ordinary visible byte, and a path
  parameter is refused outright. Each of those was a way to make the rule
  matcher and the upstream server disagree about where a path goes, which is the
  one failure that layer exists to prevent.

- **A credential's own refusals are no longer reported as "not on this run's
  allowlist".** Endpoint denials carry `credential_refused`, and a pinned host
  reached directly carries `pinned_credential_host`. Those three call for
  completely different fixes, and the first two used to render as the third.

- **A request that may have been executed upstream is no longer recorded as
  denied.** Only a connect failure proves the request never left the host; a
  timeout can mean the pinned host received and ran it and merely failed to
  answer. Recording those as refused told an operator asking "was my token
  used?" that it was not — the one question the flight recorder must not get
  wrong.

- **The `Secret::expose` guard covers the whole workspace.** It scanned only
  `crates/core/src`, while `ResolvedCredential::secret` and
  `Broker::credentials` are both `pub` — so the invariant was enforced exactly
  where it is easiest to keep and ignored where a value gets rendered for
  output. It now walks every crate and matches both call spellings. The
  `Authorization` header value is also marked sensitive, so `http`'s own `Debug`
  redacts it once the token leaves isopod's types.

- **An empty upstream chunk no longer truncates the response.** An empty chunk
  frames as `0\r\n\r\n`, which *is* the terminator, so relaying one would end
  the body early and hand the workload a short document it believed was
  complete.

- **`isopod setup` is idempotent again.** `ip addr add` reports an
  already-present address as either `File exists` or
  `Error: ipv4: Address already assigned.` depending on the iproute2 version,
  and only the first was tolerated — so re-provisioning failed on many hosts,
  including for exactly the people told to re-provision by the new port gate.

- **The flight recorder carries the specific reason inline.** `denied[].note`
  surfaces the broker's machine-readable tag in the run report, so
  `inject-not-permitted` (your allow list) is distinguishable from
  `inject-upstream-unreachable` (the API was down) without opening
  `egress.jsonl`. `RunReport.egress.injected` lists every credential the run
  held and exactly what each could do — never the secret, which the type system
  will not serialize.

## [0.9.1] — 2026-07-25

- **The egress flight recorder now records volume.** `bytes_up`/`bytes_down`
  were in the schema but always `0` — the byte pump discarded its counts.
  Counting is now incremental (as bytes flow, not at close), because a run ends
  with the guest vanishing rather than closing its sockets, so a close-triggered
  count read `0` for exactly the transfers worth seeing. Volume per destination
  is the one signal a destination allowlist cannot give on its own.
- **Image staleness compares the guest agent, not just the protocol version.**
  An additive, wire-compatible protocol change bumps no version, so a rebuilt
  guest agent left every image reporting fresh while still embedding the old
  one — which is exactly what happened to filtered egress in 0.9.0, and it
  presented as an unexplained network outage rather than a policy decision. The
  hash was already recorded in each image's sidecar; it is now checked, in
  `image ls` (with a `stale_reason`) and in the pre-boot guard.
- **Published the egress bypass ledger** ([docs/egress-ledger.md](docs/egress-ledger.md)):
  ten attempted bypasses run against a real VM, each recording which of the two
  layers caught it. Notably, DNS aimed straight at `8.8.8.8` is **transparently
  intercepted** by the broker rather than dropped, so malware with a hardcoded
  resolver is policy-enforced instead of merely failing.
- CI now compiles the `#[ignore]`d live tests (`cargo test --no-run`) so they
  cannot rot silently between hand-run ledger passes.

## [0.9.0] — 2026-07-25

- **Per-run egress allowlists — the allowlist the agent cannot rewrite.**
  `isopod run --allow-host pypi.org --allow-host '*.pythonhosted.org'` (or
  `sandbox_run(allow_hosts=[…])` over MCP) switches a run to **default-deny**
  egress: it claims a *filtered* network slot, which the setup-time nftables
  ruleset drops all forwarding from, and reaches the network only through a
  host-side broker that enforces the allowlist. Policy lives on the host,
  outside the guest boundary; a root guest can neither reach an unlisted
  destination nor edit the rules.
  - `--allow-cidr` permits literal addresses for tools that dial one. A literal
    address is never matched against `--allow-host` patterns.
  - `--deny-egress` denies everything while still recording every attempt —
    for watching what an untrusted dependency tries to reach.
- **DNS exfiltration is closed.** A filtered slot's `:53` is redirected to a
  host-side responder that answers allowlisted names and `NXDOMAIN`s the rest,
  so the guest has no path to an attacker-chosen resolver. Every query is
  recorded.
- **The egress flight recorder.** `RunReport.egress` lists every allowed and
  denied connection and every name resolved, with the complete record at
  `~/.isopod/vms/<id>/egress.jsonl`. All names are validated before recording:
  anything that is not a well-formed host name is stored as `<invalid:N>`, so
  guest-chosen bytes never reach an operator's terminal or a calling model's
  context.
- **Setup provisions 12 slots by default (8 public + 4 filtered).** The filtered
  slots are *added* to the pool, so existing public concurrency is unchanged.
  Tune with `sudo isopod setup --slots N --filtered-slots M`; `--filtered-slots
  0` reproduces the 0.8.1 ruleset byte-for-byte.
- **No behaviour change without the new flags.** A run with no allowlist takes
  the same public slot, the same ruleset, and the same `RunReport` shape as
  0.8.1 — asserted against a checked-in ruleset fixture and a report-shape test.
  A pre-0.9 `slots.json` keeps working; the first filtered run against one fails
  before boot with the exact re-provisioning command.

## [0.8.1] — 2026-07-23

- Fix the release packaging: cargo-deb rejects explicit cross-target asset
  paths, so the guest agent is staged into `dist/` alongside Firecracker.
  (v0.8.0's release run failed at the .deb step; this is the first tag with
  published artifacts.)

## [0.8.0] — 2026-07-23

- **Formal installation.** Every `v*` tag now publishes a GitHub Release with
  a `.deb`, an `.rpm`, a plain tarball, and `SHA256SUMS` (built by the new
  release workflow). Packages install `isopod`, `isopod-mcp`, and
  `isopod-jail` to `/usr/bin` plus **prebuilt Firecracker and guest-agent
  binaries** under `/usr/lib/isopod/`, so package installs need no Rust
  toolchain and skip `dev build-fc` entirely.
- Resolution now knows the installed layout: Firecracker resolves
  env override → `~/.isopod/bin` (dev build) → `/usr/lib/isopod` (package,
  new `system-package` provenance) → M0; the guest agent resolves
  env override → workspace target dir → `/usr/lib/isopod`.

## [0.7.3] — 2026-07-23

- CLI polish from an external docs review: `stage ls` and `vm list` now work
  as visible aliases (the `list`/`ls` asymmetry between the two groups was a
  papercut), and the top-level `image` help text names all four subcommands.

## [0.7.2] — 2026-07-23

- Formatting fixup missed from the 0.7.1 commit (whitespace only).

## [0.7.1] — 2026-07-23

- **CI**: GitHub Actions workflow — build, `cargo fmt --check`, clippy
  (`-D warnings`), full test suite, plus a `version-guard` job that enforces
  the versioning policy on every PR and push.
- Lint cleanup (clippy `manual_is_multiple_of`, `large_enum_variant`).

## [0.7.0] — 2026-07-23

The post-v1 hardening and findings-fix wave; adopts the versioning policy
(versions 0.2.0–0.6.0 below were tagged retroactively at their milestone-close
commits).

- **Breaking**: host↔guest RPC protocol v3 — guest hostname support, streamed
  `copy_out`, richer base metadata, protocol-stamped images with a pre-boot
  guard (`image ls` shows staleness; `image build-all` rebuilds coherently).
- **Security hardening**:
  - Guest egress restricted to public destinations by default (RFC1918 /
    CGNAT / link-local dropped, per-tap anti-spoofing, IPv6 deny);
    `setup --allow-lan-egress` opts out.
  - Opt-in rootless microjail (`ISOPOD_JAIL=1`): user/pid namespaces, minimal
    chroot, per-VM cgroup caps. Fails closed on missing prerequisites.
  - Every guest-controlled host sink bounded: exec logs capped per stream,
    serial sinks capped, all agent RPCs time-bounded, run budgets capped.
  - Guest kernel pinned by exact artifact and sha256, verified on fetch and
    on cached reuse.
- **Features**: `stdin_file` (big payloads without transiting model context),
  `--copy-out`/`copy_out` artifact extraction, run observability
  (`path`/`resume_ms`/`snapshot_built`/`commit_ms`), MCP auto-GC of VM
  records, guest hostname = vanity name.
- **Fixes**: overlay chain depth off-by-one at max depth; degraded overlay
  root now loudly fatal instead of silent; pre-boot env-var validation;
  clear error naming the failing subject on exec spawn failures; `--base`
  without `--stage` is a hard error.

## [0.6.0] — 2026-07-22

- **M5.5 + M6**: flexible per-VM resources (`vcpus`, `mem_mib`, host-capped
  with clear errors) and the warm pool — full-VM snapshot save/resume with
  post-resume network/clock reconfiguration over vsock (`warmpool
  build`/`list`/`rm`), transparent resume for eligible runs.

## [0.5.0] — 2026-07-21

- **M5**: MCP server (`isopod-mcp`, rmcp 2.2 stdio) exposing
  `sandbox_run` and the stage/VM tools; workflow skill; Claude Code plugin
  packaging; stdin plumbing.

## [0.4.0] — 2026-07-21

- **M4**: networking — one-time `sudo isopod setup` provisioning user-owned
  tap slots + nftables NAT, `--no-network`, orphaned-VMM reaping, the
  `base-alpine` toolchain image.

## [0.3.0] — 2026-07-21

- **M3**: stages — squashfs base + overlay chains, content-addressed
  commit/fork/stack store, `stage list/info/rm`, `vm ls/gc`, vanity names.

## [0.2.0] — 2026-07-21

- **M2**: exec — `isopod-proto` host↔guest RPC contract, musl PID-1 guest
  agent, `isopod run` end to end over vsock.

## [0.1.0] — 2026-07-21

- **M0/M1**: feasibility spike; cargo workspace; typed `isopod-fc`
  Firecracker client; guest-image pipeline; vendored Firecracker v1.16.1
  built from source; dev boot path.
