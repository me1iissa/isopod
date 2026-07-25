# Changelog

All notable changes to isopod. The format follows
[Keep a Changelog](https://keepachangelog.com/) loosely; versions follow
[Semantic Versioning](https://semver.org/) with pre-1.0 semantics (minor =
features or breaking changes, patch = fixes). See CONTRIBUTING.md §
Versioning for the policy.

## [0.10.0] — 2026-07-25

- **Credential injection — a run can spend a credential without ever holding
  it.** A run names an *alias*; the operator declares on the host which secret
  it is, the single host it may be sent to, and — mandatorily — which requests
  it may authorise. `isopod run --inject github` / `sandbox_run(inject:
  ["github"])`. The guest calls `$ISOPOD_CREDENTIAL_ENDPOINT/<alias>/<path>`
  and the host attaches the token, but only for a method and path the operator
  wrote down. See [docs/credentials.md](docs/credentials.md).

  The endpoint is **not a reverse proxy**: guest bytes never reach the wire. It
  reads a stated intent and constructs a new request from its own parts — its
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
