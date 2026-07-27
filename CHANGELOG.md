# Changelog

All notable changes to isopod. The format follows
[Keep a Changelog](https://keepachangelog.com/) loosely; versions follow
[Semantic Versioning](https://semver.org/) with pre-1.0 semantics (minor =
features or breaking changes, patch = fixes). See CONTRIBUTING.md §
Versioning for the policy.

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
