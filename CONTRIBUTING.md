# Contributing to isopod

Thanks for your interest in isopod. This guide covers building the project from source, running the tests, the crate layout, coding conventions, and how to propose changes.

isopod is pre-1.0; `main` is the active development line. Please open an issue to discuss a substantial change before investing a lot of work in it — the design in [PLAN.md](PLAN.md) is the reference for what is in scope for v1 versus the v2+ backlog.

> Security bugs do **not** go through the public issue tracker. See [SECURITY.md](SECURITY.md) for private reporting.

---

## Prerequisites

isopod targets **Linux with KVM**. You need:

- **KVM access** — `/dev/kvm` must exist and your user must be in the `kvm` group (`ls -l /dev/kvm`, `groups`). If you are developing inside a VM or WSL2, nested virtualization must be enabled.
- **Rust** — the toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml): `stable`, with the `x86_64-unknown-linux-musl` target (the guest agent is a static musl binary). `rustup` reads this file automatically; running `cargo` in the repo installs the pinned channel and target on first use.
- **The vendored Firecracker submodule** — Firecracker **v1.16.1** is vendored as a git submodule at `vendor/firecracker` and built from source. Fetch it before building anything:

  ```bash
  git submodule update --init --recursive
  ```

- **Host tooling** used by the image pipeline and networking:
  - `nftables` and `iproute2` — NAT setup and tap devices (`isopod setup`).
  - `e2fsprogs` — `mkfs.ext4`, `resize2fs` for scratch and stage images.
  - `squashfs-tools` — `mksquashfs` for the read-only base images.
  - a working C toolchain — to compile the vendored Firecracker.

On a Debian/Ubuntu host these come from `nftables iproute2 e2fsprogs squashfs-tools build-essential` (package names vary by distro).

---

## Build

```bash
# Build the whole workspace (CLI, MCP server, core, guest agent) in release mode.
cargo build --release
```

This produces two binaries under `target/release/`:

- `isopod` — the CLI (from `crates/cli`).
- `isopod-mcp` — the MCP stdio server (from `crates/mcp`).

They are separate binaries built from a shared `isopod-core` library, so after changing `crates/core` you must rebuild whichever front end you are exercising (`cargo build --release` builds both).

To bring up a working environment (Firecracker binary, guest kernel, guest rootfs), then run once:

```bash
./target/release/isopod dev build-fc        # build vendored Firecracker into ~/.isopod/bin
./target/release/isopod image fetch-kernel  # pull a CI guest kernel
./target/release/isopod image build-rootfs  # build the guest rootfs (unprivileged)
sudo ./target/release/isopod setup          # one-time host networking (the only root step)
```

All runtime state lives under `~/.isopod` (file-locked). Nothing is written outside your home directory except what `sudo isopod setup` provisions on the host network stack, which `sudo isopod setup --remove` cleans up.

---

## Test

```bash
cargo test                # run the full workspace test suite
cargo clippy --all-targets --all-features   # lint; keep it clean
cargo fmt --all           # format (rustfmt)
```

A few notes on the test suite:

- Unit and integration tests that do **not** require booting a VM run anywhere `cargo` runs. The bulk of `isopod-fc`, `isopod-proto`, `isopod-core` store/stage/naming logic, and the MCP argument marshaling are covered this way.
- Tests that boot a real microVM require KVM and a provisioned environment (Firecracker binary, kernel, rootfs). Stage round-trip correctness — write → commit → fork → write → commit, verifying both chains stay independent, whiteout deletions survive across layers, and xattrs are preserved — is the load-bearing integration coverage; keep it green when touching the stage store.
- Please add or update tests in the **same change** as the behavior they cover. New CLI/MCP surface should include a JSON-shape assertion; new stage/snapshot bookkeeping should include a round-trip test.

**Dogfooding is a first-class gap-finding mechanism** here: running real work through isopod itself surfaces issues that unit tests miss. Findings are logged in [docs/dogfood-findings.md](docs/dogfood-findings.md); if you discover a gap by using the tool, add an entry with a severity and a fix-or-file decision.

---

## Crate map

isopod is a Cargo workspace of six crates:

| Path | Package | Responsibility |
|---|---|---|
| `crates/fc-client` | `isopod-fc` | Typed client for the Firecracker management API, pinned to the v1.16.1 Swagger. One HTTP client per VM over its API unix socket, with a runtime pre-boot/post-boot phase guard, process supervision (`kill_on_drop`, spawn-in-slot), and hybrid-vsock helpers. Deliberately dependency-light so it can be extracted as a standalone SDK. |
| `crates/core` | `isopod-core` | All orchestration logic. Modules: `vm` (lifecycle: spawn Firecracker, configure via the API, run, reap), `stage` (commit/fork/stack/gc of the content-addressed store), `snapshot` (warm-pool save/restore + cache invalidation), `net` (tap slot claim/release), `agent` (guest-agent vsock RPC client), `store`/`paths` (`~/.isopod` on-disk state), `image` (kernel + rootfs pipeline), `names` (vanity/stage naming). |
| `crates/proto` | `isopod-proto` | The host↔guest RPC contract: length-prefixed serde-JSON frames over vsock, one connection per operation. `PROTO_VERSION` is exchanged in the ping handshake so mismatched host/guest pairs fail fast. |
| `crates/guest-agent` | `isopod-guest-agent` | Static musl binary that runs as PID 1 in the guest: mounts pseudo-filesystems and the overlay, `pivot_root`s, resyncs the clock, reaps zombies, and serves the exec/file/configure RPC on vsock port 52. |
| `crates/cli` | `isopod` | The `isopod` binary — `run`, `stage`, `vm`, `warmpool`, `setup`, `image`, `dev`. One-shot argv + JSON. |
| `crates/mcp` | `isopod-mcp` | The rmcp 2.2 stdio MCP server exposing `sandbox_run`, `stage_list`/`stage_info`/`stage_rm`, `vm_list`/`vm_gc`. A thin async shim over `isopod-core`. |

Supporting directories: `images/` (checked-in kernel config, image build inputs), `skill/` (the Claude Code workflow skill), `docs/` (feasibility, MCP usage, dogfood findings, security assessment), `vendor/firecracker/` (the pinned submodule).

---

## Coding conventions

- **One-shot, non-interactive, structured output.** Every CLI subcommand and every MCP tool is a single invocation that reads its arguments, does the work, prints exactly one JSON object to **stdout**, and exits. No REPLs, no interactive prompts, no persistent stdin. Human-readable logs and diagnostics go to **stderr** — for the MCP server this is mandatory, since stdout carries the JSON-RPC stream.
- **State on disk.** Anything that must survive between invocations lives under `~/.isopod`, file-locked so multiple sessions (Claude Code, a shell, CI) can share it safely. Do not hold cross-invocation state in memory only.
- **Follow the phase machine in `isopod-fc`.** The Firecracker API distinguishes pre-boot from post-boot operations; the typed client encodes this. Do not bypass it with raw requests.
- **Treat vsock connections as disposable.** One connection per RPC operation; assume a connection is dead after any snapshot pause/resume/fork.
- **Immutability of stages is a hard invariant.** A committed stage is never mutated. Forks add a fresh scratch on top of the read-only chain; correctness of the layered-diff bookkeeping (whiteouts, xattrs, chain independence) is where this kind of system usually breaks, so guard it with tests.
- **Cite public specs, not private notes.** Where a comment needs to reference an external contract, cite the public source (the Firecracker docs/Swagger, POSIX, an RFC, a man page).
- Keep `cargo fmt` and `cargo clippy` clean; both are expected to pass before review.

---

## Proposing changes

1. **Branch** off `main`. Do not commit directly to `main`.
2. **Keep changes focused.** Solve the stated problem; avoid unrelated refactors in the same change. Update tests and any affected docs (`README.md`, `docs/`, `PLAN.md` milestone notes) in the same change.
3. **Run the checks locally** before opening a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features`, `cargo test`.
4. **Write a clear PR description** explaining what changed and why, how you verified it (including any live VM/dogfood testing), and any follow-ups you are deliberately leaving out of scope.
5. Reference the relevant [PLAN.md](PLAN.md) milestone or backlog item where applicable, so reviewers can place the change in the roadmap.

Commit messages should be descriptive and explain the *why*, not just the *what*. There is no mandated trailer format.

By contributing, you agree that your contributions are licensed under the project's [Apache License 2.0](LICENSE).
