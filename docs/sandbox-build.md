# Building isopod inside isopod

isopod's builds run inside its own sandboxes — dogfooding the stage model with the
heaviest workload we have, and keeping toolchains and build state off the host. Proven
end-to-end over the MCP server on 2026-07-22 (see `docs/dogfood-findings.md`, MCP v2
gauntlet section).

## Stage chain

| stage | contents | rebuild trigger |
|---|---|---|
| `rust-stable` | rustup stable x86_64-unknown-linux-musl under `/root/.rustup` + `/root/.cargo` | toolchain bump |
| `isopod-src` | workspace source at `/root/src` on top of `rust-stable` | source refresh |
| `isopod-build` | source + crates.io cache + `target/` (≈1.5 GiB layer) | after a clean build |

Every build cmd starts with:

```sh
export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH=/root/.cargo/bin:$PATH
cd /root/src
```

## Getting source in

There is no git remote yet, and inline MCP `stdin` is unsuitable for large payloads (the
payload would transit model context). Use `stdin_file` (a host path — works on both the CLI
`--stdin-file` and, since the #21 fix, the MCP `sandbox_run` param):

```sh
tar czf - Cargo.toml Cargo.lock rust-toolchain.toml crates | base64 -w0 > /tmp/src.b64
isopod run --stage isopod-build --scratch-mib 8192 --stdin-file /tmp/src.b64 -- \
  /bin/sh -c 'base64 -d | tar xzf - -C /root/src && cd /root/src && \
    export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo PATH=/root/.cargo/bin:$PATH && \
    cargo build --workspace'
```

Untarring over `/root/src` updates only changed files' mtimes, so cargo rebuilds just the
touched crates (measured: 6.93 s after touching `crates/cli/src/main.rs`, vs 2 m 06 s clean).
To persist the refreshed state, add `--commit-as isopod-build/<date>` (label-reuse semantics
for an existing label are untested — use versioned labels until that's gauntleted).

Once a git remote exists: `git clone`/`git pull` in-guest replaces the tarball dance.

## Everyday check/test loop (MCP)

For Claude sessions: `sandbox_run` with `stage: "isopod-build"`, `vcpus: 4`, `mem_mib: 3072`,
`scratch_mib: 8192`, `timeout_s: 300` (600 for clean builds; commit adds ≈20 s/GiB). Run
`cargo build`/`cargo check`/`cargo test` as needed — since coreutils landed in base-alpine,
**the full workspace test suite passes in-guest (132/132 core)**. Only tests needing
`/dev/kvm` or live host state (taps, a real `~/.isopod`) stay on the host (they are
`#[ignore]`d live tests anyway).

## Getting binaries out

Use `--copy-out GUEST:HOST` (CLI) or `copy_out: [{guest, host}]` (MCP) — the streamed,
binary-safe channel with no size ceiling; mode bits (the exec bit) are preserved and byte
counts verified, with the written files listed under `copied` in the result:

```sh
isopod run --stage isopod-build --scratch-mib 8192 --vcpus 4 --mem-mib 3072 --timeout-s 600 \
  --copy-out /root/src/target/release/isopod:/tmp/isopod-built -- \
  /bin/sh -c 'cd /root/src && export RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo \
    PATH=/root/.cargo/bin:$PATH && cargo build --release -p isopod-cli'
```

Release binaries are **static-pie musl** — they run unmodified on the glibc host. (The old
base64-over-stdout recipe still works as a fallback but is obsolete.)

Note: replacing `target/release/isopod-mcp` requires restarting the MCP server, and a
`PROTO_VERSION` bump requires rebuilding all guest images together (finding #17).

## Sizing (4-core / 5.9 GiB WSL2 host)

One build VM at a time; 4 vcpu / 3072 MiB (3584 for release) / 8192 MiB scratch. Never run a
build VM alongside a fleet of test VMs — memory pressure has killed agents before.
