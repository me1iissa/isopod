# Using isopod as an MCP server in Claude Code

isopod exposes its sandbox/stage/VM operations as MCP tools over stdio, via a
dedicated binary crate (`crates/mcp`, package `isopod-mcp`) built on rmcp 2.2.
This doc covers building the server, registering it two ways (project-scope
`.mcp.json` and the bundled plugin), the tool list, and a few end-to-end
example prompts.

## Build

```bash
cargo build --release -p isopod-mcp
```

Produces `target/release/isopod-mcp`. It is a stdio server — Claude Code
spawns it as a subprocess per session; it is not a long-running daemon you
start yourself. All state (VM records, stages, network slots) lives under
`~/.isopod`, exactly as it does for the `isopod` CLI — the MCP server and the
CLI share `isopod-core` and read/write the same on-disk store.

Rebuild after any change under `crates/core` or `crates/mcp`; the CLI and the
MCP server are separate binaries built from a shared library, so a `cargo
build --release` for one does not update the other.

## Option 1: local-scope registration (recommended dev loop)

Register the built server with an absolute path at **local** scope — it is
auto-trusted (no approval prompt) and connects immediately:

```bash
cargo build --release -p isopod-mcp
claude mcp add --scope local isopod -- /absolute/path/to/isopod/target/release/isopod-mcp
claude mcp list      # -> isopod ... ✔ Connected
```

Tools appear as `mcp__isopod__<tool>`, e.g. `mcp__isopod__sandbox_run`.

**MCP servers load at Claude Code session startup**, so after registering you
must **restart Claude Code** (or reconnect) for the tools to appear in a
running session — registering mid-session does not hot-load them.

The repo deliberately does **not** commit a project-scope `.mcp.json`:
committing one forces an approval prompt on every user and conflicts with a
local registration of the same name. For distribution, use the bundled plugin
(Option 2), which carries the server config in its manifest. If you do want a
project-scope `.mcp.json` (VCS-shared, prompts once for approval), the shape
is `{"mcpServers":{"isopod":{"command":"${CLAUDE_PROJECT_DIR:-.}/target/release/isopod-mcp","args":[]}}}`
— but pick either that or the local registration, never both.

## Option 2: as a Claude Code plugin

`.claude-plugin/plugin.json` at the repo root bundles both the skill
(`skill/SKILL.md`) and the MCP server:

```json
{
  "name": "isopod",
  "...": "...",
  "skills": ["./skill"],
  "mcpServers": {
    "isopod": {
      "command": "${CLAUDE_PLUGIN_ROOT}/target/release/isopod-mcp",
      "args": []
    }
  }
}
```

`${CLAUDE_PLUGIN_ROOT}` always resolves to wherever the plugin is actually
loaded from, which is what makes this form work for local dev: load the repo
in place with

```bash
claude --plugin-dir /absolute/path/to/isopod
```

and the server command resolves to that same checkout's freshly-built
binary — no separate install/copy step, no stale binary after a rebuild.

This intentionally differs from the project-scope `.mcp.json` above (which
uses `${CLAUDE_PROJECT_DIR}` instead of `${CLAUDE_PLUGIN_ROOT}`): a
plugin-provided MCP config that used `${CLAUDE_PROJECT_DIR}` would resolve to
whatever project the *user* currently has open, not to the isopod checkout
itself, which breaks the moment someone uses the plugin while working on an
unrelated project. `${CLAUDE_PLUGIN_ROOT}` is the only form that is correct
in the plugin context, so the two registration paths carry two different
command strings.

Tools registered via the plugin appear scoped as
`mcp__plugin_isopod_isopod__<tool>` (the general plugin pattern is
`mcp__plugin_<plugin-name>_<server-name>__<tool>`; isopod uses the same name
for both, hence `isopod_isopod`).

Note on distribution: `--plugin-dir` loads the plugin **in place**, so
`${CLAUDE_PLUGIN_ROOT}/target/release/isopod-mcp` only exists if you've
built it in that checkout first. A marketplace-style install copies the
plugin into `~/.claude/plugins/cache` without running `cargo build`, so a
cache-installed copy would need a prebuilt binary vendored into the package —
out of scope for v1; local dev via `--plugin-dir` (or the project-scope
`.mcp.json`) is the supported path today.

## Tool list

All tools wrap `isopod-core` functions directly — the MCP server adds no
behavior beyond argument marshaling and JSON shaping. Full param docs live in
each tool's MCP schema (self-describing); this is the one-line semantics.

| Tool | Semantics |
|---|---|
| `sandbox_run` | **The core tool.** Boot a VM, run `cmd` via `/bin/sh -c`, optionally commit the result as a stage, destroy the VM. Ephemeral by default — nothing persists unless `commit_as` is set and the command exits 0. |
| `stage_list` | List every committed stage (id, vanity name, label, parent, base, allocated bytes, created time). |
| `stage_info` | Full metadata plus the resolved layer chain for one stage (by id, vanity name, or unique label). |
| `stage_rm` | Remove a stage. Refuses if another stage's chain still forks from it. |
| `vm_list` | Recent VM records (id, vanity name, flavor, created, directory size) — useful for finding a vanity name after the fact. |
| `vm_gc` | Reap orphaned Firecracker processes and prune old VM record directories, keeping the newest `keep_last` (default 20). |

### `sandbox_run` params (the one worth knowing in detail)

| Param | Default | Notes |
|---|---|---|
| `cmd` | — | Required. Run via `/bin/sh -c`, so pipes/redirects/`&&` all work. |
| `stage` | `"base"` | A committed stage's id/vanity-name/label to fork from, or the reserved word `"base"` for a fresh VM with zero committed layers. This is *not* the same as omitting the param entirely at the `isopod-core` level (which boots the legacy toolchain-less ext4 image) — the MCP tool defaults to `"base"` specifically so the toolchain image is what you get without having to ask. |
| `base` | `"base-alpine"` | Squashfs base for a `stage="base"` run: `base-alpine` (python3/pip, node, git, gcc) or `base-sqfs` (minimal busybox, no toolchain). Ignored when forking an existing stage — forks always reuse the base that stage was built on. |
| `network` | `true` | Set `false` for untrusted code — no NIC is attached at all; exec still works (control RPC is vsock, not the network). |
| `timeout_s` | `120` | **Outer wall-clock budget that includes VM boot** (~0.4 s), not exec-only time. |
| `cwd` | guest default (`/root`) | Working directory inside the guest. |
| `env` | `{}` | Extra environment variables as a flat `KEY: "VALUE"` object. |
| `commit_as` | — | Label to persist the result as a new stage. Only commits when the command exits 0 — a failed setup command never silently produces a broken stage. |
| `stdin` | — | Small inline text piped to the command's stdin, then closed. |
| `stdin_file` | — | HOST-side file whose bytes are piped to stdin — use for anything beyond a few KiB so large payloads never transit the model context. Mutually exclusive with `stdin`. |
| `vcpus` | `1` | Guest vCPUs: 1 or an even number, at most the host CPU count. Over-cap errors before boot. |
| `mem_mib` | `512` | Guest memory in MiB, bounded 128..=host free RAM (with headroom). Over-cap errors before boot. |
| `scratch_mib` | ~`1024` | Writable overlay scratch in MiB (128..=65536, sparse). Raise for build workloads; passing it forces the cold (disk-upper) path. |
| `copy_out` | — | List of `{guest, host}` mappings: stream guest files to host paths after a successful exec — the binary-safe artifact channel. A copy failure fails the call; written files are listed in the result's `copied`. |

Return shape (abridged): `{exit_code, signal, timed_out, stdout, stderr,
stdout_truncated, stderr_truncated, stdout_bytes, stderr_bytes, duration_ms,
total_ms, path, resume_ms?, snapshot_built, commit_ms?, vcpus, mem_mib,
vm_id, vm_name, rootfs_flavor, stage_id?, stage_name?, slot?, guest_ip?,
stdout_log_path, stderr_log_path, serial_log_path, copied?}`. Highlights:
`stdout`/`stderr` are 64 KiB inline heads with exact byte totals alongside
and full logs at the `*_log_path`s; `path` says whether the run resumed
`"warm"` or booted `"cold"` (with `resume_ms` on warm runs and
`snapshot_built` flagging the one-time cache build); `stage_*` appear only
when `commit_as` actually committed; `guest_ip`/`slot` only when networking
was on.

## Example prompts

**"Run this Python snippet in a sandbox and tell me the output."**
→ one `sandbox_run` call with `cmd` wrapping the snippet (e.g. via `python3
-c "..."` or by writing it with a heredoc inside `cmd`), default `stage`/
`base`/`network`. Ephemeral: nothing is left behind.

**"Set up a sandbox with numpy and pandas installed, then reuse it for the
rest of this session."**
→ `sandbox_run(cmd="pip install numpy pandas", commit_as="<project>/data-deps")`
(bare `pip install` works on `base-alpine` — the image ships with the
`EXTERNALLY-MANAGED` marker removed), then every subsequent
`sandbox_run(..., stage="<project>/data-deps")` in the same or a later
session forks that environment instead of reinstalling. Verify with
`stage_info(reference="<project>/data-deps")`.

**"Test this untrusted script without giving it network access, then clean
up."**
→ `sandbox_run(cmd="python3 script.py", network=false)`, followed by
`vm_gc()` (and `stage_rm(...)` if a stage was accidentally committed and
should be discarded).

## See also

- `skill/SKILL.md` — the workflow-level guidance loaded into Claude's context
  (ephemeral-first, commit/fork discipline, naming, when to disable
  networking). This doc is the registration/reference companion to it.
- `docs/dogfood-findings.md` (#9) — the `timeout_s`-includes-boot behavior
  was found and documented via dogfooding the CLI before the MCP tool
  existed; the semantics carry over unchanged.
- `PLAN.md` — "MCP server (`isopod mcp`) + skill" section for the full
  design rationale (output truncation policy, progress-notification
  keepalive, the reasoning for no persistent-session tools in v1).
