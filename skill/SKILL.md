---
name: isopod
description: Boot isolated Firecracker microVM sandboxes to run code, test untrusted commands, or build a reusable environment stage (install deps once, fork forever). Wraps the isopod MCP tools sandbox_run, stage_list/stage_info/stage_rm, vm_list/vm_gc.
when_to_use: Use when the user asks to run code in a sandbox, execute something in an isolated VM, test untrusted code or a script safely, install packages once and reuse that environment, fork or snapshot a dev environment, or manage isopod stages/VMs. Trigger phrases -- "run this in a sandbox", "isolated VM", "test untrusted code", "sandbox this script", "build a reusable environment stage", "set up an environment with X and reuse it", "fork my sandbox".
---

# isopod: Firecracker-microVM sandboxes

isopod boots a real hardware-isolated microVM per action (~400 ms cold), execs one
command over vsock, and destroys it. There is no persistent "session" tool —
**isopod's stage model IS its persistence**: a run can leave behind a *stage* (a
committed, content-addressed environment layer) that later runs *fork* from.
Forking never mutates the parent, so stages are safe to share and reuse.

Tool names depend on how isopod is installed in this session: project-scope
`.mcp.json` registers them as `mcp__isopod__<tool>` (e.g.
`mcp__isopod__sandbox_run`); the bundled plugin registers them as
`mcp__plugin_isopod_isopod__<tool>`. This skill refers to tools by their bare
name (`sandbox_run`, `stage_list`, …) — use whichever fully-qualified form is
actually present in your toolset.

## The default move: `sandbox_run`

For "run this snippet", "try this command", "does this script work" — just call
`sandbox_run`. It boots, execs, and destroys the VM in one call. Nothing
persists across the call unless you explicitly pass `commit_as`.

```
sandbox_run(cmd="python3 -c 'print(2**10)'")
```

Omit `stage` and it defaults to `stage="base"` — a fresh VM on top of the
**base-alpine** toolchain image (python3, node, git, gcc, pip) with zero
committed layers, which is why plain `pip install requests` or `npm install`
just works with no setup call first. If you truly want the minimal legacy
image with no toolchain, that's a deliberate opt-out, not the default path.

## Building and reusing an environment: commit → fork

When a task needs setup that's expensive to repeat (installed packages, a
built binary, a cloned repo), commit the result as a **stage** once, then fork
it cheaply from then on — forking is a few milliseconds of disk setup, not a
rebuild.

```
# 1. One run that installs deps AND commits the result (only commits on exit 0).
sandbox_run(
  cmd="pip install numpy pandas",
  stage="base",
  commit_as="myproj/data-deps"
)
# -> {ok:true, exit_code:0, stage_id:"st-...", stage_name:"...", ...}

# 2. Every later run forks that stage by name instead of reinstalling.
sandbox_run(cmd="python3 -c 'import numpy; print(numpy.__version__)'",
            stage="myproj/data-deps")
```

The fork in step 2 never mutates `myproj/data-deps` — it boots the same
read-only layer plus a fresh scratch. Run it 50 times concurrently and the
parent stage stays byte-identical. To layer further (e.g. add a second
package on top of the deps stage), just `commit_as` again with `stage` set to
the stage you forked from — that stacks a new layer rather than overwriting.

**Naming convention:** `<project>/<purpose>` (e.g. `myproj/data-deps`,
`scraper/chromium`, `ci/rust-toolchain`) — makes `stage_list` output scannable
and gives forks a memorable target. Vanity names (e.g. `radiant-legionary`)
are auto-assigned too and also work as a `stage=` reference, but they're not
memorable across a conversation the way a chosen label is.

## Base images

- `base-alpine` (default for stage runs) — python3/pip, node/npm, git, gcc,
  make: the useful default for real work.
- `base-sqfs` — minimal busybox, no toolchain. Pick it explicitly only when
  you specifically want the smallest possible surface (e.g. testing a static
  binary with no interpreter dependencies).

`--base` is only meaningful the first time a chain starts from `stage="base"`;
forking an existing stage always reuses whatever base it was built on
(mixing bases mid-chain would silently break the overlay).

## Untrusted code: turn networking off

Set `network=false` for anything you don't want reaching the internet —
untrusted snippets, unreviewed scripts, adversarial input. Exec still works
identically (control RPC is vsock, not the NIC); the guest simply has no
route out.

```
sandbox_run(cmd="python3 suspicious_script.py", network=false)
```

## Big inputs and parallelism

- `stdin` is for small text. For anything beyond a few KiB (tarballs, datasets,
  archives) pass `stdin_file="/abs/host/path"` instead — the server reads the
  file directly, so large payloads never transit the model context.
- Parallel `sandbox_run` calls batched in **one** assistant message execute
  serially, one VM after another. For genuinely concurrent sandboxes, issue the
  calls from separate agents/processes — the server and its network-slot pool
  handle real concurrency fine (verified 6-way).

## Timeouts

`timeout_s` (default 120) is an **outer wall-clock budget that includes VM
boot** (~400 ms), not just your command's exec time. For a 3 s budget your
command gets roughly 2.6 s of real exec time. Pad short timeouts by a few
hundred ms rather than assuming the full value is exec-only.

## Housekeeping

isopod accumulates state under `~/.isopod` across runs. The MCP server
auto-prunes **VM records** (at startup and every ~20 runs, keeping the newest
20), so read any `*_log_path` you care about promptly. **Stages are never
auto-pruned**:

- `vm_gc(keep_last=20)` — the same sweep on demand: reaps orphaned Firecracker
  processes and prunes old VM record directories (logs, throwaway disk
  copies), keeping the newest N.
- `stage_rm(reference="myproj/old-attempt")` — removes a stage by id, vanity
  name, or unique label. Refuses if another stage's chain still forks from it
  (delete leaf stages first, or just leave unreferenced ones — they're cheap).
- `stage_list()` / `stage_info(reference=...)` — check what exists and its
  full parent chain before committing a same-named stage or deleting one.
- `vm_list()` — recent VM records if you need to find a vanity name or check
  what actually ran.

## Quick reference

| Situation | Call |
|---|---|
| Run a one-off snippet | `sandbox_run(cmd=...)` |
| Save a built environment | `sandbox_run(cmd=..., stage="base", commit_as="proj/purpose")` |
| Reuse a saved environment | `sandbox_run(cmd=..., stage="proj/purpose")` |
| Untrusted input | `sandbox_run(cmd=..., network=false)` |
| Minimal image, no toolchain | `sandbox_run(cmd=..., stage="base", base="base-sqfs")` |
| See what's stored | `stage_list()`, `vm_list()` |
| Clean up | `vm_gc()`, `stage_rm(reference=...)` |
