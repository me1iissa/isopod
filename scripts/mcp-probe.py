#!/usr/bin/env python3
"""Drive isopod-mcp over stdio JSON-RPC, the way a client does."""
import json, os, subprocess, sys, time

BIN = os.path.expanduser("~/.local/bin/isopod-mcp")


class Server:
    def __init__(self, cwd, env_extra=None):
        env = dict(os.environ)
        env.update(env_extra or {})
        self.p = subprocess.Popen(
            [BIN], cwd=cwd, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
        self.n = 0
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "probe", "version": "0"},
        })
        self._notify("notifications/initialized", {})

    def _send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def _notify(self, method, params):
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _rpc(self, method, params, timeout=180):
        self.n += 1
        self._send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed stdout")
            msg = json.loads(line)
            if msg.get("id") == self.n:
                return msg
        raise TimeoutError(method)

    def call(self, name, args):
        return self._rpc("tools/call", {"name": name, "arguments": args})

    def stderr_tail(self):
        os.set_blocking(self.p.stderr.fileno(), False)
        try:
            return (self.p.stderr.read() or "")[-600:]
        except Exception:
            return ""

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def outcome(resp):
    """Reduce a tools/call reply to (verdict, detail)."""
    if "error" in resp:
        return "REFUSED", resp["error"].get("message", "")[:200]
    r = resp.get("result", {})
    if r.get("isError"):
        txt = " ".join(c.get("text", "") for c in r.get("content", []))
        return "REFUSED", txt[:200]
    txt = " ".join(c.get("text", "") for c in r.get("content", []))
    return "ALLOWED", txt[:300]
