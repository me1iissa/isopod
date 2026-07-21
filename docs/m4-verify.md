# M4 network verification runbook

> Exact commands for the coordinator to run once the network-track code has
> landed. The only privileged step is `sudo isopod setup` (run it yourself).
> Everything after that is unprivileged. Assumes the binary is at
> `target/debug/isopod` (or `target/release/isopod`) and the FC binary is at
> `~/.isopod/bin/firecracker` (auto-resolved; no env var needed).

Legend: 🔒 needs root (you run it), 👤 unprivileged (agent-safe).

---

## 0. Preconditions (already true on this host)

- `~/.isopod/bin/firecracker`, `~/.isopod/images/vmlinux-6.18.36`,
  `~/.isopod/images/rootfs-dev-agent.ext4`, `~/.isopod/images/base.sqfs` present.
- `nft` (nftables v1.0.9) + `iproute2` installed; `nft_nat` available.
- Default route is out `eth0` (auto-detected by setup; override with `--iface`).

If the agent changed, rebuild the rootfs first (bakes the current agent in):

```bash
cargo build --release --target x86_64-unknown-linux-musl -p isopod-guest-agent
./target/debug/isopod image build-rootfs --flavor dev-agent --force
```

---

## 1. 🔒 Provision the host (the one root step)

```bash
sudo ./target/debug/isopod setup            # 8 slots by default; --slots N to change
```

Expected: one JSON object, e.g.

```json
{"ok":true,"removed":false,"slots":8,
 "taps_created":["isopod-tap0", "...", "isopod-tap7"],
 "nft_table":"inet isopod","ip_forward":1,"default_iface":"eth0"}
```

Post-conditions to spot-check:

```bash
ip -o link show | grep isopod-tap            # 🔒/👤 8 taps, UP, owned by you
ip addr show isopod-tap0                      # 👤 inet 10.107.0.1/30
sudo nft list table inet isopod               # 🔒 masquerade + forward + input chains
cat /proc/sys/net/ipv4/ip_forward             # 👤 -> 1
cat /etc/sysctl.d/90-isopod.conf              # 👤 net.ipv4.ip_forward = 1
cat ~/.isopod/net/slots.json                  # 👤 owned by you; version/slot_count/default_iface
```

Idempotency: re-running `sudo ./target/debug/isopod setup` must converge (taps
skipped, nft table rebuilt atomically) and print the same shape with
`taps_created: []`.

---

## 2. 👤 Networked run — raw egress (dev-agent / busybox)

Networking is default-on. A slot is claimed automatically; the report now
carries `slot` and `guest_ip`.

```bash
# TCP egress out the NAT (HTTP by IP — busybox wget has no TLS):
./target/debug/isopod run -- /bin/sh -c \
  'busybox ifconfig eth0 2>/dev/null | head -2; \
   busybox wget -q -T 8 -O - http://1.1.1.1 >/dev/null && echo HTTP-OK; \
   echo done'

# ICMP egress (guest is uid 0, so raw sockets work):
./target/debug/isopod run -- /bin/sh -c 'busybox ping -c1 -W3 1.1.1.1 >/dev/null && echo PING-OK'

# DNS resolution through the NAT (proves isopod.dns + resolv.conf + forwarding):
./target/debug/isopod run -- /bin/sh -c 'busybox nslookup example.com 1.1.1.1 | tail -3; echo DNS-done'
```

Expected: `exit_code:0`; stdout contains `HTTP-OK` / `PING-OK` / resolved
addresses; the JSON carries `"slot":0` and `"guest_ip":"10.107.0.2"`. The
guest serial (`serial_log_path`) shows
`net: eth0 up 10.107.0.2/30 gw 10.107.0.1 dns [1.1.1.1,8.8.8.8]`.

Concurrency: run two of the above at once — they must land on **different**
slots (`slot:0` and `slot:1`, guest IPs `.0.2` and `.1.2`) and both succeed.

---

## 3. 👤 PLAN M4 acceptance — `git clone` + `pip install`

Needs a rootfs with git/python (the image track's toolchain flavor / a stage
that has them). With such an image available (substitute the real flavor/stage),
run inside the overlay topology so results can be committed:

```bash
# git clone over HTTPS:
./target/debug/isopod run --stage base -- /bin/sh -c \
  'git clone --depth 1 https://github.com/octocat/Hello-World /tmp/hw && ls /tmp/hw && echo CLONE-OK'

# pip install (the original M3 acceptance that moved here for needing network):
./target/debug/isopod run --stage base --commit-as demo/py-deps -- /bin/sh -c \
  'pip install --no-input requests && python3 -c "import requests; print(requests.__version__)" && echo PIP-OK'
```

Expected: `exit_code:0`, `CLONE-OK` / `PIP-OK` in stdout. The `--commit-as`
run also emits `stage_id` + `stage_name`; a later `--stage <that>` fork sees the
installed package (import works) while the parent stage stays byte-identical.

---

## 4. 👤 Isolation checks (must FAIL to reach)

```bash
# 4a. --no-network: no NIC at all; egress impossible, exec still works.
./target/debug/isopod run --no-network -- /bin/sh -c \
  'busybox ping -c1 -W3 1.1.1.1 >/dev/null 2>&1 && echo REACHED || echo isolated; echo alive'
#   expect: "isolated" then "alive", exit_code 0, NO slot/guest_ip in the JSON.

# 4b. Networked guest must NOT reach the host (input drop). The gateway IP is the
#     host tap; a new connection to it (or any host service) must be dropped.
./target/debug/isopod run -- /bin/sh -c \
  'busybox ping -c1 -W3 10.107.0.1 >/dev/null 2>&1 && echo REACHED-HOST || echo host-isolated'
#   expect: "host-isolated" (ping to the gateway/host is dropped).

# 4c. Inter-VM isolation (tap<->tap drop): with two concurrent networked runs on
#     slots 0 and 1, neither guest can reach the other's guest IP (10.107.1.2 /
#     10.107.0.2). A cross-guest ping must time out.
```

---

## 5. 👤 Leak / crash recovery

```bash
# Kill a run mid-flight (Ctrl-C or kill -9) and confirm the slot lock is reclaimed
# on the next run's startup sweep — no slot is permanently lost:
ls ~/.isopod/net/                     # may show a stale slot-<i>.lock after a crash
./target/debug/isopod run -- /bin/sh -c 'echo recovered'   # sweeps stale locks, reuses the slot
pgrep -a firecracker || echo "no leaked VMM"
```

---

## 6. 🔒 Teardown

```bash
sudo ./target/debug/isopod setup --remove
```

Expected JSON: `{"ok":true,"removed":true,"taps_removed":[...],...}`. Then:

```bash
ip -o link show | grep isopod-tap || echo "no taps"        # gone
sudo nft list table inet isopod 2>&1 | head -1             # "No such file or directory"
ls /etc/sysctl.d/90-isopod.conf 2>&1                        # gone
ls ~/.isopod/net/slots.json 2>&1                            # gone (manifest removed)
```

Note: `--remove` deletes the taps, the nft table, the sysctl persistence file,
and the manifest. It intentionally leaves the **live** `ip_forward` value as-is
(other tenants such as Docker may rely on it); only the isopod persistence file
is removed.

---

## Root-free proof already captured (no setup needed)

The guest-side cmdline-parse + ioctl path was verified without root by booting a
VM with `isopod.net=…` on the command line but **no NIC attached** (so `eth0` is
absent). The agent logs, gracefully, and keeps serving vsock:

```
[isopod-agent] net: eth0 missing (no NIC attached); continuing without network
```

Reproduce:

```bash
ISOPOD_FC_BIN=~/.isopod/bin/firecracker \
ISOPOD_FC_KERNEL=~/.isopod/images/vmlinux-6.18.36 \
ISOPOD_AGENT_ROOTFS=~/.isopod/images/rootfs-dev-agent.ext4 \
  cargo test -p isopod-guest-agent --test live_net -- --ignored --nocapture
```
