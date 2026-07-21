# M0 networking spike
Tests PLAN.md Known Risk #1: does kernel-forwarded traffic (netns→veth→NAT→default iface) egress under this host's WSL2 networking mode, and can an unprivileged user open a tap device created for them.
Run: `sudo bash scripts/m0-net-spike.sh`
Temporary and self-cleaning: everything it creates (netns/veth/nftables table/tap) is torn down via an EXIT trap, even on failure; `ip_forward` is restored. No permanent changes; safe to re-run after a crash.
One JSON object on stdout, progress on stderr. Verdicts: `nat_egress_works` (proceed with NAT design) / `nat_egress_blocked` (flip `.wslconfig` to NAT, `wsl --shutdown` required, or use the proxy fallback) / `partial` (investigate).
