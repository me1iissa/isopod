#!/usr/bin/env bash
# M0 networking spike for isopod (see PLAN.md "Networking" + "Known risks" #1).
#
# Definitive local verdict on: does kernel-FORWARDED traffic (netns -> veth ->
# NAT -> default iface) actually egress under this host's current WSL2
# networking mode? (microsoft/WSL#10842: mirrored mode reportedly drops it.)
# Also checks that an unprivileged user can open a tuntap device created for
# them, which the runtime (non-root) design in PLAN.md depends on.
#
# One-shot, non-interactive, self-cleaning, idempotent. Run as root:
#   sudo bash scripts/m0-net-spike.sh
#
# All human-readable progress goes to stderr. Exactly one JSON object is
# printed to stdout at the very end.

set -u
set -o pipefail

NS="isopod-spike"
VETH_H="isopod-sp-h"
VETH_N="isopod-sp-n"
TAP="isopod-sp-tap"   # NB: ifnames cap at 15 chars (IFNAMSIZ) — keep short
NFT_TABLE="isopod_spike"
RUNTIME_USER="${SUDO_USER:-$(id -un)}"
HOST_IP="10.199.0.1"
NS_IP="10.199.0.2"
PREFIX=30
NET_CIDR="10.199.0.0/30"
IP_FORWARD_PATH="/proc/sys/net/ipv4/ip_forward"
ERRFILE="$(mktemp /tmp/isopod-spike-err.XXXXXX)" || { echo "[m0-net-spike] FATAL: mktemp failed" >&2; exit 1; }

# --tap-only: skip the netns egress tests (already answered) and run only the
# unprivileged-tap-ownership test.
TAP_ONLY=false
[ "${1:-}" = "--tap-only" ] && TAP_ONLY=true

log() { printf '[m0-net-spike] %s\n' "$*" >&2; }

# ---- prerequisite checks -----------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
  log "FATAL: must run as root (sudo bash scripts/m0-net-spike.sh)"
  exit 1
fi
for bin in ip nft curl ping python3 sudo; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    log "FATAL: required tool '$bin' not found in PATH"
    exit 1
  fi
done
if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
  log "FATAL: expected unprivileged user '$RUNTIME_USER' does not exist"
  exit 1
fi

IP_FORWARD_PRIOR="$(cat "$IP_FORWARD_PATH" 2>/dev/null || echo unknown)"

# ---- idempotent pre-clean (handles leftovers from a crashed prior run) --
precleanup() {
  ip netns del "$NS" >/dev/null 2>&1 || true
  ip link del "$VETH_H" >/dev/null 2>&1 || true
  nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
  ip tuntap del "$TAP" mode tap >/dev/null 2>&1 || true
}

# ---- teardown (runs on ANY exit, including failures) --------------------
cleanup() {
  local rc=$?
  log "tearing down..."
  ip netns del "$NS" >/dev/null 2>&1 || true
  ip link del "$VETH_H" >/dev/null 2>&1 || true
  nft delete table inet "$NFT_TABLE" >/dev/null 2>&1 || true
  ip tuntap del "$TAP" mode tap >/dev/null 2>&1 || true
  if [ "$IP_FORWARD_PRIOR" = "0" ] || [ "$IP_FORWARD_PRIOR" = "1" ]; then
    echo "$IP_FORWARD_PRIOR" > "$IP_FORWARD_PATH" 2>/dev/null || true
  fi
  rm -f "$ERRFILE" 2>/dev/null || true
  log "teardown complete."
  exit "$rc"
}
trap cleanup EXIT
precleanup

# ---- baseline -------------------------------------------------------------
log "recording baseline..."
DEFAULT_IFACE="$(ip -o route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)"
[ -n "$DEFAULT_IFACE" ] || DEFAULT_IFACE="unknown"

IPTABLES_BACKEND="unknown"
if command -v iptables >/dev/null 2>&1; then
  IPTABLES_BACKEND="$(iptables --version 2>/dev/null | head -1)"
fi

WSLCONFIG_MODE="unset"
for wc in /mnt/c/Users/*/.wslconfig; do
  [ -f "$wc" ] || continue
  m="$(grep -i '^[[:space:]]*networkingMode' "$wc" 2>/dev/null | tail -1 | cut -d= -f2 | tr -d '[:space:]')"
  [ -n "$m" ] && WSLCONFIG_MODE="$m"
  break
done

MIRRORED="unknown"
if [ "$WSLCONFIG_MODE" != "unset" ]; then
  case "$WSLCONFIG_MODE" in
    mirrored) MIRRORED=true ;;
    nat) MIRRORED=false ;;
    *) MIRRORED="unknown" ;;
  esac
else
  # Heuristic fallback: mirrored mode exposes the host's real LAN address
  # directly on eth0; NAT mode gives eth0 a WSL-internal 172.x address.
  if [ "$DEFAULT_IFACE" != "unknown" ]; then
    addr="$(ip -o -4 addr show dev "$DEFAULT_IFACE" 2>/dev/null | awk '{print $4}' | head -1)"
    case "$addr" in
      172.1[6-9].*|172.2[0-9].*|172.3[01].*) MIRRORED=false ;;
      "") MIRRORED="unknown" ;;
      *) MIRRORED=true ;;
    esac
  fi
fi
log "default_iface=$DEFAULT_IFACE ip_forward_prior=$IP_FORWARD_PRIOR mirrored=$MIRRORED wslconfig_mode=$WSLCONFIG_MODE"

# ---- helper: run a JSON-safe test, never aborting the script ------------
# Usage: run_test <name-var-not-used> ; sets RESULT_JSON global.
result_json() { # pass_bool detail
  local pass="$1" detail="$2"
  printf '{"pass":%s,"detail":%s}' "$pass" "$(json_str "$detail")"
}
json_str() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  printf '"%s"' "$s"
}

# ================== TEST 1: netns egress (the core question) ============
log "setting up netns egress test..."
NETNS_SETUP_OK=true
NETNS_SETUP_ERR=""

if $TAP_ONLY; then
  NETNS_SETUP_OK=false; NETNS_SETUP_ERR="skipped (--tap-only run)"
elif ! ip netns add "$NS" 2>"$ERRFILE"; then
  NETNS_SETUP_OK=false; NETNS_SETUP_ERR="netns add failed: $(cat "$ERRFILE" 2>/dev/null)"
elif ! ip link add "$VETH_H" type veth peer name "$VETH_N" 2>"$ERRFILE"; then
  NETNS_SETUP_OK=false; NETNS_SETUP_ERR="veth add failed: $(cat "$ERRFILE" 2>/dev/null)"
elif ! ip link set "$VETH_N" netns "$NS" 2>"$ERRFILE"; then
  NETNS_SETUP_OK=false; NETNS_SETUP_ERR="veth move to netns failed: $(cat "$ERRFILE" 2>/dev/null)"
else
  ip addr add "${HOST_IP}/${PREFIX}" dev "$VETH_H" 2>"$ERRFILE" || { NETNS_SETUP_OK=false; NETNS_SETUP_ERR="host addr failed: $(cat "$ERRFILE")"; }
  ip link set "$VETH_H" up 2>/dev/null || true
  ip netns exec "$NS" ip addr add "${NS_IP}/${PREFIX}" dev "$VETH_N" 2>"$ERRFILE" || { NETNS_SETUP_OK=false; NETNS_SETUP_ERR="ns addr failed: $(cat "$ERRFILE")"; }
  ip netns exec "$NS" ip link set "$VETH_N" up 2>/dev/null || true
  ip netns exec "$NS" ip link set lo up 2>/dev/null || true
  ip netns exec "$NS" ip route add default via "$HOST_IP" 2>"$ERRFILE" || { NETNS_SETUP_OK=false; NETNS_SETUP_ERR="ns default route failed: $(cat "$ERRFILE")"; }
fi

if $NETNS_SETUP_OK; then
  echo 1 > "$IP_FORWARD_PATH" 2>/dev/null || NETNS_SETUP_OK=false
fi

if $NETNS_SETUP_OK && [ "$DEFAULT_IFACE" != "unknown" ]; then
  {
    nft add table inet "$NFT_TABLE"
    nft add chain inet "$NFT_TABLE" postrouting '{ type nat hook postrouting priority 100 ; }'
    nft add rule inet "$NFT_TABLE" postrouting ip saddr "$NET_CIDR" oifname "$DEFAULT_IFACE" masquerade
    nft add chain inet "$NFT_TABLE" forward '{ type filter hook forward priority 0 ; }'
    nft add rule inet "$NFT_TABLE" forward iifname "$VETH_H" accept
    nft add rule inet "$NFT_TABLE" forward oifname "$VETH_H" accept
  } 2>"$ERRFILE" || { NETNS_SETUP_OK=false; NETNS_SETUP_ERR="nft setup failed: $(cat "$ERRFILE")"; }
elif $NETNS_SETUP_OK; then
  NETNS_SETUP_OK=false
  NETNS_SETUP_ERR="no default route interface found; cannot set up NAT"
fi

if $NETNS_SETUP_OK; then
  log "netns egress environment ready; running tests..."
else
  log "netns egress SETUP FAILED: $NETNS_SETUP_ERR"
fi

nsx() { ip netns exec "$NS" "$@"; }

if $NETNS_SETUP_OK; then
  PING_OUT="$(nsx ping -c3 -W2 1.1.1.1 2>&1)"; PING_RC=$?
  if [ "$PING_RC" -eq 0 ]; then
    PING_JSON="$(result_json true "3/3 (or partial) replies from 1.1.1.1: $(echo "$PING_OUT" | tail -2 | tr '\n' ' ')")"
  else
    PING_JSON="$(result_json false "ping exit=$PING_RC: $(echo "$PING_OUT" | tail -3 | tr '\n' ' ')")"
  fi
else
  PING_JSON="$(result_json false "skipped, netns setup failed: $NETNS_SETUP_ERR")"
fi
log "netns_ping: $PING_JSON"

if $NETNS_SETUP_OK; then
  HTTP_CODE="$(nsx curl --max-time 10 -s -o /dev/null -w '%{http_code}' https://1.1.1.1/ -k 2>"$ERRFILE")"; CURL_RC=$?
  if [ "$CURL_RC" -eq 0 ] && [ -n "$HTTP_CODE" ] && [ "$HTTP_CODE" != "000" ]; then
    HTTPS_IP_JSON="$(result_json true "https to 1.1.1.1 by IP returned HTTP $HTTP_CODE")"
  else
    HTTPS_IP_JSON="$(result_json false "curl exit=$CURL_RC http_code=${HTTP_CODE:-none}: $(cat "$ERRFILE" 2>/dev/null)")"
  fi
else
  HTTPS_IP_JSON="$(result_json false "skipped, netns setup failed: $NETNS_SETUP_ERR")"
fi
log "netns_https_ip: $HTTPS_IP_JSON"

DNS_OK=false
if $NETNS_SETUP_OK; then
  # Explicit public resolver only -- never /etc/resolv.conf (WSL's resolver
  # is typically unreachable from a netns and would falsely fail this test).
  if command -v dig >/dev/null 2>&1; then
    DNS_OUT="$(nsx dig @1.1.1.1 github.com +time=3 +tries=1 +short 2>&1)"; DNS_RC=$?
  else
    DNS_OUT="$(nsx nslookup github.com 1.1.1.1 2>&1)"; DNS_RC=$?
  fi
  if [ "$DNS_RC" -eq 0 ] && echo "$DNS_OUT" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}'; then
    DNS_OK=true
    DNS_JSON="$(result_json true "resolved via 1.1.1.1: $(echo "$DNS_OUT" | tr '\n' ' ' | cut -c1-200)")"
  else
    DNS_JSON="$(result_json false "dns lookup via 1.1.1.1 exit=$DNS_RC: $(echo "$DNS_OUT" | tr '\n' ' ' | cut -c1-200)")"
  fi
else
  DNS_JSON="$(result_json false "skipped, netns setup failed: $NETNS_SETUP_ERR")"
fi
log "dns_public_resolver: $DNS_JSON"

if $NETNS_SETUP_OK && $DNS_OK; then
  HOST_HTTP_CODE="$(nsx curl --max-time 10 -s -o /dev/null -w '%{http_code}' https://api.github.com 2>"$ERRFILE")"; HOST_CURL_RC=$?
  if [ "$HOST_CURL_RC" -eq 0 ] && [ -n "$HOST_HTTP_CODE" ] && [ "$HOST_HTTP_CODE" != "000" ]; then
    HTTPS_HOST_JSON="$(result_json true "https to api.github.com returned HTTP $HOST_HTTP_CODE")"
  else
    HTTPS_HOST_JSON="$(result_json false "curl exit=$HOST_CURL_RC http_code=${HOST_HTTP_CODE:-none}: $(cat "$ERRFILE" 2>/dev/null)")"
  fi
elif $NETNS_SETUP_OK; then
  HTTPS_HOST_JSON="$(result_json false "skipped, DNS did not resolve via public resolver")"
else
  HTTPS_HOST_JSON="$(result_json false "skipped, netns setup failed: $NETNS_SETUP_ERR")"
fi
log "netns_https_hostname: $HTTPS_HOST_JSON"

# ================== TEST 2: unprivileged tap open ========================
log "running tap_user_create_open test..."
TAP_OK=true
TAP_DETAIL=""
if ! ip tuntap add "$TAP" mode tap user "$RUNTIME_USER" 2>"$ERRFILE"; then
  TAP_OK=false
  TAP_DETAIL="tuntap add failed: $(cat "$ERRFILE" 2>/dev/null)"
fi

if $TAP_OK && ! ip link show "$TAP" >/dev/null 2>&1; then
  TAP_OK=false
  TAP_DETAIL="tap device not visible after creation"
fi

if $TAP_OK; then
  PYOUT="$(sudo -u "$RUNTIME_USER" python3 - "$TAP" <<'PYEOF' 2>&1
import fcntl, os, struct, sys
ifname = sys.argv[1]
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca
try:
    fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', ifname.encode()[:15], IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    os.close(fd)
    print('OK')
except Exception as e:
    print('FAIL: %s' % e)
    sys.exit(1)
PYEOF
)"
  PY_RC=$?
  if [ "$PY_RC" -eq 0 ] && echo "$PYOUT" | grep -q '^OK'; then
    TAP_DETAIL="user '$RUNTIME_USER' opened /dev/net/tun and bound $TAP via TUNSETIFF (IFF_TAP|IFF_NO_PI)"
  else
    TAP_OK=false
    TAP_DETAIL="unprivileged open/ioctl failed (exit=$PY_RC): $(echo "$PYOUT" | tr '\n' ' ' | cut -c1-200)"
  fi
fi
TAP_JSON="$(result_json "$TAP_OK" "$TAP_DETAIL")"
log "tap_user_create_open: $TAP_JSON"

# ================== verdict ==============================================
if $TAP_ONLY; then
  if $TAP_OK; then
    VERDICT="tap_only_pass"
    RECOMMENDATION="user-owned tap open works; runtime-no-root design holds (combine with prior egress verdict)"
  else
    VERDICT="tap_only_fail"
    RECOMMENDATION="unprivileged tap open failed; runtime design needs a CAP_NET_ADMIN helper or FD-passing shim"
  fi
elif $NETNS_SETUP_OK && echo "$PING_JSON" | grep -q '"pass":true' && echo "$HTTPS_IP_JSON" | grep -q '"pass":true'; then
  VERDICT="nat_egress_works"
  RECOMMENDATION="proceed with NAT design"
elif $NETNS_SETUP_OK && (echo "$PING_JSON" | grep -q '"pass":true' || echo "$HTTPS_IP_JSON" | grep -q '"pass":true'); then
  VERDICT="partial"
  RECOMMENDATION="investigate: some but not all pure-IP egress paths worked, re-check nft/forward rules and mirrored-mode behavior before committing to NAT design"
else
  VERDICT="nat_egress_blocked"
  if [ "$MIRRORED" = "true" ]; then
    RECOMMENDATION="flip .wslconfig networkingMode to NAT (wsl --shutdown required) -- mirrored mode is blocking kernel-forwarded egress as expected"
  else
    RECOMMENDATION="investigate: egress blocked but mirrored mode not detected -- check host firewall/nft state before assuming a WSL2 mirrored-mode issue"
  fi
fi
log "VERDICT: $VERDICT -- $RECOMMENDATION"

# On any non-working verdict, capture firewall state so one run is diagnosable
# without a rerun (e.g. a stray FORWARD drop policy would mimic mirrored-mode loss).
DIAG=""
if [ "$VERDICT" != "nat_egress_works" ] && [ "$VERDICT" != "tap_only_pass" ]; then
  DIAG="$( { echo '--- nft ruleset (trunc):'; nft list ruleset 2>&1 | head -c 1500; echo; echo '--- iptables -S FORWARD:'; iptables -S FORWARD 2>&1 | head -5; } | tr '\n' ' ' )"
fi

# ================== final JSON (stdout, exactly one object) ==============
printf '{'
case "$MIRRORED" in
  true) MIRRORED_JSON=true ;;
  false) MIRRORED_JSON=false ;;
  *) MIRRORED_JSON='"unknown"' ;;
esac
printf '"mirrored_mode":%s,' "$MIRRORED_JSON"
printf '"ip_forward_prior":%s,' "$(json_str "$IP_FORWARD_PRIOR")"
printf '"default_iface":%s,' "$(json_str "$DEFAULT_IFACE")"
printf '"iptables_backend":%s,' "$(json_str "$IPTABLES_BACKEND")"
printf '"tests":{'
printf '"netns_ping":%s,' "$PING_JSON"
printf '"netns_https_ip":%s,' "$HTTPS_IP_JSON"
printf '"dns_public_resolver":%s,' "$DNS_JSON"
printf '"netns_https_hostname":%s,' "$HTTPS_HOST_JSON"
printf '"tap_user_create_open":%s' "$TAP_JSON"
printf '},'
printf '"verdict":%s,' "$(json_str "$VERDICT")"
printf '"recommendation":%s,' "$(json_str "$RECOMMENDATION")"
printf '"diagnostics":%s' "$(json_str "$DIAG")"
printf '}\n'
