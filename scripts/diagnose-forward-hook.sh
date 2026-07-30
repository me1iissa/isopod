#!/usr/bin/env bash
# Reproduces dogfood finding #51 and verifies isopod's fix for it, in throwaway
# network namespaces.
#
# If isopod is installed alongside Docker and guests cannot reach the network,
# this is almost certainly why: Docker sets the iptables `ip filter` FORWARD
# policy to DROP, and every guest->WAN packet falls through to it. `isopod setup`
# reports complete success while it happens, because nothing in setup inspects
# whether another tool already claimed the forward hook.
#
# It answers two questions rather than one. Does an accept rule in DOCKER-USER
# restore egress? And — the question that decides whether such a rule is allowed
# to exist at all — does isopod's OWN nftables enforcement still apply once it is
# there? An accept verdict ends evaluation of its own base chain only; every other
# base chain at the hook still runs. This measures that rather than asserting it.
#
# Topology, entirely inside throwaway namespaces:
#
#   [client ns] 10.99.0.2 --veth-- 10.99.0.1 [router ns] 10.98.0.1 --veth-- 10.98.0.2 [server ns]
#                                   ip_forward=1
#                              nft `inet probe` forward chain
#                              iptables FORWARD / DOCKER-USER
#
# A client→server connection must be FORWARDED by the router namespace, so it
# traverses the forward hook in both directions. Nothing here touches your real
# firewall, routing, or Docker: all three namespaces and every rule in them are
# deleted at the end.
set -u

R=ipf-router
C=ipf-client
S=ipf-server
PORT=19998

cleanup() { for n in "$R" "$C" "$S"; do ip netns del "$n" 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup

for n in "$R" "$C" "$S"; do ip netns add "$n" || { echo "could not create netns $n"; exit 1; }; done

ip -n "$C" link set lo up; ip -n "$R" link set lo up; ip -n "$S" link set lo up

# client <-> router
ip link add cr type veth peer name rc
ip link set cr netns "$C"; ip link set rc netns "$R"
ip -n "$C" addr add 10.99.0.2/24 dev cr; ip -n "$C" link set cr up
ip -n "$R" addr add 10.99.0.1/24 dev rc; ip -n "$R" link set rc up
ip -n "$C" route add default via 10.99.0.1

# router <-> server
ip link add rs type veth peer name sr
ip link set rs netns "$R"; ip link set sr netns "$S"
ip -n "$R" addr add 10.98.0.1/24 dev rs; ip -n "$R" link set rs up
ip -n "$S" addr add 10.98.0.2/24 dev sr; ip -n "$S" link set sr up
ip -n "$S" route add default via 10.98.0.1

ip netns exec "$R" sysctl -qw net.ipv4.ip_forward=1

ip netns exec "$S" python3 -c "
import socket, threading, time
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.98.0.2', $PORT)); s.listen(8)
def serve():
    while True:
        try: c,_ = s.accept(); c.sendall(b'hi'); c.close()
        except OSError: return
threading.Thread(target=serve, daemon=True).start()
time.sleep(600)
" &
LISTENER=$!
sleep 1

# A successful connect requires the SYN forwarded one way and the SYN-ACK
# forwarded back, so this exercises both directions of the forward hook.
try_connect() {
  ip netns exec "$C" python3 -c "
import socket
try:
    c = socket.create_connection(('10.98.0.2', $PORT), timeout=2)
    data = c.recv(8); c.close()
    print('REACHED' if data == b'hi' else 'PARTIAL')
except Exception as e:
    print('BLOCKED', type(e).__name__)
" 2>/dev/null
}

nft_drop_on() { ip netns exec "$R" nft -f - <<EOF
table inet probe {
  chain forward { type filter hook forward priority filter; policy accept;
    tcp dport $PORT drop
  }
}
EOF
}
nft_off() { ip netns exec "$R" nft delete table inet probe 2>/dev/null || true; }

# Reproduce Docker's shape exactly: FORWARD policy DROP, with a DOCKER-USER
# chain jumped to from FORWARD, and isopod's accept rule inserted into it.
docker_shape_on() {
  ip netns exec "$R" iptables -N DOCKER-USER 2>/dev/null || true
  ip netns exec "$R" iptables -A DOCKER-USER -j RETURN
  ip netns exec "$R" iptables -I FORWARD -j DOCKER-USER
  ip netns exec "$R" iptables -P FORWARD DROP
}
isopod_accept_on() {
  # What `isopod setup` would install. Both directions: the veths here stand in
  # for isopod-tap*.
  ip netns exec "$R" iptables -I DOCKER-USER -i rc -j ACCEPT
  ip netns exec "$R" iptables -I DOCKER-USER -o rc -j ACCEPT
}
ipt_off() {
  ip netns exec "$R" iptables -P FORWARD ACCEPT 2>/dev/null || true
  ip netns exec "$R" iptables -F FORWARD 2>/dev/null || true
  ip netns exec "$R" iptables -F DOCKER-USER 2>/dev/null || true
  ip netns exec "$R" iptables -X DOCKER-USER 2>/dev/null || true
}

echo "kernel: $(uname -r)"
echo
printf '%-52s %s\n' "CASE (forward hook)" "RESULT"
printf '%-52s %s\n' "-------------------" "------"

nft_off; ipt_off
printf '%-52s %s\n' "plain forwarding (harness control)" "$(try_connect)"

nft_off; ipt_off; docker_shape_on
printf '%-52s %s\n' "Docker shape: FORWARD DROP (reproduces the bug)" "$(try_connect)"

nft_off; ipt_off; docker_shape_on; isopod_accept_on
FIXED="$(try_connect)"
printf '%-52s %s\n' "  + isopod ACCEPT in DOCKER-USER (the fix)" "$FIXED"

nft_off; ipt_off; nft_drop_on
printf '%-52s %s\n' "isopod nft DROP alone" "$(try_connect)"

nft_off; ipt_off; nft_drop_on; docker_shape_on; isopod_accept_on
SAFE="$(try_connect)"
printf '%-52s %s\n' "  + nft DROP  <-- DOES ENFORCEMENT SURVIVE" "$SAFE"

kill $LISTENER 2>/dev/null || true
echo
echo "1. does the fix restore connectivity?  $FIXED  (want REACHED)"
echo "2. does isopod still enforce?          $SAFE   (want BLOCKED)"
echo
if [ "${FIXED%% *}" = "REACHED" ] && [ "${SAFE%% *}" = "BLOCKED" ]; then
  echo "VERDICT: both hold at the forward hook, in both directions."
  echo "=> the DOCKER-USER fix restores egress AND leaves isopod's own"
  echo "   enforcement authoritative. Safe to implement."
else
  echo "VERDICT: NOT the expected pair — do not implement on this basis."
  echo "   fix restored connectivity: $FIXED"
  echo "   enforcement still applied: $SAFE"
fi
