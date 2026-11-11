#!/usr/bin/env bash
# The checks behind run-wireguard.sh. Runs as root inside a container.
#   wireguard-e2e.sh seed             Before install.sh: a WireGuard server set up by hand
#   wireguard-e2e.sh imported         After install.sh: the panel took it over without breaking it
#   wireguard-e2e.sh manage IP        Turn on NAT, add a client for a device connecting to IP
#   wireguard-e2e.sh client           In a second container: connect with the client's config
#   wireguard-e2e.sh connected        Back on the server: the panel sees the client
#   wireguard-e2e.sh after-reboot     Everything comes back up, then disable and delete
#   wireguard-e2e.sh fresh IP         A server without WireGuard: install it from the panel
set -u
API=https://127.0.0.1:8443/api
JAR=/var/tmp/cp.jar
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
retry() { for _ in $(seq 1 40); do eval "$1" && return 0; sleep 0.5; done; return 1; }
checkr() { if retry "$2"; then ok "$1"; else bad "$1"; fi; }
call() { # method path [json]
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -d "$d" "$API$p"
  else
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' "$API$p"
  fi
}
code() { # method path [json] -> HTTP status, body in /var/tmp/body
  local m=$1 p=$2 d=${3:-}
  curl -sk -o /var/tmp/body -w '%{http_code}' -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' \
    -H 'Content-Type: application/json' ${d:+-d "$d"} "$API$p"
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
wgjson() { call GET /wireguard >/var/tmp/wg.json; }
w() { j "$1" </var/tmp/wg.json; }
login() {
  rm -f $JAR
  local pw
  pw=$(cat /var/lib/cloudpanel/initial_admin_password)
  call POST /auth/login "{\"username\":\"admin\",\"password\":\"$pw\"}" >/dev/null
  retry '[ "$(call GET /auth/me | j "d[\"username\"]" 2>/dev/null)" = admin ]' || bad "login"
}
run_job() { # path -> status; output in /var/tmp/job.out
  local r id status=running
  r=$(call POST "$1")
  id=$(echo "$r" | j 'd["job_id"]') || { echo "no job: $r" >/var/tmp/job.out; echo failed; return; }
  for _ in $(seq 1 900); do
    call GET "/jobs/$id" >/var/tmp/job.json
    status=$(j 'd["status"]' </var/tmp/job.json)
    [ "$status" != running ] && break
    sleep 1
  done
  j 'd["output"]' </var/tmp/job.json >/var/tmp/job.out
  echo "$status"
}
started() { systemctl show -p ActiveEnterTimestampMonotonic --value wg-quick@wg0; }
peers() { wg show wg0 peers 2>/dev/null | grep -c .; }
finish() {
  echo "  -- $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}

seed() {
  echo "== A WireGuard server set up by hand"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends wireguard-tools iptables >/dev/null
  umask 077
  mkdir -p /etc/wireguard /var/tmp/seed
  wg genkey >/var/tmp/seed/server.key
  wg genkey | tee /var/tmp/seed/phone.key | wg pubkey >/var/tmp/seed/phone.pub
  wg genpsk >/var/tmp/seed/phone.psk
  cat >/etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = $(cat /var/tmp/seed/server.key)
PostUp = iptables -A INPUT -i %i -m comment --comment seeded-by-hand -j ACCEPT
PostDown = iptables -D INPUT -i %i -m comment --comment seeded-by-hand -j ACCEPT
SaveConfig = false

### Client phone
[Peer]
PublicKey = $(cat /var/tmp/seed/phone.pub)
PresharedKey = $(cat /var/tmp/seed/phone.psk)
AllowedIPs = 10.9.0.2/32, 192.168.77.0/24
EOF
  systemctl enable --now wg-quick@wg0 >/dev/null 2>&1
  check "wg0 is up before the panel exists" '[ "$(wg show wg0 listen-port)" = 51820 ]'
  finish
}

imported() {
  echo "== The installer and the panel take over the existing setup"
  check "installer did not ask and said it imports" 'grep -q "already set up; the panel imports it" /var/tmp/install.log'
  check "installer remembered the answer" 'grep -qx "CLOUDPANEL_WIREGUARD=1" /etc/cloudpanel/cloudpanel.env'
  check "installer kept the WireGuard port open in UFW" 'ufw status | grep -q "^51820/udp .*ALLOW"'
  check "the panel may write /etc/wireguard" 'systemctl cat cloudpanel | grep -q -- "-/etc/wireguard"'
  login
  wgjson
  check "first visit imports" '[ "$(w "len(d[\"import_notes\"] or [])")" -ge 1 ]'
  w 'd["import_notes"]' | sed 's/^/       /'
  check "server key kept" '[ "$(w "d[\"server\"][\"public_key\"]")" = "$(wg pubkey </var/tmp/seed/server.key)" ]'
  check "port and address kept" '[ "$(w "d[\"server\"][\"listen_port\"], d[\"server\"][\"address\"]")" = "51820 10.9.0.1/24" ]'
  check "marked as imported and running" '[ "$(w "d[\"server\"][\"imported\"], d[\"server\"][\"enabled\"], d[\"running\"]")" = "True True True" ]'
  check "custom PostUp kept, SaveConfig dropped" '[ "$(w "\"|\".join(d[\"server\"][\"extra\"])")" = "PostUp = iptables -A INPUT -i %i -m comment --comment seeded-by-hand -j ACCEPT|PostDown = iptables -D INPUT -i %i -m comment --comment seeded-by-hand -j ACCEPT" ]'
  check "peer imported by name, address and route" '[ "$(w "[(c[\"name\"], c[\"address\"], c[\"server_allowed_ips\"], c[\"imported\"], c[\"has_config\"]) for c in d[\"clients\"]]")" = "[('"'"'phone'"'"', '"'"'10.9.0.2'"'"', '"'"'192.168.77.0/24'"'"', True, False)]" ]'
  check "importing left the file alone" '! grep -q "Managed by CloudPanel" /etc/wireguard/wg0.conf'
  check "importing left wg0 running" '[ "$(peers)" = 1 ]'
  wgjson
  check "second visit imports nothing" '[ "$(w "d[\"import_notes\"]")" = None ]'
  check "no duplicate peers" '[ "$(w "len(d[\"clients\"])")" = 1 ]'
  check "config of an imported peer is refused" '[ "$(code GET /wireguard/clients/1/config)" = 400 ]'
  finish
}

manage() {
  local ip=$1
  echo "== Managing it from the panel"
  login
  local before
  before=$(started)
  check "settings saved" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51820,\"address\":\"10.9.0.1/24\",\"endpoint\":\"$ip\",\"dns\":\"1.1.1.1\",\"nat\":true,\"out_interface\":\"\"}")" = 200 ]' \
    || cat /var/tmp/body
  check "original saved before the rewrite" 'grep -q "### Client phone" /etc/wireguard/wg0.conf.pre-cloudpanel'
  check "file now managed, mode 600" 'head -1 /etc/wireguard/wg0.conf | grep -q "Managed by CloudPanel" && [ "$(stat -c %a /etc/wireguard/wg0.conf)" = 600 ]'
  check "SaveConfig is gone" '! grep -qi saveconfig /etc/wireguard/wg0.conf'
  check "server settings restart wg0" '[ "$(started)" != "$before" ]'
  check "custom PostUp still runs" 'iptables -S INPUT | grep -q seeded-by-hand'
  check "NAT for the tunnel network" 'iptables -t nat -S POSTROUTING | grep -q -- "-s 10.9.0.0/24 .*MASQUERADE"'
  check "forwarding on" '[ "$(sysctl -n net.ipv4.ip_forward)" = 1 ]'
  check "forwarded traffic accepted before UFW" 'iptables -S FORWARD | sed -n 2,3p | grep -q "wg0"'
  check "imported peer kept with its route" 'wg show wg0 allowed-ips | grep -q "10.9.0.2/32 192.168.77.0/24"'
  check "panel tracks a UFW rule for the port" '[ "$(call GET /firewall/rules | j "[r[\"comment\"] for r in d if r[\"port\"]==51820 and r[\"protocol\"]==\"udp\"]")" = "['"'"'WireGuard'"'"']" ]'

  python3 -c 'import socket,time; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 51821)); time.sleep(60)' &
  local hog=$!
  sleep 1
  check "a port already in use is refused" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51821,\"address\":\"10.9.0.1/24\",\"endpoint\":\"$ip\",\"dns\":\"1.1.1.1\",\"nat\":true}")" = 422 ]' \
    || cat /var/tmp/body
  check "the VPN stays up on its old port" '[ "$(wg show wg0 listen-port)" = 51820 ] && [ "$(peers)" = 1 ]'
  check "the old file is back" 'grep -qx "ListenPort = 51820" /etc/wireguard/wg0.conf'
  check "the saved settings are unchanged" '[ "$(call GET /wireguard | j "d[\"server\"][\"listen_port\"]")" = 51820 ]'
  kill "$hog" 2>/dev/null

  before=$(started)
  check "client created" '[ "$(code POST /wireguard/clients "{\"name\":\"laptop\",\"allowed_ips\":\"0.0.0.0/0\"}")" = 201 ]' || cat /var/tmp/body
  local id
  id=$(j 'd["id"]' </var/tmp/body)
  check "next free address, after the imported one" '[ "$(j "d[\"address\"]" </var/tmp/body)" = 10.9.0.3 ]'
  check "peer live on wg0" '[ "$(peers)" = 2 ]'
  check "adding a client did not restart wg0" '[ "$(started)" = "$before" ]'
  check "duplicate name refused" '[ "$(code POST /wireguard/clients "{\"name\":\"LAPTOP\"}")" = 409 ]'
  check "bad name refused" '[ "$(code POST /wireguard/clients "{\"name\":\"a\\nb\"}")" = 400 ]'
  check "bad routes refused" '[ "$(code POST /wireguard/clients "{\"name\":\"x\",\"allowed_ips\":\"nope\"}")" = 400 ]'
  check "bad interface refused" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51820,\"address\":\"10.9.0.1/24\",\"endpoint\":\"$ip\",\"nat\":true,\"out_interface\":\"eth0;reboot\"}")" = 400 ]'
  check "moving the network away from clients refused" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51820,\"address\":\"10.50.0.1/24\",\"endpoint\":\"$ip\",\"nat\":true}")" = 409 ]'

  local h
  h=$(curl -sk -D - -o /var/tmp/laptop.conf -b $JAR "$API/wireguard/clients/$id/download")
  check "download is an attachment named after the client" 'echo "$h" | grep -qi "content-disposition: attachment; filename=\"laptop.conf\""'
  check "config points at the server" 'grep -qx "Endpoint = $ip:51820" /var/tmp/laptop.conf && grep -qx "PublicKey = $(wg pubkey </var/tmp/seed/server.key)" /var/tmp/laptop.conf'
  local pub psk
  pub=$(grep '^PrivateKey' /var/tmp/laptop.conf | cut -d' ' -f3 | wg pubkey)
  psk=$(wg show wg0 preshared-keys | awk -v k="$pub" '$1==k {print $2}')
  check "config's preshared key is the one on wg0" '[ -n "$psk" ] && grep -qx "PresharedKey = $psk" /var/tmp/laptop.conf'
  check "QR code returned" '[ "$(call GET /wireguard/clients/$id/config | j "d[\"qr\"][\"width\"] > 20")" = True ]'
  check "viewing the config is audited" '[ "$(call GET "/events?action=wireguard.client.config" | j "len(d)" 2>/dev/null || echo 0)" -ge 1 ]'
  finish
}

client() {
  echo "== A device connects"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q >/dev/null && apt-get install -y -q --no-install-recommends wireguard-tools iptables iputils-ping >/dev/null
  umask 077
  mkdir -p /etc/wireguard
  # DNS needs resolvconf, which a phone or laptop app handles itself.
  grep -v '^DNS' /var/tmp/laptop.conf >/etc/wireguard/wgc.conf
  check "tunnel comes up" 'wg-quick up wgc >/var/tmp/wgc.log 2>&1' || cat /var/tmp/wgc.log
  checkr "server reachable through the tunnel" 'ping -c1 -W1 10.9.0.1 >/dev/null'
  check "handshake done" '[ "$(wg show wgc latest-handshakes | awk "{print \$2}")" -gt 0 ]'
  if ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then
    ok "internet reachable through the server (NAT)"
  else
    echo "  skip internet through the tunnel (no outside network here?)"
  fi
  finish
}

connected() {
  echo "== The panel sees the device"
  login
  wgjson
  check "laptop shows a handshake and traffic" '[ "$(w "[(c[\"status\"] or {}).get(\"latest_handshake\") is not None and c[\"status\"][\"rx\"] > 0 for c in d[\"clients\"] if c[\"name\"]==\"laptop\"]")" = "[True]" ]'
  check "endpoint of the device shown" '[ "$(w "[c[\"status\"][\"endpoint\"] is not None for c in d[\"clients\"] if c[\"name\"]==\"laptop\"]")" = "[True]" ]'
  finish
}

after_reboot() {
  echo "== After a reboot"
  login
  checkr "wg0 back up with both peers" '[ "$(peers)" = 2 ]'
  check "NAT back" 'iptables -t nat -S POSTROUTING | grep -q -- "-s 10.9.0.0/24 .*MASQUERADE"'
  wgjson
  check "panel shows it running" '[ "$(w "d[\"running\"], d[\"enabled_at_boot\"]")" = "True True" ]'
  local id
  id=$(w '[c["id"] for c in d["clients"] if c["name"]=="laptop"][0]')
  check "disable a client" '[ "$(code PATCH /wireguard/clients/$id "{\"enabled\":false}")" = 200 ]'
  check "disabled peer removed from wg0" '[ "$(peers)" = 1 ]'
  check "enable it again" '[ "$(code PATCH /wireguard/clients/$id "{\"enabled\":true}")" = 200 ] && [ "$(peers)" = 2 ]'
  check "wrong private key for the imported peer refused" '[ "$(code PATCH /wireguard/clients/1 "{\"private_key\":\"$(wg genkey)\"}")" = 400 ]'
  check "its real private key accepted" '[ "$(code PATCH /wireguard/clients/1 "{\"private_key\":\"$(cat /var/tmp/seed/phone.key)\"}")" = 200 ]'
  check "imported peer now has a config" '[ "$(code GET /wireguard/clients/1/config)" = 200 ] && grep -q "Address = 10.9.0.2/32" /var/tmp/body'
  check "delete a client" '[ "$(code DELETE /wireguard/clients/$id)" = 200 ] && [ "$(peers)" = 1 ]'
  check "turn the server off" '[ "$(code PUT /wireguard "{\"enabled\":false,\"listen_port\":51820,\"address\":\"10.9.0.1/24\",\"endpoint\":\"10.0.0.1\",\"nat\":true}")" = 200 ]' || cat /var/tmp/body
  check "wg0 down and not started at boot" '! ip link show wg0 >/dev/null 2>&1 && ! systemctl is-enabled --quiet wg-quick@wg0'
  check "UFW port closed again" '! ufw status | grep -q "^51820/udp"'
  check "NAT rules removed" '! iptables -t nat -S POSTROUTING | grep -q 10.9.0.0/24'
  finish
}

fresh() {
  local ip=$1
  echo "== A server without WireGuard"
  check "installer did not install it without a yes" '! command -v wg >/dev/null && grep -qx "CLOUDPANEL_WIREGUARD=0" /etc/cloudpanel/cloudpanel.env'
  check "/etc/wireguard exists for the sandbox" '[ -d /etc/wireguard ] && [ "$(stat -c %a /etc/wireguard)" = 700 ]'
  login
  wgjson
  check "panel says not installed, can install" '[ "$(w "d[\"installed\"], d[\"can_install\"], d[\"server\"][\"configured\"]")" = "False True False" ]'
  check "enabling before installing is refused" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51820,\"address\":\"10.8.0.1/24\",\"endpoint\":\"$ip\",\"nat\":true}")" = 422 ]'
  local s
  s=$(run_job /wireguard/install)
  check "install job succeeded" '[ "$s" = succeeded ]' || tail -20 /var/tmp/job.out
  check "wg installed" 'command -v wg-quick >/dev/null'
  check "server created" '[ "$(code PUT /wireguard "{\"enabled\":true,\"listen_port\":51820,\"address\":\"10.8.0.1/24\",\"endpoint\":\"$ip\",\"nat\":true}")" = 200 ]' || cat /var/tmp/body
  check "client created" '[ "$(code POST /wireguard/clients "{\"name\":\"phone\"}")" = 201 ] && [ "$(j "d[\"address\"]" </var/tmp/body)" = 10.8.0.2 ]'
  check "wg0 running with the client" '[ "$(peers)" = 1 ] && [ "$(wg show wg0 listen-port)" = 51820 ]'
  check "server key on wg0 matches the panel" '[ "$(wg show wg0 public-key)" = "$(call GET /wireguard | j "d[\"server\"][\"public_key\"]")" ]'
  finish
}

case "${1:-}" in
  seed) seed ;;
  imported) imported ;;
  manage) manage "$2" ;;
  client) client ;;
  connected) connected ;;
  after-reboot) after_reboot ;;
  fresh) fresh "$2" ;;
  *)
    echo "usage: $0 seed|imported|manage IP|client|connected|after-reboot|fresh IP"
    exit 2
    ;;
esac
