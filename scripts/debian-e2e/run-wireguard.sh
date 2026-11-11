#!/usr/bin/env bash
# End-to-end test of WireGuard support on Debian 13 with real systemd, in throwaway containers:
#
#   server   WireGuard set up by hand before CloudPanel is installed. install.sh must keep it, the
#            panel must import it, then manage it: NAT, a new client, a reboot, disable and delete.
#   client   A device that connects with the configuration the panel hands out.
#   fresh    A server without WireGuard, which the panel installs itself.
#
#   scripts/debian-e2e/run-wireguard.sh          Run everything, remove the containers
#   scripts/debian-e2e/run-wireguard.sh --keep   Keep them afterwards
#
# Needs Docker, with a kernel that has WireGuard (Docker Desktop's does).
set -euo pipefail

keep=0
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    *)
      echo "Unknown option: $arg"
      exit 2
      ;;
  esac
done

cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
image=cloudpanel-debian-e2e
net=cloudpanel-wg-e2e
server=cloudpanel-wg-server
client=cloudpanel-wg-client
fresh=cloudpanel-wg-fresh
root=$(pwd)
[ -n "${WINDIR:-}" ] && root=$(pwd -W)
tmp=$(mktemp -d)
# docker cp gets the path as it is (no MSYS conversion), so give it the Windows form.
[ -n "${WINDIR:-}" ] && tmp=$(cd "$tmp" && pwd -W)

echo "==> Building the Linux binary"
docker run --rm \
  -v "$root:/src:ro" \
  -v cloudpanel-e2e-cargo:/usr/local/cargo/registry \
  -v cloudpanel-e2e-target:/target \
  -e CARGO_TARGET_DIR=/target \
  rust:1-trixie \
  bash -c 'cd /src && cargo build --release --locked --quiet && cp /target/release/cloudpanel /target/cloudpanel-e2e'

echo "==> Building the test image"
docker build -q -t "$image" scripts/debian-e2e >/dev/null

cleanup() {
  rm -rf "$tmp"
  if [ "$keep" = 1 ]; then
    echo "Kept $server, $client and $fresh (remove with: docker rm -f $server $client $fresh; docker network rm $net)"
  else
    docker rm -f "$server" "$client" "$fresh" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
  fi
}
docker rm -f "$server" "$client" "$fresh" >/dev/null 2>&1 || true
docker network rm "$net" >/dev/null 2>&1 || true
trap cleanup EXIT
docker network create "$net" >/dev/null

echo "==> Starting three Debian 13 machines with systemd"
for name in "$server" "$client" "$fresh"; do
  docker run -d --name "$name" --hostname "${name#cloudpanel-wg-}" --network "$net" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
    "$image" >/dev/null
done

wait_for_boot() {
  local s=""
  for _ in $(seq 1 90); do
    s=$(docker exec "$1" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) return 0 ;; esac
    sleep 1
  done
  echo "systemd did not finish booting in $1 ($s)"
  return 1
}
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }

docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e >"$tmp/cloudpanel"
for name in "$server" "$client" "$fresh"; do
  wait_for_boot "$name"
  docker cp "$tmp/cloudpanel" "$name":/var/tmp/cloudpanel
  docker cp install.sh "$name":/var/tmp/install.sh
  docker cp scripts/debian-e2e/wireguard-e2e.sh "$name":/usr/local/bin/wireguard-e2e.sh
  docker exec "$name" sh -c 'chmod +x /var/tmp/cloudpanel; sed -i "s/\r$//" /var/tmp/install.sh /usr/local/bin/wireguard-e2e.sh'
done
server_ip=$(ip_of "$server")
fresh_ip=$(ip_of "$fresh")

status=0
t() { docker exec "$1" bash /usr/local/bin/wireguard-e2e.sh "${@:2}" || status=1; }

t "$server" seed

# The fresh server installs in the background while the first one is tested. No --with-wireguard
# and no terminal: the installer must not install WireGuard on its own.
echo "==> Running install.sh on both servers"
docker exec "$fresh" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 >/var/tmp/install.log 2>&1' &
fresh_install=$!
# With the firewall: an existing tunnel's port must stay open when UFW is turned on.
docker exec "$server" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --swap-size 0 >/var/tmp/install.log 2>&1' || {
  docker exec "$server" tail -40 /var/tmp/install.log
  exit 1
}

t "$server" imported
t "$server" manage "$server_ip"
docker cp "$server":/var/tmp/laptop.conf "$tmp/laptop.conf"
docker cp "$tmp/laptop.conf" "$client":/var/tmp/laptop.conf
t "$client" client
t "$server" connected

echo "==> Rebooting the server"
docker restart "$server" >/dev/null
wait_for_boot "$server"
sleep 5
t "$server" after-reboot

wait "$fresh_install" || {
  docker exec "$fresh" tail -40 /var/tmp/install.log
  exit 1
}
t "$fresh" fresh "$fresh_ip"

[ "$status" = 0 ] && echo "==> All WireGuard checks passed" || echo "==> Some WireGuard checks failed"
exit "$status"
