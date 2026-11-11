#!/usr/bin/env bash
# End-to-end test of Garage object storage on Debian 13 with real systemd, in throwaway containers:
#
#   server   Installed with --with-garage: buckets, keys and grants through the panel, used over
#            real S3 requests, then a reboot, a second install and an uninstall.
#   fresh    Installed without it: the panel installs Garage itself.
#
#   scripts/debian-e2e/run-garage.sh          Run everything, remove the containers
#   scripts/debian-e2e/run-garage.sh --keep   Keep them afterwards
#
# Needs Docker and internet access (Garage's release is downloaded and checked).
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
server=cloudpanel-garage-server
fresh=cloudpanel-garage-fresh
root=$(pwd)
[ -n "${WINDIR:-}" ] && root=$(pwd -W)
# target/ is ignored by git, and writable where /tmp isn't (some Windows shells).
tmp=$(mktemp -d 2>/dev/null || mktemp -d -p target)
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
    echo "Kept $server (https://localhost:18444) and $fresh (https://localhost:18445)"
    echo "Remove with: docker rm -f $server $fresh"
  else
    docker rm -f "$server" "$fresh" >/dev/null 2>&1 || true
  fi
}
docker rm -f "$server" "$fresh" >/dev/null 2>&1 || true
trap cleanup EXIT

echo "==> Starting two Debian 13 machines with systemd"
port=18444
for name in "$server" "$fresh"; do
  docker run -d --name "$name" --hostname "${name#cloudpanel-garage-}" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp -p "$port:8443" \
    "$image" >/dev/null
  port=$((port + 1))
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

docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e >"$tmp/cloudpanel"
for name in "$server" "$fresh"; do
  wait_for_boot "$name"
  docker cp "$tmp/cloudpanel" "$name":/var/tmp/cloudpanel
  docker cp install.sh "$name":/var/tmp/install.sh
  docker cp scripts/debian-e2e/garage-e2e.sh "$name":/usr/local/bin/garage-e2e.sh
  docker exec "$name" sh -c 'chmod +x /var/tmp/cloudpanel; sed -i "s/\r$//" /var/tmp/install.sh /usr/local/bin/garage-e2e.sh'
done

status=0
t() { docker exec "$1" bash /usr/local/bin/garage-e2e.sh "${@:2}" || status=1; }

# No --with-garage and no terminal on the fresh one: the installer must not install it on its own.
echo "==> Running install.sh on both servers"
docker exec "$fresh" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 >/var/tmp/install.log 2>&1' &
fresh_install=$!
docker exec "$server" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 --with-garage >/var/tmp/install.log 2>&1' || {
  docker exec "$server" tail -40 /var/tmp/install.log
  exit 1
}

t "$server" installed
t "$server" manage

echo "==> Rebooting the server"
docker restart "$server" >/dev/null
wait_for_boot "$server"
sleep 5
t "$server" after-reboot
t "$server" reinstall
t "$server" uninstall

wait "$fresh_install" || {
  docker exec "$fresh" tail -40 /var/tmp/install.log
  exit 1
}
t "$fresh" fresh

[ "$status" = 0 ] && echo "==> All Garage checks passed" || echo "==> Some Garage checks failed"
exit "$status"
