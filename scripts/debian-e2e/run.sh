#!/usr/bin/env bash
# End-to-end test of the panel on Debian 13 with real systemd, in a throwaway container. It
# builds a Linux binary, runs install.sh, then checks site apps (PM2 and systemd), .env handling
# and the www redirect through the API, including surviving a reboot. Needs Docker.
#
#   scripts/debian-e2e/run.sh              Build, install, run every check, remove the container
#   scripts/debian-e2e/run.sh --keep       Keep the container afterwards, with the panel on
#                                          https://localhost:18443, for poking around
#   scripts/debian-e2e/run.sh --no-checks  Stop after installing (use with --keep)
#   scripts/debian-e2e/run.sh --security   Attack an install with MariaDB and SQLite (security.sh),
#                                          instead of the feature checks
set -euo pipefail

keep=0
checks=1
security=0
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    --no-checks) checks=0 ;;
    --security) security=1 ;;
    *)
      echo "Unknown option: $arg"
      exit 2
      ;;
  esac
done

cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
image=cloudpanel-debian-e2e
name=cloudpanel-debian-e2e
root=$(pwd)
[ -n "${WINDIR:-}" ] && root=$(pwd -W)

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

docker rm -f "$name" >/dev/null 2>&1 || true
cleanup() {
  if [ "$keep" = 1 ]; then
    echo "Kept container $name. Panel: https://localhost:18443 (remove with: docker rm -f $name)"
  else
    docker rm -f "$name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "==> Starting Debian 13 with systemd"
docker run -d --name "$name" --hostname e2e --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
  -p 18443:8443 \
  "$image" >/dev/null

wait_for_boot() {
  for _ in $(seq 1 90); do
    s=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) return 0 ;; esac
    sleep 1
  done
  echo "systemd did not finish booting ($s)"
  return 1
}
wait_for_boot

docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e \
  | docker exec -i "$name" sh -c 'cat > /var/tmp/cloudpanel && chmod +x /var/tmp/cloudpanel'
docker cp install.sh "$name":/var/tmp/install.sh
docker cp scripts/debian-e2e/e2e.sh "$name":/usr/local/bin/e2e.sh
docker cp scripts/debian-e2e/security.sh "$name":/usr/local/bin/security.sh

install_args=""
[ "$security" = 1 ] && install_args="--databases mariadb,sqlite"

echo "==> Running install.sh"
docker exec "$name" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 '"$install_args"' \
  >/var/tmp/install.log 2>&1' || {
  docker exec "$name" tail -40 /var/tmp/install.log
  exit 1
}

[ "$checks" = 1 ] || exit 0

status=0
if [ "$security" = 1 ]; then
  docker exec "$name" bash /usr/local/bin/security.sh attack || status=$?
  echo "==> Rebooting the container"
  docker restart "$name" >/dev/null
  wait_for_boot
  sleep 5
  docker exec "$name" bash /usr/local/bin/security.sh after-reboot || status=$?
  exit "$status"
fi

docker exec "$name" bash /usr/local/bin/e2e.sh before-reboot || status=$?

echo "==> Rebooting the container"
docker restart "$name" >/dev/null
wait_for_boot
sleep 5
docker exec "$name" bash /usr/local/bin/e2e.sh after-reboot || status=$?

# Connections from this machine to itself skip the firewall, so these come from a second one.
echo "==> Checking the firewall with real traffic"
ip=$(docker exec "$name" hostname -i | cut -d' ' -f1)
docker exec "$name" bash /usr/local/bin/e2e.sh firewall-rules || status=$?
expect="19100=closed 19205=closed 19206=open 19300=closed 19600=closed 19700=open 19800=open 19900=open 19950=open 19960=closed 20000=closed 20100=open"
results=$(docker run --rm "$image" bash -c "
  for want in $expect; do
    port=\${want%=*}
    if curl -s -m 3 -o /dev/null http://$ip:\$port/; then got=open; else got=closed; fi
    echo \"\$port=\$got\"
  done")
for want in $expect; do
  if echo "$results" | grep -qx "$want"; then
    echo "  ok   port ${want%=*} is ${want#*=}"
  else
    echo "  FAIL port ${want%=*} should be ${want#*=}"
    status=1
  fi
done

exit "$status"
