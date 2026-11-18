#!/usr/bin/env bash
# End-to-end test of the email sending service on Debian 13 with real systemd, in throwaway containers:
#
#   server   Installed with --with-mail: send over SMTP and the API, DKIM, delivery tracking,
#            webhooks, refusals and forwarding, then a second install and an uninstall.
#   fresh    Installed without it, and without a terminal: nothing mail-related is installed.
#            Then it is installed and managed from the panel's API (the Email page).
#
#   scripts/debian-e2e/run-mail.sh          Run everything, remove the containers
#   scripts/debian-e2e/run-mail.sh --keep   Keep them afterwards
#
# Needs Docker and internet access (packages). No mail leaves the containers: Postfix relays to a
# local sink.
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
server=cloudpanel-mail-server
fresh=cloudpanel-mail-fresh
root=$(pwd)
[ -n "${WINDIR:-}" ] && root=$(pwd -W)
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
    echo "Kept $server and $fresh. Remove with: docker rm -f $server $fresh"
  else
    docker rm -f "$server" "$fresh" >/dev/null 2>&1 || true
  fi
}
docker rm -f "$server" "$fresh" >/dev/null 2>&1 || true
trap cleanup EXIT

echo "==> Starting two Debian 13 machines with systemd"
for name in "$server" "$fresh"; do
  docker run -d --name "$name" --hostname "${name#cloudpanel-mail-}" --privileged --cgroupns=private \
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

docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e >"$tmp/cloudpanel"
for name in "$server" "$fresh"; do
  wait_for_boot "$name"
  docker cp "$tmp/cloudpanel" "$name":/var/tmp/cloudpanel
  docker cp install.sh "$name":/var/tmp/install.sh
  docker cp scripts/debian-e2e/mail-e2e.sh "$name":/usr/local/bin/mail-e2e.sh
  docker exec "$name" sh -c 'chmod +x /var/tmp/cloudpanel; sed -i "s/\r$//" /var/tmp/install.sh /usr/local/bin/mail-e2e.sh'
done

status=0
t() { docker exec "$1" bash /usr/local/bin/mail-e2e.sh "${@:2}" || status=1; }

echo "==> Running install.sh on both servers"
docker exec "$fresh" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 </dev/null >/var/tmp/install.log 2>&1' &
fresh_install=$!
# No --mail-email: no public DNS here, so the certificate is self-signed.
docker exec "$server" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 --with-mail --mail-hostname mail.test >/var/tmp/install.log 2>&1' || {
  docker exec "$server" tail -60 /var/tmp/install.log
  exit 1
}
# For the DKIM check (dkimpy) only; the service doesn't need it.
docker exec "$server" sh -c 'apt-get install -y -q python3-dkim >/dev/null 2>&1'

t "$server" installed
t "$server" send

echo "==> Running install.sh again"
docker exec "$server" sh -c 'bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 </dev/null >/var/tmp/install2.log 2>&1' || {
  docker exec "$server" tail -40 /var/tmp/install2.log
  status=1
}
t "$server" reinstall

docker exec "$server" sh -c 'bash /var/tmp/install.sh --uninstall >/var/tmp/uninstall.log 2>&1' || status=1
t "$server" uninstall

wait "$fresh_install" || {
  docker exec "$fresh" tail -40 /var/tmp/install.log
  exit 1
}
t "$fresh" not-installed
t "$fresh" panel

[ "$status" = 0 ] && echo "==> All mail checks passed" || echo "==> Some mail checks failed"
exit "$status"
