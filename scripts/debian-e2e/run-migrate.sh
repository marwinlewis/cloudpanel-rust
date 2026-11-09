#!/usr/bin/env bash
# End-to-end test of migrate-from-ce.sh against real CloudPanel CE, on Debian 13 with real systemd,
# in throwaway containers. A second container requests every site several times a second for the
# whole run, so any moment of downtime fails the test. Needs Docker.
#
# It needs an image of an installed CE, which takes about 45 minutes to make and is only made once:
#   CE_IMAGE=clp-ce-base (see docs/migrating-from-cloudpanel-ce.md for how to build it)
#
#   scripts/debian-e2e/run-migrate.sh              Everything
#   scripts/debian-e2e/run-migrate.sh with-php     PHP sites managed in the new panel
#   scripts/debian-e2e/run-migrate.sh without-php  PHP sites left running, unmanaged
#   scripts/debian-e2e/run-migrate.sh fresh        A plain server: PHP is opt-in (no CE image needed)
#   scripts/debian-e2e/run-migrate.sh removal      Move certificates to certbot and remove CE for good
set -euo pipefail

CE_IMAGE=${CE_IMAGE:-clp-ce-base}
case "${1:-all}" in
  all) scenarios="with-php without-php"; fresh="fresh-php fresh-no-php"; removal=1 ;;
  fresh) scenarios=""; fresh="fresh-php fresh-no-php"; removal=0 ;;
  removal) scenarios=""; fresh=""; removal=1 ;;
  *) scenarios=$1; fresh=""; removal=0 ;;
esac

cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
root=$(pwd)
[ -n "${WINDIR:-}" ] && root=$(pwd -W)

[ "$removal$scenarios" = 0 ] || docker image inspect "$CE_IMAGE" >/dev/null 2>&1 || {
  echo "No image '$CE_IMAGE' of an installed CloudPanel CE. See docs/migrating-from-cloudpanel-ce.md."
  exit 1
}

echo "==> Building the Linux binary"
docker run --rm \
  -v "$root:/src:ro" \
  -v cloudpanel-e2e-cargo:/usr/local/cargo/registry \
  -v cloudpanel-e2e-target:/target \
  -e CARGO_TARGET_DIR=/target \
  rust:1-trixie \
  bash -c 'cd /src && cargo build --release --locked --quiet && cp /target/release/cloudpanel /target/cloudpanel-e2e'

status=0
for scenario in $scenarios; do
  server=clp-migrate-$scenario
  prober=clp-prober-$scenario
  cleanup() { docker rm -f "$server" "$prober" >/dev/null 2>&1 || true; }
  cleanup
  trap cleanup EXIT

  echo
  echo "################ $scenario ################"
  docker run -d --name "$server" --hostname ce-truth --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$CE_IMAGE" >/dev/null
  for _ in $(seq 1 90); do
    s=$(docker exec "$server" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) break ;; esac
    sleep 1
  done

  docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e \
    | docker exec -i "$server" sh -c 'cat > /var/tmp/cloudpanel && chmod +x /var/tmp/cloudpanel'
  docker cp migrate-from-ce.sh "$server":/var/tmp/migrate-from-ce.sh
  docker cp install.sh "$server":/var/tmp/install.sh
  docker cp scripts/debian-e2e/migrate-e2e.sh "$server":/var/tmp/migrate-e2e.sh
  docker exec "$server" sed -i 's/\r$//' /var/tmp/migrate-from-ce.sh /var/tmp/install.sh /var/tmp/migrate-e2e.sh

  docker exec "$server" bash /var/tmp/migrate-e2e.sh setup || { status=1; continue; }

  ip=$(docker exec "$server" hostname -i | cut -d' ' -f1)
  docker run -d --name "$prober" cloudpanel-debian-e2e sleep infinity >/dev/null
  docker cp scripts/debian-e2e/migrate-prober.sh "$prober":/var/tmp/migrate-prober.sh
  docker exec "$prober" sed -i 's/\r$//' /var/tmp/migrate-prober.sh
  docker exec -d "$prober" bash /var/tmp/migrate-prober.sh "$ip" \
    php.test.local=php-ok.*db=ok static.test.local=static-ok node.test.local=node-ok \
    py.test.local=py-ok proxy.test.local=proxy-ok
  sleep 3

  docker exec "$server" bash /var/tmp/migrate-e2e.sh "$scenario" || status=1

  docker exec "$prober" touch /var/tmp/probe-stop
  for _ in $(seq 1 30); do
    docker exec "$prober" test -f /var/tmp/probe-done && break
    sleep 1
  done
  total=$(docker exec "$prober" cat /var/tmp/probe-count)
  failed=$(docker exec "$prober" sh -c 'wc -l < /var/tmp/probe-failures')
  echo
  echo "== downtime, seen from another machine"
  if [ "$failed" = 0 ] && [ "$total" -gt 50 ]; then
    echo "  ok   $total requests to the sites during the migration, none failed"
  else
    echo "  FAIL $failed of $total requests failed:"
    docker exec "$prober" head -20 /var/tmp/probe-failures | sed 's/^/       /'
    status=1
  fi

  # The test apps were transient, so only sites that don't need them are checked after this.
  echo "==> Rebooting the server"
  docker restart "$server" >/dev/null
  for _ in $(seq 1 90); do
    s=$(docker exec "$server" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) break ;; esac
    sleep 1
  done
  docker exec "$server" bash /var/tmp/migrate-e2e.sh after-reboot || status=1
  cleanup
done

# A real ACME server, so certificates are really issued and renewed. Pebble is Let's Encrypt's own
# test server, and challtestsrv answers its DNS questions with the test server's address.
if [ "$removal" = 1 ]; then
  server=clp-removal
  prober=clp-prober-removal
  net=clp-removal-net
  cleanup() {
    docker rm -f "$server" "$prober" clp-pebble clp-pebble-dns >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
  }
  cleanup
  trap cleanup EXIT
  echo
  echo "################ removal ################"
  docker network create "$net" >/dev/null
  docker run -d --name "$server" --network "$net" --hostname ce-truth --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp "$CE_IMAGE" >/dev/null
  for _ in $(seq 1 90); do
    s=$(docker exec "$server" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) break ;; esac
    sleep 1
  done
  ip=$(docker exec "$server" hostname -i | cut -d' ' -f1)

  docker run -d --name clp-pebble-dns --network "$net" ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -defaultIPv4 "$ip" -defaultIPv6 "" -dnsserver :8053 -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
  dns_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" clp-pebble-dns)
  docker create --name clp-pebble --network "$net" -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    ghcr.io/letsencrypt/pebble:latest -config /test/config/migrate.json -dnsserver "$dns_ip:8053" >/dev/null
  docker cp scripts/debian-e2e/pebble-config.json clp-pebble:/test/config/migrate.json
  docker start clp-pebble >/dev/null

  docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e \
    | docker exec -i "$server" sh -c 'cat > /var/tmp/cloudpanel && chmod +x /var/tmp/cloudpanel'
  docker cp migrate-from-ce.sh "$server":/var/tmp/migrate-from-ce.sh
  docker cp install.sh "$server":/var/tmp/install.sh
  docker cp scripts/debian-e2e/migrate-e2e.sh "$server":/var/tmp/migrate-e2e.sh
  docker exec "$server" sed -i 's/\r$//' /var/tmp/migrate-from-ce.sh /var/tmp/install.sh /var/tmp/migrate-e2e.sh

  if docker exec "$server" bash /var/tmp/migrate-e2e.sh setup-removal; then
    docker run -d --name "$prober" --network "$net" cloudpanel-debian-e2e sleep infinity >/dev/null
    docker cp scripts/debian-e2e/migrate-prober.sh "$prober":/var/tmp/migrate-prober.sh
    docker exec "$prober" sed -i 's/\r$//' /var/tmp/migrate-prober.sh
    docker exec -d "$prober" bash /var/tmp/migrate-prober.sh "$ip" \
      static.test.local=static-ok node.test.local=node-ok py.test.local=py-ok proxy.test.local=proxy-ok
    sleep 3

    docker exec -e CLOUDPANEL_ACME_SERVER=https://clp-pebble:14000/dir "$server" \
      bash /var/tmp/migrate-e2e.sh removal || status=1

    docker exec "$prober" touch /var/tmp/probe-stop
    for _ in $(seq 1 30); do
      docker exec "$prober" test -f /var/tmp/probe-done && break
      sleep 1
    done
    total=$(docker exec "$prober" cat /var/tmp/probe-count)
    failed=$(docker exec "$prober" sh -c 'wc -l < /var/tmp/probe-failures')
    echo
    echo "== downtime, seen from another machine"
    if [ "$failed" = 0 ] && [ "$total" -gt 50 ]; then
      echo "  ok   $total requests to the sites through certificates moving and CE being removed, none failed"
    else
      echo "  FAIL $failed of $total requests failed:"
      docker exec "$prober" head -20 /var/tmp/probe-failures | sed 's/^/       /'
      status=1
    fi

    echo "==> Rebooting the server"
    docker restart "$server" >/dev/null
    for _ in $(seq 1 90); do
      s=$(docker exec "$server" systemctl is-system-running 2>/dev/null || true)
      case "$s" in running | degraded) break ;; esac
      sleep 1
    done
    docker exec "$server" bash /var/tmp/migrate-e2e.sh after-removal-reboot || status=1
  else
    status=1
  fi
  cleanup
fi

# A plain server that never had CE: PHP has to be opt-in.
for scenario in $fresh; do
  server=clp-fresh-$scenario
  cleanup() { docker rm -f "$server" >/dev/null 2>&1 || true; }
  cleanup
  trap cleanup EXIT
  echo
  echo "################ $scenario ################"
  docker build -q -t cloudpanel-debian-e2e scripts/debian-e2e >/dev/null
  docker run -d --name "$server" --hostname fresh --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --tmpfs /tmp cloudpanel-debian-e2e >/dev/null
  for _ in $(seq 1 90); do
    s=$(docker exec "$server" systemctl is-system-running 2>/dev/null || true)
    case "$s" in running | degraded) break ;; esac
    sleep 1
  done
  docker run --rm -v cloudpanel-e2e-target:/target:ro debian:13 cat /target/cloudpanel-e2e \
    | docker exec -i "$server" sh -c 'cat > /var/tmp/cloudpanel && chmod +x /var/tmp/cloudpanel'
  docker cp install.sh "$server":/var/tmp/install.sh
  docker cp scripts/debian-e2e/migrate-e2e.sh "$server":/var/tmp/migrate-e2e.sh
  docker exec "$server" sed -i 's/\r$//' /var/tmp/install.sh /var/tmp/migrate-e2e.sh
  php_flag=""
  [ "$scenario" = fresh-php ] && php_flag=--with-php
  # No flag and no terminal, as with `curl | sudo bash` in a script: PHP must stay off.
  docker exec "$server" sh -c "bash /var/tmp/install.sh --binary /var/tmp/cloudpanel --no-firewall --swap-size 0 --no-nodejs --databases sqlite $php_flag </dev/null >/var/tmp/install.log 2>&1" || {
    docker exec "$server" tail -30 /var/tmp/install.log
    status=1
    continue
  }
  docker exec "$server" sh -c 'command -v sqlite3 >/dev/null || apt-get install -y -q sqlite3 >/dev/null 2>&1'
  docker exec "$server" bash /var/tmp/migrate-e2e.sh "$scenario" || status=1
  cleanup
done

echo
if [ "$status" = 0 ]; then echo "All migration checks passed."; else echo "Migration checks FAILED."; fi
exit "$status"
