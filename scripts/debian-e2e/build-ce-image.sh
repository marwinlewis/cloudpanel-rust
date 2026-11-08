#!/usr/bin/env bash
# Builds the image run-migrate.sh tests against: Debian 13 with real systemd, the real CloudPanel
# CE installed by its own installer, and one site of each type. It takes about 45 minutes, mostly
# downloading, and only needs doing once, or to test against a newer CE. Needs Docker.
#
#   scripts/debian-e2e/build-ce-image.sh [image name, default clp-ce-base]
set -euo pipefail

image=${1:-clp-ce-base}
name=clp-ce-build
# Published on https://www.cloudpanel.io/docs/v2/getting-started/other/. When CE releases a new
# installer this stops here, rather than run something unverified. Check it there and update it.
installer_sha256=8146dbe0a488e7088b04071b0c34d59aa0ab1fe9dcec382d395fd155c9e6c476

cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1

docker build -q -t cloudpanel-debian-e2e scripts/debian-e2e >/dev/null
docker rm -f "$name" >/dev/null 2>&1 || true
trap 'docker rm -f "$name" >/dev/null 2>&1 || true' EXIT
docker run -d --name "$name" --hostname ce-truth --privileged --cgroupns=private \
  --tmpfs /run --tmpfs /run/lock --tmpfs /tmp cloudpanel-debian-e2e >/dev/null
for _ in $(seq 1 90); do
  s=$(docker exec "$name" systemctl is-system-running 2>/dev/null || true)
  case "$s" in running | degraded) break ;; esac
  sleep 1
done

docker cp scripts/debian-e2e/ce-seed.sh "$name":/var/tmp/ce-seed.sh
docker exec "$name" sed -i 's/\r$//' /var/tmp/ce-seed.sh

# Run detached and followed through a log, as a dropped connection to Docker shouldn't kill it.
docker exec -i "$name" sh -c 'cat > /var/tmp/ce-install.sh' <<EOF
#!/bin/bash
exec > /var/tmp/ce-install.log 2>&1
# What a real VPS already has, and this minimal image doesn't. CE's post-install script needs SSH's
# PAM file, percona-release needs lsb_release, and Docker's policy file stops services from starting.
rm -f /usr/sbin/policy-rc.d
touch /etc/sysctl.conf
apt-get update -q
DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl wget sudo lsb-release openssh-server
mkdir -p /var/tmp/ce && cd /var/tmp/ce || exit 1
curl -sS https://installer.cloudpanel.io/ce/v2/install.sh -o install.sh
if ! echo "$installer_sha256 install.sh" | sha256sum -c; then
  echo checksum-failed > /var/tmp/ce-install.done
  exit 1
fi
DB_ENGINE=MYSQL_8.4 SWAP=false bash install.sh
rc=\$?
if [ "\$rc" = 0 ]; then
  bash /var/tmp/ce-seed.sh || rc=seed-failed
fi
clpctl user:add --userName=ceadmin --email=ceadmin@test.local --firstName=CE --lastName=Admin \
  --password='Test-Only-Pass-1234' --role=admin --timezone=UTC --status=1 </dev/null
echo "\$rc" > /var/tmp/ce-install.done
EOF
docker exec "$name" sed -i 's/\r$//' /var/tmp/ce-install.sh
docker exec -d "$name" bash /var/tmp/ce-install.sh

echo "==> Installing CloudPanel CE. Follow along with: docker exec $name tail -f /var/tmp/ce-install.log"
while ! docker exec "$name" test -f /var/tmp/ce-install.done; do
  sleep 20
done

result=$(docker exec "$name" cat /var/tmp/ce-install.done)
if [ "$result" != 0 ]; then
  docker exec "$name" tail -30 /var/tmp/ce-install.log
  echo "The install failed: $result"
  exit 1
fi

docker exec "$name" sh -c 'grep -v Deprecated /var/tmp/ce-install.log | tail -12 | cut -c1-120'
docker commit -m "CloudPanel CE with seeded sites" "$name" "$image" >/dev/null
echo "==> Saved as image $image"
