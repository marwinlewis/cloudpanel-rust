#!/usr/bin/env bash
# Seeds a CloudPanel CE test install with one site of each type, using CE's own CLI, so that the
# migration test runs against what CE really generates. Test values only; runs in a throwaway
# container. See migrate-e2e.sh.
set -uo pipefail

PW='Test-Only-Pass-1234'
systemctl start nginx
for v in 8.4; do systemctl start "php$v-fpm" || true; done

# stdin is closed because clpctl stops to ask a question when a command fails, rather than saying so.
add() { echo "--- clpctl $1"; clpctl "$@" </dev/null 2>&1 | grep -v -E '^(PHP )?Deprecated|^$' | tail -3; }

add site:add:php --domainName=php.test.local --phpVersion=8.4 --vhostTemplate='Generic' \
  --siteUser=phpsite --siteUserPassword="$PW"
add site:add:static --domainName=static.test.local --siteUser=staticsite --siteUserPassword="$PW"
add site:add:nodejs --domainName=node.test.local --nodejsVersion=22 --appPort=3100 \
  --siteUser=nodesite --siteUserPassword="$PW"
add site:add:python --domainName=py.test.local --pythonVersion=3.13 --appPort=3200 \
  --siteUser=pysite --siteUserPassword="$PW"
add site:add:reverse-proxy --domainName=proxy.test.local --reverseProxyUrl=http://127.0.0.1:3300 \
  --siteUser=proxysite --siteUserPassword="$PW"

# Right after the sites are created, db:add can print nothing, exit 0 and do nothing, though the
# same command works moments later. So check that it happened.
ce_db=/home/clp/htdocs/app/data/db.sq3
for _ in $(seq 1 10); do
  add db:add --domainName=php.test.local --databaseName=phpdb --databaseUserName=phpdbuser \
    --databaseUserPassword="$PW"
  [ "$(sqlite3 "$ce_db" "SELECT COUNT(*) FROM \"database\" WHERE name = 'phpdb'")" = 1 ] && break
  sleep 5
done
if [ "$(sqlite3 "$ce_db" "SELECT COUNT(*) FROM \"database\" WHERE name = 'phpdb'")" != 1 ]; then
  echo "Could not create the test database"
  exit 1
fi

# Content that tells us the real stack answered: PHP has to execute, and the database has to work.
cat > /home/phpsite/htdocs/php.test.local/index.php <<EOF
<?php
\$db = new mysqli('127.0.0.1', 'phpdbuser', '$PW', 'phpdb');
echo 'php-ok ', PHP_VERSION, ' db=', \$db->connect_errno ? 'fail' : 'ok', "\n";
EOF
chown phpsite:phpsite /home/phpsite/htdocs/php.test.local/index.php
echo 'static-ok' > /home/staticsite/htdocs/static.test.local/index.html
chown staticsite:staticsite /home/staticsite/htdocs/static.test.local/index.html
