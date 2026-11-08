#!/usr/bin/env bash
# Runs on a second machine and requests every site over and over for the whole migration, the way
# visitors would. The sites are "down" for as long as this sees anything but the expected answer.
#   migrate-prober.sh <server ip> <domain=expected text>...
# Writes one line per failed request to /var/tmp/probe-failures and counts to /var/tmp/probe-count.
ip=$1
shift
: > /var/tmp/probe-failures
total=0
while [ ! -f /var/tmp/probe-stop ]; do
  for pair in "$@"; do
    domain=${pair%%=*}
    want=${pair#*=}
    body=$(curl -sk --max-time 5 --resolve "$domain:443:$ip" "https://$domain/" 2>&1)
    rc=$?
    total=$((total + 1))
    if [ "$rc" -ne 0 ] || ! printf '%s' "$body" | grep -q "$want"; then
      printf '%s %s curl=%s body=%s\n' "$(date -u +%H:%M:%S.%N | cut -c1-12)" "$domain" "$rc" \
        "$(printf '%s' "$body" | head -c 60 | tr '\n' ' ')" >> /var/tmp/probe-failures
    fi
  done
  printf '%s\n' "$total" > /var/tmp/probe-count
done
touch /var/tmp/probe-done
