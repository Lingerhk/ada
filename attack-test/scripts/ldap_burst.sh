#!/usr/bin/env bash
set -euo pipefail

HOST=${LDAP_HOST:-"192.168.1.10"}
PORT=${LDAP_PORT:-"389"}
BIND_DN=${LDAP_BIND_DN:-"SEVENKINGDOMS\\Vagrant"}
PASS=${LDAP_PASS:-"vagrant"}
BASE_DN=${LDAP_BASE_DN:-"DC=sevenkingdoms,DC=local"}
FILTER=${LDAP_FILTER:-"(sAMAccountName=vagrant)"}
COUNT=${COUNT:-30}

# Default output under attack-test/artifacts/logs
OUT_DIR=${OUT_DIR:-"./artifacts/logs"}
mkdir -p "$OUT_DIR"
LOG_FILE="$OUT_DIR/ldap_burst_$(date -u +%Y%m%dT%H%M%SZ).log"

echo "Starting LDAP burst: host=$HOST port=$PORT count=$COUNT" | tee -a "$LOG_FILE"

auth="${BIND_DN}%${PASS}"
for i in $(seq 1 "$COUNT"); do
  sleep_s=$(( (RANDOM % 5) + 1 ))
  echo "[$(date -u +%FT%TZ)] run $i/$COUNT (sleep next=${sleep_s}s)" | tee -a "$LOG_FILE"

  # -LLL for clean output; -o nettimeout keeps it from hanging forever
  ldapsearch -LLL \
    -H "ldap://${HOST}:${PORT}" \
    -x \
    -D "${BIND_DN}" \
    -w "${PASS}" \
    -b "${BASE_DN}" \
    -o nettimeout=5 \
    "${FILTER}" dn >> "$LOG_FILE" 2>&1 || true

  sleep "$sleep_s"
done

echo "Done. Log: $LOG_FILE" | tee -a "$LOG_FILE"
