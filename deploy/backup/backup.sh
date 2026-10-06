#!/usr/bin/env bash
# Encrypted daily PostgreSQL backups (docs/architettura.md §15.1).
#
#   backup.sh schedule   wait for BACKUP_TIME every day and run a backup (default)
#   backup.sh now        run one backup immediately
#
# Environment:
#   PGHOST PGUSER PGPASSWORD PGDATABASE   database to dump
#   BACKUP_AGE_RECIPIENT                  age public key (age1...); dumps are never stored in clear
#   BACKUP_DIR (/backups)                 must contain the marker file below
#   BACKUP_TIME (02:30)                   local time of the daily run (TZ)
#   BACKUP_KEEP_DAILY (7) BACKUP_KEEP_WEEKLY (4)
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_TIME="${BACKUP_TIME:-02:30}"
BACKUP_KEEP_DAILY="${BACKUP_KEEP_DAILY:-7}"
BACKUP_KEEP_WEEKLY="${BACKUP_KEEP_WEEKLY:-4}"
# Created once by the owner on the data disk. If the disk is not mounted, the
# host path is an empty directory on the system disk and has no marker.
MARKER=".specula-backup-disk"
STATUS_FILE="${BACKUP_DIR}/last-backup.json"

log() {
  printf '{"timestamp": "%s", "level": "%s", "logger": "backup", "message": "%s"}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" "$1" "$2"
}

write_status() {
  # $1 outcome, $2 file, $3 bytes, $4 seconds
  local tmp="${STATUS_FILE}.tmp"
  printf '{"outcome": "%s", "finished_at": "%s", "file": "%s", "bytes": %s, "duration_seconds": %s}\n' \
    "$1" "$(date -u +%Y-%m-%dT%H:%M:%S+00:00)" "$2" "$3" "$4" > "$tmp"
  mv "$tmp" "$STATUS_FILE"
}

preflight() {
  if [[ ! -f "${BACKUP_DIR}/${MARKER}" ]]; then
    log ERROR "${BACKUP_DIR}/${MARKER} not found: the backup disk is not mounted, refusing to write"
    return 1
  fi
  if [[ ! "${BACKUP_AGE_RECIPIENT:-}" =~ ^age1[0-9a-z]+$ ]]; then
    log ERROR "BACKUP_AGE_RECIPIENT is missing or not an age public key, refusing to write unencrypted dumps"
    return 1
  fi
}

prune() {
  # Keep the newest BACKUP_KEEP_DAILY dumps plus the newest BACKUP_KEEP_WEEKLY Sunday dumps.
  local -a all keep
  mapfile -t all < <(find "$BACKUP_DIR" -maxdepth 1 -name 'specula-*.dump.age' -printf '%f\n' | sort -r)
  keep=("${all[@]:0:${BACKUP_KEEP_DAILY}}")
  local name day weekly=0
  for name in "${all[@]}"; do
    day="${name:8:8}"
    if [[ "$(date -d "$day" +%u)" == "7" && $weekly -lt $BACKUP_KEEP_WEEKLY ]]; then
      keep+=("$name")
      weekly=$((weekly + 1))
    fi
  done
  for name in "${all[@]}"; do
    if [[ ! " ${keep[*]} " == *" ${name} "* ]]; then
      rm -f "${BACKUP_DIR}/${name}" "${BACKUP_DIR}/${name}.sha256"
      log INFO "pruned ${name}"
    fi
  done
}

run_backup() {
  local started name tmp bytes
  started="$(date +%s)"
  if ! preflight; then
    [[ -f "${BACKUP_DIR}/${MARKER}" ]] && write_status failed "" 0 0
    return 1
  fi
  name="specula-$(date +%Y%m%d-%H%M).dump.age"
  tmp="${BACKUP_DIR}/.tmp-${name}"
  log INFO "backup started: ${name}"
  if pg_dump --format=custom --no-password | age --encrypt --recipient "$BACKUP_AGE_RECIPIENT" > "$tmp"; then
    mv "$tmp" "${BACKUP_DIR}/${name}"
    (cd "$BACKUP_DIR" && sha256sum "$name" > "${name}.sha256")
    bytes="$(stat -c %s "${BACKUP_DIR}/${name}")"
    write_status success "$name" "$bytes" "$(( $(date +%s) - started ))"
    log INFO "backup finished: ${name} (${bytes} bytes)"
    prune
  else
    rm -f "$tmp"
    write_status failed "$name" 0 "$(( $(date +%s) - started ))"
    log ERROR "backup failed: ${name}"
    return 1
  fi
}

schedule() {
  trap 'log INFO "backup scheduler stopped"; exit 0' TERM INT
  log INFO "backup scheduler started: daily at ${BACKUP_TIME} (${TZ:-UTC})"
  local now target
  while true; do
    now="$(date +%s)"
    target="$(date -d "today ${BACKUP_TIME}" +%s)"
    (( target <= now )) && target="$(date -d "tomorrow ${BACKUP_TIME}" +%s)"
    sleep "$(( target - now ))" &
    wait $!
    run_backup || true
  done
}

case "${1:-schedule}" in
  schedule) schedule ;;
  now) run_backup ;;
  *) echo "usage: backup.sh [schedule|now]" >&2; exit 2 ;;
esac
