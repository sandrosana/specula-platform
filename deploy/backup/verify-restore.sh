#!/usr/bin/env bash
# Run the restore test against the live stack (docs/runbook-backup.md).
#
#   deploy/backup/verify-restore.sh [latest|<file>.dump.age] < age-identity-file
#
# Run from the repository root on the LAB host. The identity is streamed into a
# throwaway container and never written to disk.
set -euo pipefail

cd "$(dirname "$0")/../.."
[[ -f .env ]] || { echo "missing .env in $(pwd)" >&2; exit 1; }
if [[ -t 0 ]]; then
  echo "provide the age identity on stdin: verify-restore.sh [file] < key-file" >&2
  exit 2
fi

env_value() { grep -E "^$1=" .env | tail -n 1 | cut -d= -f2-; }
live_user="$(env_value POSTGRES_USER)"
live_db="$(env_value POSTGRES_DB)"
backup_dir="$(env_value BACKUP_HOST_DIR)"
# Passed through the environment, not the command line (other users can read `ps`).
LIVE_PGPASSWORD="$(env_value POSTGRES_PASSWORD)"
export LIVE_PGPASSWORD

docker run --rm -i \
  --network specula_data \
  --tmpfs /tmp:rw,size=2g \
  -v "${backup_dir:-/mnt/specula-backup}:/backups:ro" \
  -e LIVE_PGHOST=db \
  -e LIVE_PGUSER="${live_user:-specula}" \
  -e LIVE_PGDATABASE="${live_db:-specula}" \
  -e LIVE_PGPASSWORD \
  specula-backup:local restore-test.sh "${1:-latest}"
