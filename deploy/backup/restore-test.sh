#!/usr/bin/env bash
# Restore test (docs/architettura.md §15.2), run inside a throwaway container.
#
#   restore-test.sh [latest|<file>.dump.age]  < age-identity-file
#
# The age identity (private key) is read from stdin and never written to disk.
# The dump is restored into a temporary PostgreSQL server on tmpfs, never into
# the live database, then compared with the live database (LIVE_PG* variables).
set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/backups}"
TARGET="${1:-latest}"
WORK=/tmp/restore-test
started="$(date +%s)"

fail() { echo "RESULT: FAILED - $1"; exit 1; }

if [[ "$TARGET" == "latest" ]]; then
  TARGET="$(find "$BACKUP_DIR" -maxdepth 1 -name 'specula-*.dump.age' -printf '%f\n' | sort | tail -n 1)"
  [[ -n "$TARGET" ]] || fail "no backup found in ${BACKUP_DIR}"
fi
echo "dump: ${TARGET}"

# 1. Checksum.
(cd "$BACKUP_DIR" && sha256sum --check --quiet "${TARGET}.sha256") || fail "checksum mismatch"
echo "checksum: ok"

# 2. Temporary PostgreSQL server on tmpfs, reachable only through a local socket.
mkdir -p "$WORK"
chown postgres:postgres "$WORK"
gosu postgres initdb --auth=trust --username=postgres -D "$WORK/data" > /dev/null
gosu postgres pg_ctl -D "$WORK/data" -o "-c listen_addresses='' -k $WORK" -w start > /dev/null
trap 'gosu postgres pg_ctl -D "$WORK/data" -m immediate stop > /dev/null 2>&1 || true' EXIT
local_psql() { psql -h "$WORK" -U postgres -X -tA "$@"; }
createdb -h "$WORK" -U postgres restore

# 3. Decrypt (identity from stdin) and restore.
age --decrypt --identity /dev/stdin "${BACKUP_DIR}/${TARGET}" \
  | pg_restore -h "$WORK" -U postgres -d restore --no-owner --no-privileges --exit-on-error \
  || fail "decrypt or restore error"
echo "restore: ok"

# 4. Compare with the live database.
live_psql() {
  PGPASSWORD="$LIVE_PGPASSWORD" psql -h "$LIVE_PGHOST" -U "$LIVE_PGUSER" -d "$LIVE_PGDATABASE" -X -tA "$@"
}
live_rev="$(live_psql -c 'select version_num from alembic_version')"
restored_rev="$(local_psql -d restore -c 'select version_num from alembic_version')"
echo "alembic: live=${live_rev} restored=${restored_rev}"
[[ "$live_rev" == "$restored_rev" ]] || fail "alembic version differs"

tables="$(live_psql -c "select tablename from pg_tables where schemaname = 'public' order by 1")"
differences=0
printf '%-32s %12s %12s\n' "table" "live" "restored"
for table in $tables; do
  live_count="$(live_psql -c "select count(*) from public.\"${table}\"")"
  restored_count="$(local_psql -d restore -c "select count(*) from public.\"${table}\"" 2>/dev/null || echo missing)"
  printf '%-32s %12s %12s\n' "$table" "$live_count" "$restored_count"
  [[ "$restored_count" == "missing" ]] && fail "table ${table} missing in the restored dump"
  [[ "$live_count" == "$restored_count" ]] || differences=$((differences + 1))
done

duration="$(( $(date +%s) - started ))"
if (( differences > 0 )); then
  # Rows written after the dump are expected: report, do not fail.
  echo "RESULT: OK with ${differences} table(s) changed since the dump (${duration}s)"
else
  echo "RESULT: OK (${duration}s)"
fi
