# Specula Threat – deployment

Docker Compose deployment on the LAB host (see `docs/architettura.md` §2, §3 and §11).

| Service | Role | Networks |
|---------|------|----------|
| `proxy` | Caddy: HTTPS with a self-signed local CA, access limited to `SPECULA_ALLOWED_NETWORKS` | `public` (ports 80/443), `web` |
| `api` | FastAPI (`/api/v1`) | `web`, `data` |
| `scheduler` | Collectors (empty until M2) | `data` |
| `migrate` | One-shot `alembic upgrade head` before `api` and `scheduler` start | `data` |
| `db` | PostgreSQL 16, data in the `db-data` volume | `data` |
| `backup` | Daily encrypted `pg_dump` to `/mnt/specula-backup` (see [docs/runbook-backup.md](../docs/runbook-backup.md)) | `data` |

`web` and `data` are internal networks: the database and the backend have no internet access and are reachable only through the proxy.

## First start

```bash
git clone https://github.com/sandrosana/specula-platform.git
cd specula-platform
cp .env.example .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
sed -i "s/^SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
chmod 600 .env
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
docker compose --env-file .env -f deploy/docker-compose.yml ps
```

Check from a machine in the allowed network:

```bash
curl -k https://10.128.4.106/api/v1/health
curl -k https://10.128.4.106/api/v1/health/ready
```

## Update

```bash
git pull
docker compose --env-file .env -f deploy/docker-compose.yml up -d --build
```

Migrations run automatically through the `migrate` service.

## Users

Every API call except `/api/v1/health` needs a login (docs/architettura.md §10.4). Create the first Admin inside the `api` container; the password (at least 14 characters) is asked twice without echo:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec api python -m app.users create-admin --email name@example.com
```

At the first login an Admin enrols the second factor (TOTP): `POST /api/v1/auth/totp/setup` returns the secret and the `otpauth://` URI for the authenticator app, `POST /api/v1/auth/totp/activate` confirms it with a code and returns 10 one-time recovery codes, shown only once. Later logins need a code (`POST /api/v1/auth/totp`).

An Admin who lost both the phone and the recovery codes enrols again after a reset, which also closes all their sessions:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec api python -m app.users reset-totp --email name@example.com
```

`SECRET_KEY` encrypts the second-factor secrets: changing it makes them unreadable, so every Admin must be reset and enrol again.

## Trusting the certificate

Caddy issues the certificate from its own local CA. To avoid the browser warning, install the CA root certificate on the analysts' machines:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml cp proxy:/data/caddy/pki/authorities/local/root.crt ./specula-root.crt
```

Then import `specula-root.crt` as a trusted root certification authority (on Windows: double-click → Install certificate → Local machine → "Trusted Root Certification Authorities"). The root is valid for 10 years; the server certificate is renewed automatically.

## Collectors

The `scheduler` runs every enabled collector on its schedule. It is the only service with outbound internet access (`egress` network) and the only one that receives the source API keys from `.env`.

```bash
# list collectors, their configuration and why a collector is disabled
docker compose --env-file .env -f deploy/docker-compose.yml exec scheduler python -m app.collectors list
# run one collector now (--full ignores the saved cursor, --no-cache ignores the HTTP cache)
docker compose --env-file .env -f deploy/docker-compose.yml exec scheduler python -m app.collectors run <name>
```

Never start a manual run of a collector that is already running: the advisory lock skips it (`skipped_locked`), but a forced `--full` run of NVD repeats the whole load.

### CVE priority levels

Levels P1–P4 and their sort key are updated automatically after every NVD, KEV and EPSS write. Recompute every CVE once after a migration that adds priority columns, or after changing `EPSS_THRESHOLD` in `.env` (restart the `scheduler` first so it reads the new value):

```bash
docker compose --env-file .env -f deploy/docker-compose.yml exec scheduler python -m app.processing priorities
```

### Reference figures (LAB host, October 2026)

| Operation | Records | Duration | Database after |
|-----------|---------|----------|----------------|
| NVD full load (`nvd`, first run, with API key) | 403,403 CVEs, 1,435,018 affected products, 202 requests | 1 h 15 min | 1.9 GB |
| EPSS first run (`epss`) | 384,534 scores | 3 min | 2.6 GB |
| Priority recompute, all CVEs | 384,930 rows | about 1 min | 2.8 GB |

`GET /api/v1/cves` (priority order, 10 items, warm cache): about 240 ms, mostly the `total` count; filtered by level about 50 ms; `GET /api/v1/cves/{cve_id}` about 20 ms.

## Backups

Set `BACKUP_AGE_RECIPIENT` in `.env` and create the marker file on the backup disk once (as root): `touch /mnt/specula-backup/.specula-backup-disk`. Procedures for manual backups and restore tests: [docs/runbook-backup.md](../docs/runbook-backup.md).

## Logs

```bash
docker compose --env-file .env -f deploy/docker-compose.yml logs -f api scheduler
```
