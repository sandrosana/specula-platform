# Specula Threat – deployment

Docker Compose deployment on the LAB host (see `docs/architettura.md` §2, §3 and §11).

| Service | Role | Networks |
|---------|------|----------|
| `proxy` | Caddy: HTTPS with a self-signed local CA, access limited to `SPECULA_ALLOWED_NETWORKS` | `public` (ports 80/443), `web` |
| `api` | FastAPI (`/api/v1`) | `web`, `data` |
| `scheduler` | Collectors (empty until M2) | `data` |
| `migrate` | One-shot `alembic upgrade head` before `api` and `scheduler` start | `data` |
| `db` | PostgreSQL 16, data in the `db-data` volume | `data` |

`web` and `data` are internal networks: the database and the backend have no internet access and are reachable only through the proxy.

## First start

```bash
git clone https://github.com/sandrosana/specula-platform.git
cd specula-platform
cp .env.example .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 32)/" .env
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

## Trusting the certificate

Caddy issues the certificate from its own local CA. To avoid the browser warning, install the CA root certificate on the analysts' machines:

```bash
docker compose --env-file .env -f deploy/docker-compose.yml cp proxy:/data/caddy/pki/authorities/local/root.crt ./specula-root.crt
```

Then import `specula-root.crt` as a trusted root certification authority (on Windows: double-click → Install certificate → Local machine → "Trusted Root Certification Authorities"). The root is valid for 10 years; the server certificate is renewed automatically.

## Logs

```bash
docker compose --env-file .env -f deploy/docker-compose.yml logs -f api scheduler
```
