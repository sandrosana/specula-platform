# CLAUDE.md – Specula

Repository `specula-platform`. **Specula** is the platform; the current module (MVP) is **Specula Threat**, a Threat Intelligence module. Future modules: Exposure, Third Party, OSINT, CLOSINT – do not build them without an approved spec.

Specula Threat: Python/FastAPI backend (API-first), plugin collectors, PostgreSQL, React frontend, Docker Compose deploy (compose project `specula`) on a Linux VM.

Source of truth for scope and design:
- [docs/specifica-funzionale-dashboard.md](docs/specifica-funzionale-dashboard.md) – what the product does
- [docs/architettura.md](docs/architettura.md) – how it is built

## Workflow rules

- **Spec first.** No feature code without an approved spec. If a task requires behaviour not in the docs, update the docs and get approval before implementing.
- Docs are approved by the owner (Sandro Sana). Docs marked `BOZZA` are not approved yet: do not implement from them. Spec is `APPROVATO – v1.2`, architecture is `APPROVATO – v1.3`; changes to them need a new approval.
- `main` is protected by a GitHub ruleset: changes only through PRs, and the CI checks (`backend-lint`, `backend-types`, `backend-test`, `images`) must pass before merging.
- Implement milestone by milestone following [docs/piano-implementazione.md](docs/piano-implementazione.md), only once the plan is approved. Do not start a milestone before the previous one meets its completion criterion.
- Work on feature branches, never commit directly to `main`. Commit only when asked.
- Every PR must pass CI (ruff, mypy, pytest; see `docs/architettura.md` §14). Never merge with red checks, never skip or disable checks to get green.
- Keep changes small and focused; one collector or one feature per PR.
- Open decisions live in `docs/architettura.md` §11. Do not settle them silently in code.

## Language

- Code, identifiers, comments, commit messages, API fields: **English**.
- Docs in `docs/` and UI strings: **Italian** (UI strings via i18n files, never hardcoded in components).
- Product names: "Specula" (platform), "Specula Threat" (this module). Do not invent other names or abbreviations.

## UI and brand

- Colors, fonts and severity styles come only from the design tokens in [docs/identita-visiva.md](docs/identita-visiva.md). No hardcoded colors outside the token definitions.
- Never use color alone: severity always has its text label; every text/background pair must meet WCAG AA.

## Backend conventions

- Python 3.12, type hints everywhere, `ruff` (lint + format) and `mypy` must pass. The whole backend (including tests) is checked with `mypy --strict`, which covers the stricter requirement for collectors.
- Commands (run from `backend/`, require `uv`): `uv sync`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`, `uv run pytest`. API: `uv run uvicorn app.main:create_app --factory`.
- `backend/uv.lock` is committed and CI/Docker install with `--locked`. After changing dependencies in `pyproject.toml`, regenerate it (the workstation has no uv: run `uv lock` in the `ghcr.io/astral-sh/uv:python3.12-bookworm-slim` container on the LAB host) and commit it in the same PR.
- Tests run with network sockets disabled (`pytest-socket`). Never enable real network access in tests. The only exception is `tests/db/`, which may connect to `127.0.0.1` (the disposable database given by `TEST_DATABASE_URL`) through `DB_TEST_MARKS`.
- New tables: models use `ClassifiedMixin` for the `classification` column; never add a Python-side default for it (the database default is `sensitive`).
- Async throughout: SQLAlchemy 2.0 async, httpx async.
- Configuration only through `app.core.config` (pydantic-settings). Never read `os.environ` elsewhere.
- Schema changes only through Alembic migrations. Never edit an applied migration.
- API: versioned under `/api/v1`, Pydantic schemas for every request/response, errors as `application/problem+json`, every write endpoint has an explicit role dependency.
- The API never calls external sources. Only collectors (run by the scheduler) do.

## Collector rules

- Every source is a `Collector` subclass in `backend/app/collectors/` implementing the interface in `docs/architettura.md` §5.
- All outbound HTTP goes through the shared client (`collectors/http.py`): it applies cache TTL, rate limits and retries. Never instantiate `httpx` directly in a collector.
- `normalize()` is pure: no I/O, no DB, no clock reads.
- Writes are idempotent upserts on natural keys. Re-running a collector must not create duplicates.
- A missing required API key disables the collector; it must never crash the app.
- Every collector declares `kind` (periodic | listener), `classification` and `license` (`SourceLicense`). Changing `commercial_use` requires updating `docs/architettura.md` §6.2 in the same PR.
- Ransomware victims and IOCs are entities with per-source sightings: a new source adds sightings, never duplicate entities.
- Respect each source's terms of use and documented rate limits. Verify endpoints against the official docs when implementing; do not rely on memory.
- Never download malware samples (metadata and hashes only). For ransomware data store only public metadata; never store leaked content or link to leak sites.

## Secrets

- Secrets only in `.env` (git-ignored). Every new variable is added to `.env.example` with an empty or dummy value and a comment.
- Never commit, log, print or return API keys. `GET /sources` exposes only `configured: true/false`.
- Only the `scheduler` container receives source API keys.

## Testing

- `pytest` for the backend. Collector tests use recorded, trimmed fixtures in `backend/tests/fixtures/<source>/` with `respx`; tests never hit real sources.
- Each collector needs tests for: normalization of fixture records, idempotent re-run, missing-key behaviour, incremental cursor.
- Each API endpoint needs a test for the happy path and for RBAC (forbidden role).

## Data classification

- Every entity, sighting and event row carries `classification` (`public` | `internal` | `sensitive`), assigned by the collector at collection time.
- Missing or invalid classification means `sensitive`: DB default, visibility filters and any future AI routing must all follow this.
- Visibility is enforced in the backend repository layer, never only in the UI. Aggregates must not leak counts of data the user cannot see.
- AI enrichment is out of MVP. When implemented: remote providers only for `public` data, everything else on the local CPU provider; every remote call is written to the audit log (see `docs/architettura.md` §13.4).

## Environment notes

- Target runtime: physical machine `cybertower` (Debian 13, 10.128.4.106, 4 CPU, 7.6 GB RAM) in the Eurosystem LAB, shared with other users; Docker Engine + Compose plugin; no GPU, no outbound proxy. HTTPS via Caddy `tls internal` (self-signed local CA). Backups go to `/mnt/specula-backup` (bind mount of a root-only folder on the separate data disk); the backup job refuses to write unless the marker file `.specula-backup-disk` is present. Dumps are always encrypted with age; the private key is never stored on the host and never printed (procedures: `docs/runbook-backup.md`).
- Access: SSH as `sandro` with the dedicated key `~/.ssh/specula_lab` (member of `docker`, no passwordless sudo). Read-only commands are fine; ask before anything that changes the machine. Anything needing root is done by the owner.
- The owner's Windows workstation has no Docker, Node or reliable Python. Code written there cannot be run locally: say so explicitly instead of claiming it works. Build and test on the LAB VM or in CI.
- Legacy bash OSINT scripts (`scripts/`, `templates/`, `install.sh`) will be deleted after tagging `legacy-final` (`docs/architettura.md` §12). Do not extend them.
