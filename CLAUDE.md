# CLAUDE.md – Specula

Repository `specula-platform`. **Specula** is the platform; the current module (MVP) is **Specula Threat**, a Threat Intelligence module. Future modules: Exposure, Third Party, OSINT, CLOSINT – do not build them without an approved spec.

Specula Threat: Python/FastAPI backend (API-first), plugin collectors, PostgreSQL, React frontend, Docker Compose deploy (compose project `specula`) on a Linux VM.

Source of truth for scope and design:
- [docs/specifica-funzionale-dashboard.md](docs/specifica-funzionale-dashboard.md) – what the product does
- [docs/architettura.md](docs/architettura.md) – how it is built

## Workflow rules

- **Spec first.** No feature code without an approved spec. If a task requires behaviour not in the docs, update the docs and get approval before implementing.
- Docs are approved by the owner (Sandro Sana). Docs marked `BOZZA` are not approved yet: do not implement from them. Spec and architecture are `APPROVATO – v1.1`; changes to them need a new approval.
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

- Python 3.12, type hints everywhere, `ruff` (lint + format) and `mypy` must pass. Collectors are checked with `mypy --strict`.
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

- Target runtime: Ubuntu 24.04 VM in the Eurosystem LAB with Docker (no GPU).
- The owner's Windows workstation has no Docker, Node or reliable Python. Code written there cannot be run locally: say so explicitly instead of claiming it works. Build and test on the LAB VM or in CI.
- Legacy bash OSINT scripts (`scripts/`, `templates/`, `install.sh`) will be deleted after tagging `legacy-final` (`docs/architettura.md` §12). Do not extend them.
