# Specula Threat – backend

API-first FastAPI backend of Specula Threat. Design: [docs/architettura.md](../docs/architettura.md).

## Development

Requires [uv](https://docs.astral.sh/uv/). uv installs Python 3.12 automatically (see `.python-version`).

```bash
cd backend
uv sync                      # install dependencies (dev group included)
uv run ruff check .          # lint
uv run ruff format --check . # formatting
uv run mypy                  # type checking (strict)
uv run pytest                # tests (network access is blocked)
```

Run the API locally (needs `DATABASE_URL`):

```bash
uv run uvicorn app.main:create_app --factory --reload
```

Then open `http://127.0.0.1:8000/api/v1/health` (liveness), `/api/v1/health/ready` (database reachable) or the OpenAPI docs at `/api/v1/docs`.

## Collectors

```bash
uv run python -m app.collectors list                     # collectors and effective configuration
uv run python -m app.collectors run <name> [--full] [--no-cache]
uv run python -m app.scheduler                           # run all schedules
```

A collector is a `PeriodicCollector` subclass in `app/collectors/`, decorated with `@register`; its entities need a writer registered with `@register_writer` (see `docs/architettura.md` §5).

## Database

Schema changes go only through Alembic migrations in `migrations/versions/`:

```bash
uv run alembic upgrade head          # apply all migrations (uses DATABASE_URL)
uv run alembic downgrade base        # revert everything
uv run alembic revision -m "..."     # new empty revision
```

Tests in `tests/db/` run against a real, disposable PostgreSQL given by `TEST_DATABASE_URL` (they drop and recreate the schema). Without it they are skipped locally; in CI they are mandatory:

```bash
TEST_DATABASE_URL=postgresql+asyncpg://specula:specula@127.0.0.1:5432/specula_test uv run pytest
```

Configuration comes only from environment variables, listed in [`.env.example`](../.env.example).
