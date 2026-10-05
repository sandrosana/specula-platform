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

Run the API locally:

```bash
uv run uvicorn app.main:create_app --factory --reload
```

Then open `http://127.0.0.1:8000/api/v1/health` or the OpenAPI docs at `http://127.0.0.1:8000/api/v1/docs`.

Configuration comes only from environment variables, listed in [`.env.example`](../.env.example).
