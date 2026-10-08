"""Checks on the migration scripts that need no database."""

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from app.core.classification import DEFAULT_CLASSIFICATION, Classification
from app.models import ClassifiedMixin

BACKEND_DIR = Path(__file__).resolve().parents[1]


def _scripts() -> ScriptDirectory:
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "migrations"))
    return ScriptDirectory.from_config(config)


def test_single_head() -> None:
    assert _scripts().get_heads() == ["0002"]


def test_baseline_enum_matches_classification() -> None:
    baseline = (BACKEND_DIR / "migrations" / "versions" / "0001_baseline.py").read_text("utf-8")

    values = ", ".join(f"'{member.value}'" for member in Classification)
    assert f"CREATE TYPE classification AS ENUM ({values})" in baseline


def test_default_classification_is_sensitive() -> None:
    assert DEFAULT_CLASSIFICATION is Classification.SENSITIVE

    column = ClassifiedMixin.__dict__["classification"].column
    assert column.nullable is False
    assert column.server_default.arg == "sensitive"
