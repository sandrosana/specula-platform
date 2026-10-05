import json
import logging

from app.core.logging import JsonFormatter, configure_logging


def _record(message: str, level: int = logging.INFO) -> logging.LogRecord:
    return logging.LogRecord(
        name="specula.test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=None,
        exc_info=None,
    )


def test_formatter_emits_one_json_object() -> None:
    line = JsonFormatter().format(_record("collector run finished"))

    payload = json.loads(line)
    assert payload["level"] == "INFO"
    assert payload["logger"] == "specula.test"
    assert payload["message"] == "collector run finished"
    assert payload["timestamp"].endswith("+00:00")


def test_formatter_keeps_non_ascii_text() -> None:
    payload = json.loads(JsonFormatter().format(_record("vulnerabilità")))

    assert payload["message"] == "vulnerabilità"


def test_configure_logging_sets_level_and_json_handler() -> None:
    root = logging.getLogger()
    saved_handlers, saved_level = root.handlers[:], root.level
    try:
        configure_logging("WARNING")

        assert root.level == logging.WARNING
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JsonFormatter)
    finally:
        root.handlers = saved_handlers
        root.setLevel(saved_level)
