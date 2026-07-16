from __future__ import annotations

import json
import logging

from envwitness.infrastructure.logging import JsonLogFormatter, configure_logging


def test_json_log_formatter_keeps_scalar_context() -> None:
    record = logging.LogRecord(
        name="envwitness.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="captured",
        args=(),
        exc_info=None,
    )
    record.fact_count = 12
    record.unbounded = {"secret": "not serialized"}
    payload = json.loads(JsonLogFormatter().format(record))
    assert payload["message"] == "captured"
    assert payload["fact_count"] == 12
    assert "unbounded" not in payload


def test_configure_logging_replaces_handlers() -> None:
    configure_logging(verbose=True, json_output=True)
    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) == 1
    assert isinstance(root_logger.handlers[0].formatter, JsonLogFormatter)
