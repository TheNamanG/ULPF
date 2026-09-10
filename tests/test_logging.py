import logging
from typing import Any

from ulpf.config.settings import ULPFSettings
from ulpf.logging import _add_correlation_id, setup_logging


def test_add_correlation_id_adds_new() -> None:
    event_dict: dict[str, Any] = {}
    result = _add_correlation_id(None, "", event_dict)
    assert "correlation_id" in result
    assert isinstance(result["correlation_id"], str)
    assert len(result["correlation_id"]) > 0


def test_add_correlation_id_preserves_existing() -> None:
    event_dict: dict[str, Any] = {"correlation_id": "test-id-123"}
    result = _add_correlation_id(None, "", event_dict)
    assert result["correlation_id"] == "test-id-123"


def test_setup_logging_runs_without_error() -> None:
    settings = ULPFSettings(log_level="debug")
    setup_logging(settings)

    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG
    assert len(root_logger.handlers) > 0
