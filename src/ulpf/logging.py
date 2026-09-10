"""Structured logging setup for the ULPF pipeline.

Uses ``structlog`` with JSON formatting (§6) so that every log entry
is machine-parseable for downstream log aggregation (ELK, Splunk, etc.).

A correlation ID is attached to every log entry to trace a given raw log
from ingestion → parse/DLQ → sink. This is critical for SOC operators
debugging why a specific event was dropped, DLQ'd, or misclassified.
"""

from __future__ import annotations

import logging
import sys
import uuid
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from ulpf.config.settings import ULPFSettings


def _add_correlation_id(
    logger: structlog.types.WrappedLogger,
    method_name: str,
    event_dict: structlog.types.EventDict,
) -> structlog.types.EventDict:
    """Attach a correlation ID to every log entry if one isn't already present.

    When processing a specific log message, the pipeline sets ``correlation_id``
    in the structlog context. If no ID is set (e.g., for infrastructure logs),
    a new one is generated.
    """
    if "correlation_id" not in event_dict:
        event_dict["correlation_id"] = str(uuid.uuid4())
    return event_dict


def setup_logging(settings: ULPFSettings) -> None:
    """Configure structlog for JSON-formatted, structured logging.

    This must be called once at pipeline startup, before any log output.
    It configures both structlog and the standard library ``logging`` module
    to ensure all output (including third-party library logs) goes through
    the same JSON formatter.

    Args:
        settings: The validated ULPF settings containing ``log_level``.
    """
    log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # Configure structlog processors.
    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        _add_correlation_id,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Configure the standard library root logger to use structlog formatting.
    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(log_level)
