"""Manual DLQ strategy: writes unparsed logs to disk."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import structlog

from ulpf.dlq.base import BaseDLQHandler

logger = structlog.get_logger(__name__)


class ManualDLQHandler(BaseDLQHandler):
    """Safely persists unparsed logs to disk for human review.
    
    This is the default, air-gapped safe strategy. It writes logs to a
    local directory in JSON Lines format, preserving the forensic hash
    and the error context.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def handle(self, raw_payload: str, raw_sha256: str, error_reason: str) -> None:
        """Write the unparsed payload to a daily-rotated JSONL file."""
        today = datetime.now(tz=UTC).strftime("%Y-%m-%d")
        file_path = self.output_dir / f"dlq-{today}.jsonl"

        dlq_entry = {
            "timestamp": datetime.now(tz=UTC).isoformat(),
            "raw_sha256": raw_sha256,
            "error": error_reason,
            "raw_payload": raw_payload,
        }

        try:
            # We use append mode and write synchronously. In a high-throughput
            # environment we might use aiofiles, but a blocking write is acceptable
            # here for the manual fallback if volume is low.
            with file_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(dlq_entry) + "\n")

            logger.warning(
                "log_routed_to_manual_dlq",
                raw_sha256=raw_sha256,
                reason=error_reason,
            )
        except Exception as exc:
            # Degrade, don't crash (§5). If disk is full, log and shed load.
            logger.error(
                "manual_dlq_write_failed",
                raw_sha256=raw_sha256,
                error=str(exc),
            )
