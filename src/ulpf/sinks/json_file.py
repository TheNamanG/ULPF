"""JSON Lines file sink — appends OCSF events to a rotating .jsonl file.

This is the primary persistent sink for SIEM/Data Lake integration
(requirement g). Events are appended one-per-line in NDJSON format,
which is directly ingestible by Elasticsearch, Splunk HEC, and most
data lake tools.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import structlog

from ulpf.sinks.base import BaseSink

logger = structlog.get_logger(__name__)


class JsonFileSink(BaseSink):
    """Appends OCSF events as JSON lines to a file on disk.

    Creates the output directory and file if they don't exist.
    Uses an asyncio lock to prevent interleaved writes from
    concurrent workers.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.output_file = self.output_dir / "events.jsonl"
        self._lock = asyncio.Lock()
        self._file_handle = open(self.output_file, "a", encoding="utf-8")  # noqa: SIM115
        logger.info("jsonl_sink_initialized", path=str(self.output_file))

    async def emit(self, event_json: str, event_data: dict[str, Any]) -> None:
        """Append a single OCSF JSON event as a new line."""
        async with self._lock:
            self._file_handle.write(event_json + "\n")
            self._file_handle.flush()

    async def close(self) -> None:
        """Flush and close the file handle."""
        self._file_handle.flush()
        self._file_handle.close()
        logger.info("jsonl_sink_closed", path=str(self.output_file))
