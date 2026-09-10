"""The ULPF Pipeline Orchestrator.

Ties ingestion, parsing, normalization, deduplication, output sinks,
and DLQ together into a cohesive asynchronous processing loop.
Handles graceful shutdown and signal handling.

Key improvements over the stub version:
- Pre-compiled regex patterns (no re.compile in hot path).
- Real OCSF event instantiation via ``normalizer.py``.
- Time-windowed SHA-256 deduplication (§5).
- Configurable worker pool for parallel processing (§scalability).
- Pluggable output sinks (§g: SIEM/Data Lake integration).
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

import structlog
from pydantic import ValidationError

from ulpf.config.settings import ULPFSettings
from ulpf.core.forensic import compute_raw_sha256
from ulpf.dlq.base import BaseDLQHandler
from ulpf.dlq.factory import create_dlq_handler
from ulpf.ingestion.listener import start_syslog_listener
from ulpf.metrics import (
    ULPF_DEDUP_TOTAL,
    ULPF_DLQ_TOTAL,
    ULPF_INGEST_TOTAL,
    ULPF_OCSF_VALIDATION_FAIL,
    ULPF_PARSE_SUCCESS_TOTAL,
    ULPF_QUEUE_DEPTH,
)
from ulpf.parsers.loader import load_active_parsers
from ulpf.parsers.normalizer import normalize_event
from ulpf.parsers.schema import ParserDefinition
from ulpf.server import start_http_server
from ulpf.sinks.base import BaseSink
from ulpf.sinks.factory import create_sink

logger = structlog.get_logger(__name__)


class Pipeline:
    """The main ingestion and processing pipeline.

    Orchestrates the full lifecycle: ingest → dedup → parse → normalize
    → validate OCSF → emit to sink. Unmatched or invalid events are
    routed to the Dead Letter Queue.
    """

    def __init__(self, settings: ULPFSettings, workspace_dir: Path) -> None:
        self.settings = settings
        self.workspace_dir = workspace_dir
        self.queue: asyncio.Queue[str] = asyncio.Queue(maxsize=settings.queue_max_size)
        self.running = False

        self.dlq_handler: BaseDLQHandler = create_dlq_handler(settings, workspace_dir)
        self.sink: BaseSink = create_sink(settings.sink_mode, workspace_dir / settings.output_dir)

        # Dashboard event history (bounded ring buffer).
        self.event_history: deque[dict[str, Any]] = deque(maxlen=200)

        # Deduplication window (§5: idempotency via raw_sha256).
        self._dedup_set: set[str] = set()
        self._dedup_timestamps: deque[tuple[float, str]] = deque()

        self.parsers: list[ParserDefinition] = load_active_parsers(
            workspace_dir / "parsers" / "active"
        )
        if not self.parsers:
            logger.warning("pipeline_starting_with_no_active_parsers")

    def _check_dedup(self, raw_sha256: str) -> bool:
        """Check if this event hash was already seen within the dedup window.

        Returns True if it's a duplicate (should be skipped).
        """
        if not self.settings.dedup_enabled:
            return False

        now = time.time()

        # Evict expired entries.
        while self._dedup_timestamps and (now - self._dedup_timestamps[0][0]) > self.settings.dedup_window_seconds:
            _, old_hash = self._dedup_timestamps.popleft()
            self._dedup_set.discard(old_hash)

        if raw_sha256 in self._dedup_set:
            ULPF_DEDUP_TOTAL.inc()
            return True

        self._dedup_set.add(raw_sha256)
        self._dedup_timestamps.append((now, raw_sha256))
        return False

    async def _process_payload(self, payload: str) -> None:
        """Process a single raw syslog payload through the full pipeline.

        Flow: dedup → regex match → OCSF normalize → validate → sink / DLQ.
        """
        raw_bytes = payload.encode("utf-8")
        raw_hash = compute_raw_sha256(raw_bytes)

        # Deduplication check (§5).
        if self._check_dedup(raw_hash):
            logger.debug("event_deduplicated", raw_sha256=raw_hash)
            return

        for parser in self.parsers:
            for compiled_pattern in parser.compiled_patterns:
                match = compiled_pattern.match(payload)
                if match:
                    ULPF_PARSE_SUCCESS_TOTAL.labels(parser=parser.name).inc()

                    try:
                        # Full OCSF normalization via field_mappings + Jinja2.
                        ocsf_event = normalize_event(parser, match, payload, raw_hash)
                        event_json = ocsf_event.model_dump_json(exclude_none=True)
                        event_data = json.loads(event_json)

                        # Emit to configured sink (stdout or jsonl file).
                        await self.sink.emit(event_json, event_data)

                        # Record for dashboard history.
                        self.event_history.append({
                            "status": "success",
                            "parser": parser.name,
                            "type_uid": ocsf_event.type_uid,
                            "ocsf_class": parser.ocsf_class,
                            "severity": event_data.get("severity_id", 1),
                            "message": event_data.get("message", ""),
                            "raw_sha256": raw_hash,
                            "raw_payload": payload[:1500],
                        })

                        logger.info(
                            "event_normalized",
                            parser_name=parser.name,
                            ocsf_class=parser.ocsf_class,
                            type_uid=ocsf_event.type_uid,
                            raw_sha256=raw_hash,
                        )
                    except ValidationError as exc:
                        # Matched a parser but failed OCSF strict validation.
                        ULPF_OCSF_VALIDATION_FAIL.labels(parser=parser.name).inc()
                        logger.warning(
                            "ocsf_validation_failed",
                            parser_name=parser.name,
                            raw_sha256=raw_hash,
                            error=str(exc),
                        )

                        # Still route to DLQ with the validation error.
                        self.event_history.append({
                            "status": "validation_error",
                            "parser": parser.name,
                            "type_uid": None,
                            "ocsf_class": parser.ocsf_class,
                            "severity": 0,
                            "message": str(exc)[:200],
                            "raw_sha256": raw_hash,
                            "raw_payload": payload[:1500],
                        })

                        ULPF_DLQ_TOTAL.labels(
                            reason="ocsf_validation_failed",
                            dlq_mode=self.settings.dlq_mode,
                        ).inc()
                        await self.dlq_handler.handle(
                            raw_payload=payload,
                            raw_sha256=raw_hash,
                            error_reason=f"OCSF validation failed: {exc}",
                        )
                    except Exception as exc:
                        logger.error("normalizer_error", parser_name=parser.name, error=str(exc))
                    return

        # If no parser matched, send to DLQ.
        ULPF_DLQ_TOTAL.labels(reason="unmatched", dlq_mode=self.settings.dlq_mode).inc()
        self.event_history.append({
            "status": "dlq",
            "parser": "None (Unmatched)",
            "type_uid": None,
            "ocsf_class": "unknown",
            "severity": 0,
            "message": "",
            "raw_sha256": raw_hash,
            "raw_payload": payload[:1500],
        })
        await self.dlq_handler.handle(
            raw_payload=payload,
            raw_sha256=raw_hash,
            error_reason="No matching active parsers found.",
        )

    async def _worker(self, worker_id: int) -> None:
        """Background worker that continuously processes the queue.

        Multiple workers run concurrently to maximize throughput.
        """
        while self.running or not self.queue.empty():
            ULPF_QUEUE_DEPTH.set(self.queue.qsize())
            try:
                payload = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                ULPF_INGEST_TOTAL.inc()
                try:
                    await self._process_payload(payload)
                finally:
                    self.queue.task_done()
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("worker_unexpected_error", worker_id=worker_id, error=str(exc))

    async def run(self) -> None:
        """Start the pipeline and run until cancelled."""
        self.running = True
        logger.info("pipeline_starting", worker_count=self.settings.worker_count)

        # Start observability server.
        server_runner = await start_http_server(self.settings, self)

        # Start listener.
        transport = await start_syslog_listener(self.settings, self.queue)

        # Start worker pool.
        worker_tasks = [
            asyncio.create_task(self._worker(i))
            for i in range(self.settings.worker_count)
        ]
        logger.info("workers_started", count=len(worker_tasks))

        try:
            while self.running:
                await asyncio.sleep(0.5)
        finally:
            logger.info("pipeline_shutting_down")
            transport.close()
            await server_runner.cleanup()

            # Drain queue gracefully (§5).
            logger.info("draining_queue", remaining=self.queue.qsize())
            await self.queue.join()

            for task in worker_tasks:
                task.cancel()

            for task in worker_tasks:
                try:
                    await task
                except asyncio.CancelledError:
                    pass

            # Close output sink.
            await self.sink.close()
            logger.info("pipeline_stopped")


def _setup_uvloop() -> None:
    """Dynamically use uvloop if available (non-Windows)."""
    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
            logger.info("uvloop_installed")
        except ImportError:
            logger.info("uvloop_not_installed_falling_back_to_asyncio")


def main() -> None:
    """Entry point for the pipeline."""
    _setup_uvloop()

    settings = ULPFSettings()
    workspace_dir = Path.cwd()

    pipeline = Pipeline(settings, workspace_dir)

    # Graceful shutdown handler.
    def shutdown_handler(sig: Any, frame: Any) -> None:
        logger.info("shutdown_signal_received", signal=sig)
        pipeline.running = False

    if sys.platform != "win32":
        signal.signal(signal.SIGINT, shutdown_handler)
        signal.signal(signal.SIGTERM, shutdown_handler)
    else:
        signal.signal(signal.SIGINT, shutdown_handler)

    try:
        asyncio.run(pipeline.run())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        logger.fatal("pipeline_crashed", error=str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
