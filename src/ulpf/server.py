"""Asynchronous HTTP server for exposing metrics and health checks."""

from __future__ import annotations

from typing import Any

import structlog
from aiohttp import web
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from ulpf.config.settings import ULPFSettings

logger = structlog.get_logger(__name__)


async def metrics_handler(request: web.Request) -> web.Response:
    """Serve Prometheus metrics."""
    data = generate_latest()
    headers = {
        "Content-Type": CONTENT_TYPE_LATEST,
        "Access-Control-Allow-Origin": "*",
    }
    return web.Response(body=data, headers=headers)


async def healthz_handler(request: web.Request) -> web.Response:
    """Liveness probe - always returns 200 OK if server is responsive."""
    return web.Response(text="OK", status=200)


async def readyz_handler(request: web.Request) -> web.Response:
    """Readiness probe - checks if the pipeline is fully initialized.
    
    Reads from the application state to see if active parsers were loaded.
    """
    is_ready: bool = request.app.get("is_ready", False)
    if is_ready:
        return web.Response(text="Ready", status=200)
    return web.Response(text="Not Ready", status=503)


async def history_handler(request: web.Request) -> web.Response:
    """Serve recent parsed/dlq log event history for the dashboard."""
    pipeline = request.app.get("pipeline")
    events = list(pipeline.event_history) if pipeline and hasattr(pipeline, "event_history") else []
    headers = {
        "Access-Control-Allow-Origin": "*",
    }
    return web.json_response(events, headers=headers)


async def start_http_server(settings: ULPFSettings, pipeline: Any) -> web.AppRunner:
    """Start the observability HTTP server.
    
    Args:
        settings: Application settings.
        pipeline: The Pipeline instance to check readiness state.
        
    Returns:
        The aiohttp AppRunner to allow graceful shutdown later.
    """
    app = web.Application()

    # Expose pipeline state for readiness checks and history
    app["is_ready"] = len(pipeline.parsers) > 0
    app["pipeline"] = pipeline

    app.add_routes([
        web.get("/metrics", metrics_handler),
        web.get("/healthz", healthz_handler),
        web.get("/readyz", readyz_handler),
        web.get("/history", history_handler),
    ])

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", 8080)
    await site.start()

    logger.info("observability_server_started", port=8080)
    return runner
