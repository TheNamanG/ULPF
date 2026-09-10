"""Factory for selecting the active DLQ handler strategy."""

from __future__ import annotations

from pathlib import Path

import structlog

from ulpf.config.settings import ULPFSettings
from ulpf.dlq.ai import OllamaDLQHandler, OpenAIDLQHandler
from ulpf.dlq.ai_clients import AIClientConfig
from ulpf.dlq.base import BaseDLQHandler
from ulpf.dlq.manual import ManualDLQHandler

logger = structlog.get_logger(__name__)


def create_dlq_handler(settings: ULPFSettings, workspace_dir: Path) -> BaseDLQHandler:
    """Instantiate the configured DLQ handler strategy.
    
    Args:
        settings: Application settings.
        workspace_dir: Base directory for resolving dlq/ and parsers/ paths.
        
    Returns:
        A BaseDLQHandler instance configured per settings.dlq_mode.
    """
    manual_dir = workspace_dir / "dlq"
    pending_dir = workspace_dir / "parsers" / "pending"

    manual_handler = ManualDLQHandler(output_dir=manual_dir)

    if settings.dlq_mode == "manual":
        return manual_handler

    elif settings.dlq_mode == "ollama":
        config = AIClientConfig(
            base_url=settings.ollama_host,
            model="llama3",  # Sensible default for Ollama local instances
            max_retries=2,
            timeout_seconds=30,
            circuit_breaker_threshold=5,
        )
        return OllamaDLQHandler(config, pending_dir, fallback_handler=manual_handler)

    elif settings.dlq_mode == "openai":
        if not settings.openai_api_key:
            logger.warning("openai_key_missing_falling_back_to_manual_dlq")
            return manual_handler

        config = AIClientConfig(
            base_url="https://api.openai.com",
            api_key=settings.openai_api_key.get_secret_value(),
            model="gpt-4o",  # Advanced reasoning model for zero-shot parsers
            max_retries=2,
            timeout_seconds=30,
            circuit_breaker_threshold=5,
        )
        return OpenAIDLQHandler(config, pending_dir, fallback_handler=manual_handler)

    logger.warning("unknown_dlq_mode_falling_back_to_manual", mode=settings.dlq_mode)
    return manual_handler
