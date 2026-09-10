"""ULPF application settings driven entirely by environment variables.

Design rationale:
- Every tunable from AGENTS.md §2-§6 is surfaced here as a typed, validated field.
- Secrets use ``SecretStr`` and come from the environment only (§3).
- Bounded queue size and max message size are explicit to prevent memory-exhaustion
  DoS on the syslog listener (§3).
- The ``DLQ_MODE`` enum selects the Strategy Pattern handler at runtime (§2).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ULPFSettings(BaseSettings):
    """Centralized, validated configuration for the ULPF pipeline.

    All fields are populated from environment variables with the ``ULPF_`` prefix.
    A ``.env`` file is loaded automatically when present (gitignored in production).
    """

    model_config = SettingsConfigDict(
        env_prefix="ULPF_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Listener ─────────────────────────────────────────────────────────
    listen_host: str = "0.0.0.0"
    listen_port: int = 514
    max_message_size: int = 65_536
    """Per §3: bound every network read to prevent memory-exhaustion DoS."""
    queue_max_size: int = 500_000
    """Per §3: bounded, backpressured queue between ingestion and parser engine."""

    # ── DLQ Mode (Strategy Pattern selector) ─────────────────────────────
    dlq_mode: Literal["manual", "ollama", "openai"] = "manual"
    """Per §2: safe default is 'manual'. AI modes require additional config."""

    # ── Ollama (air-gapped AI) ───────────────────────────────────────────
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "mistral"

    # ── OpenAI (cloud AI) ────────────────────────────────────────────────
    openai_api_key: SecretStr | None = None
    """Per §3: from environment only. Never committed to code or files."""
    openai_model: str = "gpt-4o"
    openai_max_rpm: int = 10
    """Per §3: rate/cost-guard for the AI DLQ handler."""

    # ── AI Self-Healing ──────────────────────────────────────────────────
    ai_max_retries: int = 2
    """Per §2: capped retries before falling back to plain DLQ write."""

    # ── Paths ────────────────────────────────────────────────────────────
    parsers_active_dir: Path = Path("parsers/active")
    parsers_pending_dir: Path = Path("parsers/pending")
    dlq_dir: Path = Path("data/dlq")
    audit_log_path: Path = Path("data/audit.log")
    """Per §3: tamper-evident promotion trail for parser trust chain."""

    # ── Logging ──────────────────────────────────────────────────────────
    log_level: str = "INFO"

    # ── Observability ────────────────────────────────────────────────────
    metrics_port: int = 9090

    # ── Deduplication ────────────────────────────────────────────────────
    dedup_enabled: bool = True
    """Per §5: idempotency via raw_sha256 dedup."""
    dedup_window_seconds: int = 300

    # ── Worker Pool ──────────────────────────────────────────────────────
    worker_count: int = 16
    """Number of concurrent worker tasks for parallel event processing."""

    # ── Output Sinks (requirement g) ─────────────────────────────────────
    sink_mode: Literal["stdout", "jsonl"] = "jsonl"
    """Output destination: ``stdout`` for console, ``jsonl`` for file persistence."""
    output_dir: Path = Path("data/output")
    """Directory for persistent JSONL output files."""

    @model_validator(mode="after")
    def _validate_openai_key_when_needed(self) -> ULPFSettings:
        """Ensure ``OPENAI_API_KEY`` is set when ``DLQ_MODE`` is ``openai``.

        This prevents a silent misconfiguration from reaching production —
        the pipeline would appear healthy but silently fail every AI request.
        """
        if self.dlq_mode == "openai" and not self.openai_api_key:
            msg = (
                "ULPF_OPENAI_API_KEY must be set when ULPF_DLQ_MODE='openai'. "
                "Set the environment variable or switch to 'manual'/'ollama' mode."
            )
            raise ValueError(msg)
        return self

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist.

        Called during pipeline startup to avoid runtime write failures.
        Directory creation is idempotent (``exist_ok=True``).
        """
        self.parsers_active_dir.mkdir(parents=True, exist_ok=True)
        self.parsers_pending_dir.mkdir(parents=True, exist_ok=True)
        self.dlq_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
