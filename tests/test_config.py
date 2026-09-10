"""Tests for the ULPF configuration module."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from ulpf.config.settings import ULPFSettings

if TYPE_CHECKING:
    from pathlib import Path


class TestULPFSettingsDefaults:
    """Verify default settings load correctly without any env vars."""

    def test_default_dlq_mode_is_manual(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The safe default DLQ mode is 'manual' per §2."""
        monkeypatch.delenv("ULPF_DLQ_MODE", raising=False)
        settings = ULPFSettings()
        assert settings.dlq_mode == "manual"

    def test_default_listen_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings = ULPFSettings()
        assert settings.listen_port == 514

    def test_default_max_message_size(self) -> None:
        """Bounded network reads per §3."""
        settings = ULPFSettings()
        assert settings.max_message_size == 65_536

    def test_default_queue_max_size(self) -> None:
        """Bounded backpressured queue per §3."""
        settings = ULPFSettings()
        assert settings.queue_max_size == 500_000

    def test_default_dedup_enabled(self) -> None:
        """Idempotency via raw_sha256 dedup per §5."""
        settings = ULPFSettings()
        assert settings.dedup_enabled is True

    def test_default_ai_max_retries(self) -> None:
        """Self-healing retry cap per §2."""
        settings = ULPFSettings()
        assert settings.ai_max_retries == 2


class TestULPFSettingsValidation:
    """Verify settings validation catches misconfigurations early."""

    def test_openai_mode_without_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DLQ_MODE=openai requires OPENAI_API_KEY to be set."""
        monkeypatch.setenv("ULPF_DLQ_MODE", "openai")
        monkeypatch.delenv("ULPF_OPENAI_API_KEY", raising=False)
        with pytest.raises(ValidationError, match="ULPF_OPENAI_API_KEY must be set"):
            ULPFSettings()

    def test_openai_mode_with_key_succeeds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """DLQ_MODE=openai with a key should succeed."""
        monkeypatch.setenv("ULPF_DLQ_MODE", "openai")
        monkeypatch.setenv("ULPF_OPENAI_API_KEY", "sk-test-key-12345")
        settings = ULPFSettings()
        assert settings.dlq_mode == "openai"
        assert settings.openai_api_key is not None

    def test_ollama_mode_succeeds_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Ollama mode should work without an OpenAI key."""
        monkeypatch.setenv("ULPF_DLQ_MODE", "ollama")
        monkeypatch.delenv("ULPF_OPENAI_API_KEY", raising=False)
        settings = ULPFSettings()
        assert settings.dlq_mode == "ollama"


class TestULPFSettingsEnvOverride:
    """Verify environment variables override defaults correctly."""

    def test_listen_port_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ULPF_LISTEN_PORT", "1514")
        settings = ULPFSettings()
        assert settings.listen_port == 1514

    def test_log_level_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ULPF_LOG_LEVEL", "DEBUG")
        settings = ULPFSettings()
        assert settings.log_level == "DEBUG"

    def test_metrics_port_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ULPF_METRICS_PORT", "8080")
        settings = ULPFSettings()
        assert settings.metrics_port == 8080


class TestEnsureDirectories:
    """Verify directory creation works correctly."""

    def test_creates_required_directories(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ULPF_PARSERS_ACTIVE_DIR", str(tmp_path / "p" / "active"))
        monkeypatch.setenv("ULPF_PARSERS_PENDING_DIR", str(tmp_path / "p" / "pending"))
        monkeypatch.setenv("ULPF_DLQ_DIR", str(tmp_path / "d" / "dlq"))
        monkeypatch.setenv("ULPF_AUDIT_LOG_PATH", str(tmp_path / "d" / "audit.log"))

        settings = ULPFSettings()
        settings.ensure_directories()

        assert settings.parsers_active_dir.exists()
        assert settings.parsers_pending_dir.exists()
        assert settings.dlq_dir.exists()
        assert settings.audit_log_path.parent.exists()

    def test_idempotent_directory_creation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Calling ensure_directories twice should not raise."""
        monkeypatch.setenv("ULPF_PARSERS_ACTIVE_DIR", str(tmp_path / "active"))
        monkeypatch.setenv("ULPF_PARSERS_PENDING_DIR", str(tmp_path / "pending"))
        monkeypatch.setenv("ULPF_DLQ_DIR", str(tmp_path / "dlq"))
        monkeypatch.setenv("ULPF_AUDIT_LOG_PATH", str(tmp_path / "audit.log"))

        settings = ULPFSettings()
        settings.ensure_directories()
        settings.ensure_directories()  # Should not raise
