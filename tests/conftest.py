"""Shared test fixtures for the ULPF test suite."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from ulpf.config.settings import ULPFSettings
from ulpf.core.objects import Metadata, Product


@pytest.fixture
def sample_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ULPFSettings:
    """Provide a ULPFSettings instance with paths pointing to a temp directory."""
    monkeypatch.setenv("ULPF_DLQ_MODE", "manual")
    monkeypatch.setenv("ULPF_PARSERS_ACTIVE_DIR", str(tmp_path / "parsers" / "active"))
    monkeypatch.setenv("ULPF_PARSERS_PENDING_DIR", str(tmp_path / "parsers" / "pending"))
    monkeypatch.setenv("ULPF_DLQ_DIR", str(tmp_path / "data" / "dlq"))
    monkeypatch.setenv("ULPF_AUDIT_LOG_PATH", str(tmp_path / "data" / "audit.log"))
    monkeypatch.setenv("ULPF_LOG_LEVEL", "DEBUG")
    return ULPFSettings()


@pytest.fixture
def sample_metadata() -> Metadata:
    """Provide a minimal valid OCSF Metadata object."""
    return Metadata(
        version="1.3.0",
        product=Product(name="ulpf", vendor_name="SyntaxSentinels"),
    )


@pytest.fixture
def sample_raw_log() -> bytes:
    """A generic raw log line as bytes — used for forensic envelope tests."""
    return b"<134>1 2026-09-06T10:00:00Z myhost myapp 1234 ID47 - Test message"


@pytest.fixture
def sample_auth_log() -> bytes:
    """A Linux sshd 'Accepted password' log line as bytes."""
    return b"Sep  6 10:00:00 webserver sshd[12345]: Accepted password for admin from 192.168.1.100 port 52413 ssh2"


@pytest.fixture
def sample_auth_log_failed() -> bytes:
    """A Linux sshd 'Failed password' log line as bytes."""
    return b"Sep  6 10:00:01 webserver sshd[12345]: Failed password for invalid user root from 10.0.0.5 port 44231 ssh2"


@pytest.fixture
def sample_asa_log() -> bytes:
    """A Cisco ASA connection-built syslog message as bytes."""
    return b"%ASA-6-302013: Built inbound TCP connection 12345 for outside:10.0.0.1/1234 (10.0.0.1/1234) to inside:192.168.1.1/443 (192.168.1.1/443)"


@pytest.fixture
def sample_rfc5424_log() -> bytes:
    """A RFC 5424 structured syslog message as bytes."""
    return b"<134>1 2026-09-06T10:00:00.000Z myhost myapp 1234 ID47 [exampleSDID@32473 iut=\"3\"] Application event occurred"


@pytest.fixture
def current_time_ms() -> int:
    """Current time as Unix epoch milliseconds (OCSF timestamp format)."""
    return int(time.time() * 1000)


@pytest.fixture
def parsers_active_dir() -> Path:
    """Path to the shipped active parsers directory."""
    return Path(__file__).parent.parent / "parsers" / "active"
