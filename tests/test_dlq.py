import json
from pathlib import Path

import pytest

from ulpf.config.settings import ULPFSettings
from ulpf.dlq.ai import AIDLQHandler
from ulpf.dlq.ai_clients import AICircuitBreakerTripped, AIClientConfig, AIClientError, BaseAIClient
from ulpf.dlq.factory import create_dlq_handler
from ulpf.dlq.manual import ManualDLQHandler


@pytest.mark.asyncio
async def test_manual_dlq_handler_writes_file(tmp_path: Path) -> None:
    dlq_dir = tmp_path / "dlq"
    handler = ManualDLQHandler(output_dir=dlq_dir)

    await handler.handle("raw test log", "fake-hash", "test reason")

    # Find the written file
    files = list(dlq_dir.glob("*.jsonl"))
    assert len(files) == 1

    content = files[0].read_text()
    data = json.loads(content)

    assert data["raw_sha256"] == "fake-hash"
    assert data["error"] == "test reason"
    assert data["raw_payload"] == "raw test log"
    assert "timestamp" in data

def test_dlq_factory_manual(tmp_path: Path) -> None:
    settings = ULPFSettings(dlq_mode="manual")
    handler = create_dlq_handler(settings, tmp_path)
    assert isinstance(handler, ManualDLQHandler)

class DummyAIClient(BaseAIClient):
    def __init__(self, config: AIClientConfig) -> None:
        super().__init__(config)
        self.calls = 0
        self.responses: list[str] = []
        self.raise_err = False

    async def generate_parser(self, system_prompt: str, user_prompt: str) -> str:
        self.check_circuit()
        self.calls += 1
        if self.raise_err:
            self._record_failure()
            raise AIClientError("Mock failure")
        self._record_success()
        return self.responses.pop(0)

@pytest.mark.asyncio
async def test_ai_dlq_circuit_breaker() -> None:
    config = AIClientConfig(base_url="http://test", model="test", circuit_breaker_threshold=2)
    client = DummyAIClient(config)
    client.raise_err = True

    # Attempt 1
    with pytest.raises(AIClientError):
        await client.generate_parser("", "")

    # Attempt 2 -> trips circuit breaker
    with pytest.raises(AIClientError):
        await client.generate_parser("", "")

    # Attempt 3 -> immediately raises circuit breaker exception
    with pytest.raises(AICircuitBreakerTripped):
        await client.generate_parser("", "")

@pytest.mark.asyncio
async def test_ai_dlq_handler_validates_and_saves(tmp_path: Path) -> None:
    config = AIClientConfig(base_url="http://test", model="test", max_retries=1)
    client = DummyAIClient(config)

    # Bad response first, then good response to test self-healing
    client.responses = [
        "not a dict",
        """
name: test_parser
version: "1.0.0"
author: ai:test
created_at: "2026-09-06T00:00:00Z"
vendor: unknown
log_format: syslog
match_patterns:
  - "(?P<msg>.+)"
ocsf_class: base_event
ocsf_category_uid: 0
ocsf_class_uid: 0
field_mappings: []
"""
    ]

    pending_dir = tmp_path / "pending"
    fallback = ManualDLQHandler(tmp_path / "dlq")

    handler = AIDLQHandler(client, pending_dir, fallback)

    await handler.handle("raw", "hash123", "err")

    # 2 calls were made (1 initial + 1 retry)
    assert client.calls == 2

    # Should have saved the valid YAML
    saved = list(pending_dir.glob("hash123.yaml"))
    assert len(saved) == 1
