from pathlib import Path

import pytest

from ulpf.config.settings import ULPFSettings
from ulpf.pipeline import Pipeline, _setup_uvloop


@pytest.mark.asyncio
async def test_pipeline_initialization(tmp_path: Path) -> None:
    settings = ULPFSettings(dlq_mode="manual")
    # Missing active parsers
    pipeline = Pipeline(settings, tmp_path)
    assert not pipeline.running
    assert len(pipeline.parsers) == 0
    assert pipeline.queue.maxsize == settings.queue_max_size

@pytest.mark.asyncio
async def test_pipeline_process_payload_dlq_routing(tmp_path: Path) -> None:
    settings = ULPFSettings(dlq_mode="manual")
    pipeline = Pipeline(settings, tmp_path)

    # Send a payload that won't match any parser (there are no parsers)
    await pipeline._process_payload("unmatched log")

    # Check if manual DLQ got it
    dlq_files = list((tmp_path / "dlq").glob("*.jsonl"))
    assert len(dlq_files) == 1
    content = dlq_files[0].read_text()
    assert "unmatched log" in content

def test_setup_uvloop() -> None:
    # Just ensure it doesn't crash on Windows
    _setup_uvloop()
