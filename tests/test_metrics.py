from pathlib import Path
import pytest
from aiohttp import web
from ulpf.config.settings import ULPFSettings
from ulpf.pipeline import Pipeline
from ulpf.server import start_http_server


@pytest.mark.asyncio
async def test_metrics_and_healthz_server(tmp_path: Path) -> None:
    settings = ULPFSettings(dlq_mode="manual")
    pipeline = Pipeline(settings, tmp_path)

    # Start server
    runner = await start_http_server(settings, pipeline)

    # Since we can't easily mock an HTTP client without aiohttp.test_utils,
    # we'll just test that the handlers work directly.
    # The handlers don't strictly need a full request, just something with .app
    # but readyz_handler expects request.app to be a dict-like object.
    class MockRequest:
        def __init__(self) -> None:
            self.app: dict[str, bool] = {"is_ready": False}
    
    req = MockRequest()
    
    from ulpf.server import healthz_handler, readyz_handler, metrics_handler
    
    res_healthz = await healthz_handler(req) # type: ignore[arg-type]
    assert res_healthz.status == 200
    assert res_healthz.text == "OK"
    
    res_readyz = await readyz_handler(req) # type: ignore[arg-type]
    # No parsers loaded, so should be 503
    assert res_readyz.status == 503
    
    res_metrics = await metrics_handler(req) # type: ignore[arg-type]
    assert res_metrics.status == 200
    assert res_metrics.text is not None
    assert "ulpf_ingest_total" in res_metrics.text
    
    await runner.cleanup()
