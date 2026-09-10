import asyncio

import pytest

from ulpf.config.settings import ULPFSettings
from ulpf.ingestion.listener import SyslogProtocol, start_syslog_listener


@pytest.mark.asyncio
async def test_syslog_protocol_drops_oversized() -> None:
    queue: asyncio.Queue[str] = asyncio.Queue()
    protocol = SyslogProtocol(queue=queue, max_message_size=10)

    # 11 bytes should be dropped
    protocol.datagram_received(b"12345678901", ("127.0.0.1", 514))
    assert queue.empty()

    # 10 bytes should be accepted
    protocol.datagram_received(b"1234567890", ("127.0.0.1", 514))
    assert not queue.empty()
    assert queue.get_nowait() == "1234567890"

@pytest.mark.asyncio
async def test_syslog_protocol_load_sheds_on_full_queue() -> None:
    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
    protocol = SyslogProtocol(queue=queue, max_message_size=100)

    # First message fits
    protocol.datagram_received(b"msg1", ("127.0.0.1", 514))
    assert queue.qsize() == 1

    # Second message is shed
    protocol.datagram_received(b"msg2", ("127.0.0.1", 514))
    assert queue.qsize() == 1

    # Queue only has msg1
    assert queue.get_nowait() == "msg1"

@pytest.mark.asyncio
async def test_syslog_protocol_handles_bad_utf8() -> None:
    queue: asyncio.Queue[str] = asyncio.Queue()
    protocol = SyslogProtocol(queue=queue, max_message_size=100)

    # Invalid UTF-8 bytes
    protocol.datagram_received(b"hello \xff world", ("127.0.0.1", 514))

    assert not queue.empty()
    # It replaces errors, so it shouldn't crash
    result = queue.get_nowait()
    assert "hello" in result
    assert "world" in result

@pytest.mark.asyncio
async def test_start_syslog_listener() -> None:
    settings = ULPFSettings()
    # Temporarily override port so we don't conflict
    queue: asyncio.Queue[str] = asyncio.Queue()
    transport = await start_syslog_listener(settings, queue)

    assert transport is not None
    transport.close()
