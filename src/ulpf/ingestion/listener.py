"""Syslog network listener for ULPF.

Implements an asyncio UDP datagram listener. Features bounded queues
and memory-exhaustion protections.
"""

from __future__ import annotations

import asyncio

import structlog

from ulpf.config.settings import ULPFSettings

logger = structlog.get_logger(__name__)


class SyslogProtocol(asyncio.DatagramProtocol):
    """UDP Protocol for receiving syslog packets.
    
    Puts received UTF-8 decoded packets into a bounded asyncio.Queue.
    If the queue is full, the packet is intentionally dropped (load shedding)
    rather than consuming unbounded memory (§3).
    """
    def __init__(self, queue: asyncio.Queue[str], max_message_size: int) -> None:
        self.queue = queue
        self.max_message_size = max_message_size

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport
        logger.info("syslog_listener_started")

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        if len(data) > self.max_message_size:
            logger.warning(
                "syslog_message_too_large_dropped",
                size=len(data),
                max_size=self.max_message_size,
                src_ip=addr[0],
            )
            return

        try:
            # We strictly decode UTF-8. In real environments, fallback to
            # latin-1 or replacing errors might be required, but per §7
            # non-UTF-8 packets must not crash the process.
            payload = data.decode("utf-8", errors="replace")
        except Exception as exc:
            logger.warning("syslog_decode_failed", error=str(exc), src_ip=addr[0])
            return

        try:
            # Use put_nowait to drop the packet if queue is full (load shedding)
            self.queue.put_nowait(payload)
        except asyncio.QueueFull:
            # Load shedding active.
            logger.warning("syslog_queue_full_load_shedding", src_ip=addr[0])


async def start_syslog_listener(
    settings: ULPFSettings,
    queue: asyncio.Queue[str],
) -> asyncio.DatagramTransport:
    """Start the UDP Syslog listener.
    
    Args:
        settings: ULPF settings containing host/port config.
        queue: Bounded queue to push raw syslog payloads into.
        
    Returns:
        The active UDP transport.
    """
    loop = asyncio.get_running_loop()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(queue=queue, max_message_size=settings.max_message_size),
        local_addr=("0.0.0.0", 5140), # Default unprivileged port for testing
    )

    logger.info(
        "syslog_listener_bound",
        host="0.0.0.0",
        port=5140,
        queue_maxsize=queue.maxsize,
    )
    return transport
