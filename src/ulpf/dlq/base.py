"""Base interface for DLQ handlers (Strategy Pattern)."""

from __future__ import annotations

import abc


class BaseDLQHandler(abc.ABC):
    """Abstract interface for all Dead Letter Queue strategies.
    
    A DLQ handler is invoked when a log message fails to match any active
    parsers or fails OCSF validation. Implementations may simply write the
    log to disk (Manual) or attempt to use AI to generate a parser.
    """

    @abc.abstractmethod
    async def handle(self, raw_payload: str, raw_sha256: str, error_reason: str) -> None:
        """Process an unparsed log message.
        
        Args:
            raw_payload: The exact UTF-8 string of the unparsed log.
            raw_sha256: The SHA-256 hash of the original raw bytes.
            error_reason: A brief description of why the log was routed to DLQ.
        """
        pass
