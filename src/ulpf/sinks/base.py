"""Abstract base class for output sinks."""

from __future__ import annotations

import abc
from typing import Any


class BaseSink(abc.ABC):
    """Interface for pipeline output destinations.

    Every sink must implement ``emit()`` to receive validated OCSF events
    and ``close()`` for graceful shutdown. The pipeline calls these methods
    after successful normalization and validation.
    """

    @abc.abstractmethod
    async def emit(self, event_json: str, event_data: dict[str, Any]) -> None:
        """Write a single normalized OCSF event to the output.

        Args:
            event_json: The serialized JSON string of the OCSF event.
            event_data: The dict representation for sinks that need structured access.
        """

    @abc.abstractmethod
    async def close(self) -> None:
        """Flush buffers and release resources during graceful shutdown."""
