"""Stdout output sink — prints OCSF JSON to standard output."""

from __future__ import annotations

from typing import Any

from ulpf.sinks.base import BaseSink


class StdoutSink(BaseSink):
    """Prints each normalized OCSF event as a JSON line to stdout.

    This is the simplest sink, useful for development, piping to ``jq``,
    or redirecting to a file externally.
    """

    async def emit(self, event_json: str, event_data: dict[str, Any]) -> None:
        """Print the OCSF JSON to stdout."""
        print(event_json)

    async def close(self) -> None:
        """No resources to release for stdout."""
