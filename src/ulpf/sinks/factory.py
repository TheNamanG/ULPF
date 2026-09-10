"""Sink factory — selects the output sink based on configuration.

Follows the Strategy Pattern (§2): a new sink is a new class + a new
entry here. Zero changes to the pipeline's call sites.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from ulpf.sinks.base import BaseSink
from ulpf.sinks.json_file import JsonFileSink
from ulpf.sinks.stdout import StdoutSink


def create_sink(mode: Literal["stdout", "jsonl"], output_dir: Path) -> BaseSink:
    """Create the appropriate output sink based on config.

    Args:
        mode: ``stdout`` for console output, ``jsonl`` for file persistence.
        output_dir: Directory for the JSONL file (only used in ``jsonl`` mode).

    Returns:
        A configured ``BaseSink`` instance.
    """
    if mode == "jsonl":
        return JsonFileSink(output_dir)
    return StdoutSink()
