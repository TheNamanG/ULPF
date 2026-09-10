"""CLI tool for ULPF.

Provides utilities for analysts to test parsers securely offline.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import structlog

from ulpf.core.forensic import compute_raw_sha256
from ulpf.parsers.loader import ParserValidationError, load_parser
from ulpf.parsers.schema import ParserDefinition

logger = structlog.get_logger(__name__)


@click.group()
def cli() -> None:
    """Universal Log Pre-processing Framework (ULPF) CLI."""
    pass


@cli.group()
def parser() -> None:
    """Manage and test OCSF parsers."""
    pass


@parser.command()
@click.argument("parser_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("sample_file", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def test(parser_file: Path, sample_file: Path) -> None:
    """Test a single YAML parser against a sample raw log."""
    try:
        parser_def: ParserDefinition = load_parser(parser_file)
    except ParserValidationError as exc:
        click.secho(f"Parser validation failed: {exc}", fg="red", err=True)
        sys.exit(1)

    raw_payload = sample_file.read_text(encoding="utf-8")
    raw_hash = compute_raw_sha256(raw_payload.encode("utf-8"))

    import re
    for pattern_str in parser_def.match_patterns:
        pattern = re.compile(pattern_str)
        match = pattern.match(raw_payload)
        if match:
            click.secho(f"Match found using pattern: {pattern_str}", fg="green", err=True)
            # Stubbed OCSF output for testing
            output = {
                "type_uid": parser_def.ocsf_class_uid * 100,
                "raw_sha256": raw_hash,
                "raw_payload": raw_payload,
                "parser": parser_def.name,
                "extracted_fields": match.groupdict(),
            }
            click.echo(json.dumps(output, indent=2))
            sys.exit(0)

    click.secho("No match found.", fg="yellow", err=True)
    sys.exit(1)


if __name__ == "__main__":
    cli()
