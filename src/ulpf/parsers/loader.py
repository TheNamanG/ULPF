"""Parser definition file loader.

Reads YAML parser files from disk, validates them against the
``ParserDefinition`` Pydantic schema (§4), and returns them sorted
by match priority for the parser engine.

Design decisions:
- Invalid parser files are logged as warnings but never crash the
  pipeline (§5: degrade, don't crash).
- Parsers are sorted by ``match_priority`` (ascending) so lower-priority
  values are tried first.
- The loader is synchronous because it runs at startup, not in the
  hot path.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
import yaml
from pydantic import ValidationError

from ulpf.parsers.schema import ParserDefinition

if TYPE_CHECKING:
    from pathlib import Path

logger = structlog.get_logger(__name__)


class ParserValidationError(Exception):
    """Raised when a parser YAML file fails schema validation.

    Wraps the underlying Pydantic ``ValidationError`` with the file path
    for operator-friendly error messages.
    """

    def __init__(self, path: Path, cause: ValidationError | yaml.YAMLError) -> None:
        self.path = path
        self.cause = cause
        super().__init__(f"Invalid parser definition at {path}: {cause}")


def load_parser(path: Path) -> ParserDefinition:
    """Load and validate a single YAML parser definition file.

    Args:
        path: Absolute or relative path to the ``.yaml`` file.

    Returns:
        A validated ``ParserDefinition`` instance.

    Raises:
        ParserValidationError: If the YAML is malformed or fails schema
            validation. The caller decides whether to log-and-skip or
            re-raise.
        FileNotFoundError: If the path does not exist.
    """
    raw_text = path.read_text(encoding="utf-8")

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ParserValidationError(path, exc) from exc

    if not isinstance(data, dict):
        raise ParserValidationError(
            path,
            ValidationError.from_exception_data(
                title="ParserDefinition",
                line_errors=[],
            ),
        )

    try:
        return ParserDefinition.model_validate(data)
    except ValidationError as exc:
        raise ParserValidationError(path, exc) from exc


def load_active_parsers(active_dir: Path) -> list[ParserDefinition]:
    """Scan the active parsers directory and load all valid definitions.

    Invalid files are logged as warnings but skipped — the pipeline
    starts with whatever parsers are valid rather than refusing to
    start at all (§5: degrade, don't crash).

    Args:
        active_dir: Path to the ``parsers/active/`` directory.

    Returns:
        List of validated ``ParserDefinition`` instances, sorted by
        ``match_priority`` (ascending — lower values tried first).
    """
    parsers: list[ParserDefinition] = []

    if not active_dir.exists():
        logger.warning("active_parsers_dir_missing", path=str(active_dir))
        return parsers

    yaml_files = sorted(active_dir.glob("*.yaml"))
    if not yaml_files:
        logger.warning("no_active_parsers_found", path=str(active_dir))
        return parsers

    for path in yaml_files:
        try:
            parser_def = load_parser(path)
            parsers.append(parser_def)
            logger.info(
                "parser_loaded",
                name=parser_def.name,
                version=parser_def.version,
                priority=parser_def.match_priority,
                path=str(path),
            )
        except ParserValidationError as exc:
            logger.warning(
                "parser_load_failed",
                path=str(path),
                error=str(exc.cause),
            )
        except Exception as exc:
            logger.warning(
                "parser_load_unexpected_error",
                path=str(path),
                error=str(exc),
            )

    # Sort by priority — lower match_priority values are tried first.
    parsers.sort(key=lambda p: p.match_priority)

    logger.info("active_parsers_loaded", count=len(parsers), total_files=len(yaml_files))
    return parsers
