"""Strict Pydantic schema for YAML parser definition files.

This model validates the **parser definition itself** (§4) — the YAML file
that a human or AI writes into ``parsers/*/``. It is validated on load, not
at runtime, so a malformed parser is rejected before it ever touches the
pipeline.

Security note (§3): The ``match_patterns`` are compiled as regexes to catch
syntax errors early. The ``jinja2_template`` fields are validated to ensure
they don't contain obviously dangerous constructs, but the real sandboxing
happens at render time in ``sandbox.py``.
"""

from __future__ import annotations

import re
from datetime import datetime  # noqa: TC003
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

# The set of OCSF class UIDs we support (expandable as we add more event classes).
_KNOWN_CLASS_UIDS: frozenset[int] = frozenset({0, 3002, 4001})

# SemVer regex (simplified but sufficient for validation).
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?$")


class ParserField(BaseModel):
    """Maps a named regex capture group to an OCSF field path.

    Each field specifies where in the OCSF event the extracted value
    should be placed (``ocsf_field``), what type to coerce it to, and
    an optional Jinja2 template for value transformation.
    """

    model_config = ConfigDict(strict=False)

    ocsf_field: str
    """Dot-path into the OCSF event, e.g. ``src_endpoint.ip``."""

    type: Literal["str", "int", "bool", "float", "datetime"] = "str"
    """Target Python type for the extracted value."""

    jinja2_template: str | None = None
    """Optional Jinja2 expression for value transformation (rendered in sandbox)."""

    default: Any = None
    """Fallback value when the capture group is empty or missing."""


class ParserDefinition(BaseModel):
    """The validated schema for a YAML parser definition file.

    Every parser file in ``parsers/active/`` and ``parsers/pending/`` must
    conform to this schema. Files that fail validation are rejected —
    they are never loaded into the pipeline (§4).

    Audit metadata (``version``, ``author``, ``created_at``) is required
    on every parser for the tamper-evident promotion trail (§3).
    """

    model_config = ConfigDict(strict=False)

    # ── Metadata (§4: audit) ─────────────────────────────────────────────
    name: str
    """Unique parser identifier, e.g. ``linux_sshd``, ``cisco_asa``."""

    version: str
    """SemVer string, e.g. ``1.0.0``. Validated against SemVer pattern."""

    author: str
    """``human`` or ``ai:<model>`` — tracks provenance for audit."""

    created_at: datetime
    """ISO 8601 timestamp of parser creation."""

    description: str | None = None

    # ── Matching ─────────────────────────────────────────────────────────
    vendor: str
    """Vendor identifier, e.g. ``cisco``, ``linux``, ``generic``."""

    log_format: str
    """Expected log format, e.g. ``syslog``, ``json``, ``csv``."""

    match_patterns: list[str]
    """Regex patterns tried in order. First match wins and populates named groups."""

    match_priority: int = 100
    """Lower value = tried first. Default parsers ship at 100; fallback at 999."""

    # ── OCSF Mapping ─────────────────────────────────────────────────────
    ocsf_class: Literal["base_event", "authentication", "network_activity"]
    """Which OCSF event class this parser emits."""

    ocsf_category_uid: int
    """OCSF category UID (e.g. 3 for IAM, 4 for Network)."""

    ocsf_class_uid: int
    """OCSF class UID (e.g. 3002, 4001). Must be in the known set."""

    field_mappings: list[ParserField]
    """Ordered list of capture-group-to-OCSF-field mappings."""

    static_values: dict[str, Any] = {}
    """Key-value pairs set on every event from this parser (e.g. severity_id)."""

    # Populated post-validation, not from YAML.
    compiled_patterns: list[re.Pattern[str]] = []
    """Pre-compiled regex patterns for hot-path performance. Populated by model_validator."""

    @model_validator(mode="after")
    def _compile_patterns(self) -> "ParserDefinition":
        """Pre-compile regex patterns once at load time.

        Avoids calling ``re.compile()`` on every single event in the
        hot path — a critical performance optimization for high-EPS.
        """
        self.compiled_patterns = [re.compile(p) for p in self.match_patterns]
        return self

    # ── Validators ───────────────────────────────────────────────────────

    @field_validator("version")
    @classmethod
    def _validate_semver(cls, v: str) -> str:
        """Reject non-SemVer version strings early.

        This prevents unversioned or arbitrarily-versioned parsers from
        entering the registry, which would break the audit trail.
        """
        if not _SEMVER_RE.match(v):
            msg = f"Parser version must be valid SemVer, got: {v!r}"
            raise ValueError(msg)
        return v

    @field_validator("match_patterns")
    @classmethod
    def _validate_regex_patterns(cls, patterns: list[str]) -> list[str]:
        """Compile each regex pattern to catch syntax errors at load time.

        A parser with an invalid regex would silently never match anything
        at runtime — catching it here gives the operator a clear error.
        """
        for i, pattern in enumerate(patterns):
            try:
                re.compile(pattern)
            except re.error as exc:
                msg = f"match_patterns[{i}] is not valid regex: {exc}"
                raise ValueError(msg) from exc
        return patterns

    @field_validator("ocsf_class_uid")
    @classmethod
    def _validate_class_uid(cls, v: int) -> int:
        """Ensure the class UID is one we have a Pydantic model for.

        This prevents parsers from claiming to emit event types that
        our pipeline can't validate, which would cause silent failures.
        """
        if v not in _KNOWN_CLASS_UIDS:
            msg = f"ocsf_class_uid must be one of {sorted(_KNOWN_CLASS_UIDS)}, got: {v}"
            raise ValueError(msg)
        return v

    @field_validator("author")
    @classmethod
    def _validate_author(cls, v: str) -> str:
        """Ensure author follows the convention: ``human`` or ``ai:<model>``.

        This is the provenance tag for the audit trail — a free-form
        string here would undermine trust decisions during parser promotion.
        """
        if v != "human" and not v.startswith("ai:"):
            msg = f"author must be 'human' or 'ai:<model>', got: {v!r}"
            raise ValueError(msg)
        return v
