"""OCSF event normalizer — transforms regex matches into validated OCSF events.

This is the core of the framework's claim: taking raw, heterogeneous log
data and producing strict, validated OCSF v1.3 events. Every event is
built from the parser's ``field_mappings``, rendered through the Jinja2
sandbox, type-coerced, and finally validated by the Pydantic model.

Security note (§3): All Jinja2 templates are rendered through the
hardened ``SandboxedEnvironment`` in ``sandbox.py``. No template author
(human or AI) can access ``__class__``, file I/O, or ``import``.
"""

from __future__ import annotations

import re
import time
from typing import Any

import structlog
from pydantic import ValidationError

from ulpf.core.enums import FingerprintAlgorithmId
from ulpf.core.events import Authentication, BaseEvent, NetworkActivity
from ulpf.core.objects import Fingerprint, Metadata, Product
from ulpf.parsers.sandbox import render_template
from ulpf.parsers.schema import ParserDefinition, ParserField

logger = structlog.get_logger(__name__)

# Map ocsf_class strings to their Pydantic model classes.
_EVENT_CLASS_MAP: dict[str, type[BaseEvent]] = {
    "base_event": BaseEvent,
    "authentication": Authentication,
    "network_activity": NetworkActivity,
}


def _coerce_value(raw: str, target_type: str) -> Any:
    """Coerce a string value extracted from a regex match to the target type.

    Args:
        raw: The raw string from the capture group or Jinja2 render.
        target_type: One of ``str``, ``int``, ``float``, ``bool``, ``datetime``.

    Returns:
        The coerced value.

    Raises:
        ValueError: If the coercion fails.
    """
    if target_type == "str":
        return raw
    if target_type == "int":
        return int(raw)
    if target_type == "float":
        return float(raw)
    if target_type == "bool":
        return raw.lower() in ("true", "1", "yes")
    if target_type == "datetime":
        return raw  # Keep as string; OCSF uses epoch ms in `time` field.
    return raw


def _set_nested(data: dict[str, Any], dotpath: str, value: Any) -> None:
    """Set a value in a nested dict using a dot-separated path.

    For example, ``_set_nested(d, "src_endpoint.ip", "1.2.3.4")`` creates
    ``{"src_endpoint": {"ip": "1.2.3.4"}}``.
    """
    keys = dotpath.split(".")
    current = data
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        current = current[key]
    current[keys[-1]] = value


def normalize_event(
    parser: ParserDefinition,
    match: re.Match[str],
    raw_payload: str,
    raw_sha256: str,
) -> BaseEvent:
    """Transform a regex match into a validated OCSF event.

    This is the heart of the ULPF pipeline. It:
    1. Extracts named capture groups from the regex match.
    2. Renders Jinja2 templates from ``field_mappings`` through the sandbox.
    3. Coerces values to their declared types.
    4. Builds the forensic envelope (``raw_data``, ``raw_data_hash``).
    5. Instantiates and validates the correct OCSF Pydantic model.

    Args:
        parser: The matched parser definition.
        match: The regex match object with named capture groups.
        raw_payload: The original, unmodified log payload.
        raw_sha256: Pre-computed SHA-256 hex digest of the raw bytes.

    Returns:
        A validated OCSF event instance.

    Raises:
        ValidationError: If the constructed event fails OCSF schema validation.
    """
    groups = match.groupdict()
    now_epoch_ms = int(time.time() * 1000)

    # Start building the event data dict.
    event_data: dict[str, Any] = {}

    # Apply field mappings.
    for field_map in parser.field_mappings:
        try:
            if field_map.jinja2_template:
                rendered = render_template(field_map.jinja2_template, groups)
            else:
                # Direct extraction: use the ocsf_field name as the group key.
                leaf = field_map.ocsf_field.split(".")[-1]
                rendered = groups.get(leaf, "")

            if rendered:
                value = _coerce_value(rendered, field_map.type)
                _set_nested(event_data, field_map.ocsf_field, value)
            elif field_map.default is not None:
                _set_nested(event_data, field_map.ocsf_field, field_map.default)
        except Exception as exc:
            logger.debug(
                "field_mapping_error",
                parser=parser.name,
                field=field_map.ocsf_field,
                error=str(exc),
            )

    # Apply static values from the parser definition.
    for key, val in parser.static_values.items():
        _set_nested(event_data, key, val)

    # Inject OCSF classification fields.
    event_data.setdefault("activity_id", 0)
    event_data.setdefault("category_uid", parser.ocsf_category_uid)
    event_data.setdefault("class_uid", parser.ocsf_class_uid)
    event_data["time"] = now_epoch_ms

    # Build metadata.
    event_data["metadata"] = {
        "version": "1.3.0",
        "product": {
            "name": parser.name,
            "vendor_name": parser.vendor,
            "version": parser.version,
        },
        "processed_time": now_epoch_ms,
    }

    # Forensic envelope — lossless preservation (§2).
    event_data["raw_data"] = raw_payload
    event_data["raw_data_hash"] = {
        "algorithm": "SHA-256",
        "algorithm_id": FingerprintAlgorithmId.SHA256,
        "value": raw_sha256,
    }
    event_data["raw_data_size"] = len(raw_payload.encode("utf-8"))

    # Collect unmapped capture groups for traceability (requirement d).
    mapped_fields = {fm.ocsf_field.split(".")[-1] for fm in parser.field_mappings}
    unmapped = {k: v for k, v in groups.items() if k not in mapped_fields and v}
    if unmapped:
        event_data["unmapped"] = unmapped

    # Select the correct OCSF event class.
    event_cls = _EVENT_CLASS_MAP.get(parser.ocsf_class, BaseEvent)

    # Validate and instantiate — this is where OCSF compliance is enforced.
    return event_cls.model_validate(event_data)
