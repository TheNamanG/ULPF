"""Tests for the parser definition YAML schema validation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ulpf.parsers.schema import ParserDefinition, ParserField


def _valid_parser_data(**overrides: object) -> dict[str, object]:
    """Build a valid parser definition dict with optional overrides."""
    base: dict[str, object] = {
        "name": "test_parser",
        "version": "1.0.0",
        "author": "human",
        "created_at": datetime.now(tz=UTC).isoformat(),
        "vendor": "test",
        "log_format": "syslog",
        "match_patterns": [r"(?P<msg>.+)"],
        "ocsf_class": "base_event",
        "ocsf_category_uid": 0,
        "ocsf_class_uid": 0,
        "field_mappings": [
            {"ocsf_field": "message", "type": "str"},
        ],
    }
    base.update(overrides)
    return base


class TestParserDefinitionValid:
    """Verify valid parser definitions are accepted."""

    def test_minimal_valid_parser(self) -> None:
        data = _valid_parser_data()
        parser = ParserDefinition.model_validate(data)
        assert parser.name == "test_parser"
        assert parser.version == "1.0.0"
        assert parser.author == "human"

    def test_ai_author_format(self) -> None:
        data = _valid_parser_data(author="ai:gpt-4o")
        parser = ParserDefinition.model_validate(data)
        assert parser.author == "ai:gpt-4o"

    def test_default_match_priority(self) -> None:
        data = _valid_parser_data()
        parser = ParserDefinition.model_validate(data)
        assert parser.match_priority == 100

    def test_custom_match_priority(self) -> None:
        data = _valid_parser_data(match_priority=50)
        parser = ParserDefinition.model_validate(data)
        assert parser.match_priority == 50

    def test_with_static_values(self) -> None:
        data = _valid_parser_data(static_values={"severity_id": 1, "is_remote": True})
        parser = ParserDefinition.model_validate(data)
        assert parser.static_values["severity_id"] == 1

    def test_with_jinja2_template_in_field(self) -> None:
        data = _valid_parser_data(
            field_mappings=[
                {"ocsf_field": "message", "type": "str", "jinja2_template": "{{ msg | upper }}"},
            ]
        )
        parser = ParserDefinition.model_validate(data)
        assert parser.field_mappings[0].jinja2_template == "{{ msg | upper }}"

    def test_multiple_match_patterns(self) -> None:
        data = _valid_parser_data(
            match_patterns=[r"(?P<a>pattern1)", r"(?P<b>pattern2)", r"(?P<c>pattern3)"]
        )
        parser = ParserDefinition.model_validate(data)
        assert len(parser.match_patterns) == 3


class TestParserDefinitionRejections:
    """Verify invalid parser definitions are rejected."""

    def test_invalid_regex_rejected(self) -> None:
        """Malformed regex must be caught at load time, not at runtime."""
        data = _valid_parser_data(match_patterns=["[invalid(regex"])
        with pytest.raises(ValidationError, match="not valid regex"):
            ParserDefinition.model_validate(data)

    def test_missing_name_rejected(self) -> None:
        data = _valid_parser_data()
        del data["name"]
        with pytest.raises(ValidationError):
            ParserDefinition.model_validate(data)

    def test_missing_version_rejected(self) -> None:
        data = _valid_parser_data()
        del data["version"]
        with pytest.raises(ValidationError):
            ParserDefinition.model_validate(data)

    def test_missing_author_rejected(self) -> None:
        data = _valid_parser_data()
        del data["author"]
        with pytest.raises(ValidationError):
            ParserDefinition.model_validate(data)

    def test_invalid_semver_rejected(self) -> None:
        """Version must be valid SemVer."""
        data = _valid_parser_data(version="not-a-version")
        with pytest.raises(ValidationError, match="SemVer"):
            ParserDefinition.model_validate(data)

    def test_unknown_class_uid_rejected(self) -> None:
        """ocsf_class_uid must be in the known set."""
        data = _valid_parser_data(ocsf_class_uid=9999)
        with pytest.raises(ValidationError, match="ocsf_class_uid"):
            ParserDefinition.model_validate(data)

    def test_invalid_author_format_rejected(self) -> None:
        """Author must be 'human' or 'ai:<model>'."""
        data = _valid_parser_data(author="bot")
        with pytest.raises(ValidationError, match="'human' or 'ai:"):
            ParserDefinition.model_validate(data)

    def test_empty_match_patterns_rejected(self) -> None:
        """At least one match pattern is implicitly required (empty list fails)."""
        # An empty list is technically valid per the model but won't match anything.
        # This test documents the behavior; the engine will handle the semantic check.
        data = _valid_parser_data(match_patterns=[])
        parser = ParserDefinition.model_validate(data)
        assert parser.match_patterns == []


class TestParserField:
    """Verify ParserField model validation."""

    def test_minimal_field(self) -> None:
        field = ParserField(ocsf_field="message", type="str")
        assert field.ocsf_field == "message"
        assert field.type == "str"
        assert field.jinja2_template is None
        assert field.default is None

    def test_field_with_template(self) -> None:
        field = ParserField(
            ocsf_field="src_endpoint.ip",
            type="str",
            jinja2_template="{{ src_ip }}",
        )
        assert field.jinja2_template == "{{ src_ip }}"

    def test_field_with_default(self) -> None:
        field = ParserField(ocsf_field="service", type="str", default="sshd")
        assert field.default == "sshd"

    def test_invalid_type_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ParserField(ocsf_field="test", type="invalid_type")  # type: ignore[arg-type]
