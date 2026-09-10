"""Tests for the parser file loader."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from ulpf.parsers.loader import ParserValidationError, load_active_parsers, load_parser

if TYPE_CHECKING:
    from pathlib import Path


class TestLoadParser:
    """Verify single parser file loading and validation."""

    def test_load_valid_parser(self, parsers_active_dir: Path) -> None:
        """Each shipped parser should load without errors."""
        linux_sshd = parsers_active_dir / "linux_sshd.yaml"
        if linux_sshd.exists():
            parser = load_parser(linux_sshd)
            assert parser.name == "linux_sshd"
            assert parser.version == "1.0.0"
            assert parser.author == "human"

    def test_load_cisco_asa_parser(self, parsers_active_dir: Path) -> None:
        cisco_asa = parsers_active_dir / "cisco_asa.yaml"
        if cisco_asa.exists():
            parser = load_parser(cisco_asa)
            assert parser.name == "cisco_asa"
            assert parser.ocsf_class_uid == 4001

    def test_load_rfc5424_parser(self, parsers_active_dir: Path) -> None:
        rfc5424 = parsers_active_dir / "rfc5424_fallback.yaml"
        if rfc5424.exists():
            parser = load_parser(rfc5424)
            assert parser.name == "rfc5424_fallback"
            assert parser.match_priority == 999

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        """Malformed YAML should raise ParserValidationError."""
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("{{{{invalid yaml", encoding="utf-8")
        try:
            load_parser(bad_file)
            assert False, "Should have raised"  # noqa: B011
        except ParserValidationError:
            pass

    def test_missing_fields_raises(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "bad.yaml"
        yaml_path.write_text("name: missing_fields", encoding="utf-8")
        with pytest.raises(ParserValidationError):
            load_parser(yaml_path)

    def test_not_a_dict_raises(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "bad.yaml"
        yaml_path.write_text("- item1\n- item2", encoding="utf-8")
        with pytest.raises(ParserValidationError):
            load_parser(yaml_path)


class TestLoadActiveParsers:
    """Verify active parsers directory scanning."""

    def test_loads_all_shipped_parsers(self, parsers_active_dir: Path) -> None:
        """All 3 shipped parsers should load successfully."""
        if parsers_active_dir.exists():
            parsers = load_active_parsers(parsers_active_dir)
            assert len(parsers) >= 3
            names = {p.name for p in parsers}
            assert "linux_sshd" in names
            assert "cisco_asa" in names
            assert "rfc5424_fallback" in names

    def test_sorted_by_priority(self, parsers_active_dir: Path) -> None:
        """Parsers should be sorted by match_priority ascending."""
        if parsers_active_dir.exists():
            parsers = load_active_parsers(parsers_active_dir)
            priorities = [p.match_priority for p in parsers]
            assert priorities == sorted(priorities)

    def test_rfc5424_is_last(self, parsers_active_dir: Path) -> None:
        """The RFC5424 fallback (priority 999) should be tried last."""
        if parsers_active_dir.exists():
            parsers = load_active_parsers(parsers_active_dir)
            assert parsers[-1].name == "rfc5424_fallback"

    def test_missing_dir_returns_empty(self, tmp_path: Path) -> None:
        """A missing directory should return empty list, not crash."""
        parsers = load_active_parsers(tmp_path / "nonexistent")
        assert parsers == []

    def test_invalid_file_skipped_gracefully(self, tmp_path: Path) -> None:
        # Create a valid parser
        valid_yaml = tmp_path / "valid.yaml"
        valid_yaml.write_text(
            """
name: rfc5424_fallback
version: "1.0.0"
author: human
created_at: "2026-09-06T00:00:00Z"
vendor: generic
log_format: rfc5424
match_priority: 999
match_patterns:
  - "(?P<msg>.+)"
ocsf_class: base_event
ocsf_category_uid: 0
ocsf_class_uid: 0
field_mappings:
  - ocsf_field: message
    type: str
""",
            encoding="utf-8",
        )
        # Create an invalid parser
        invalid_yaml = tmp_path / "invalid.yaml"
        invalid_yaml.write_text("not: valid: parser:", encoding="utf-8")

        parsers = load_active_parsers(tmp_path)
        assert len(parsers) == 1
        assert parsers[0].name == "rfc5424_fallback"

    def test_no_yaml_files_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "not_yaml.txt").write_text("test", encoding="utf-8")
        assert len(load_active_parsers(tmp_path)) == 0

    def test_unexpected_error_skipped_gracefully(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        valid_yaml = tmp_path / "valid.yaml"
        valid_yaml.write_text("name: test", encoding="utf-8")

        def mock_load_parser(path: Path) -> None:
            raise RuntimeError("Unexpected boom!")

        import ulpf.parsers.loader
        monkeypatch.setattr(ulpf.parsers.loader, "load_parser", mock_load_parser)

        parsers = load_active_parsers(tmp_path)
        assert len(parsers) == 0
