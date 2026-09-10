from pathlib import Path
from click.testing import CliRunner

from ulpf.cli import cli


def test_cli_parser_test_success(tmp_path: Path) -> None:
    parser_yaml = tmp_path / "test.yaml"
    parser_yaml.write_text("""
name: dummy
version: 1.0.0
author: human
created_at: "2026-09-06T00:00:00Z"
vendor: unknown
log_format: json
match_patterns:
  - "(?P<msg>.+)"
ocsf_class: base_event
ocsf_category_uid: 0
ocsf_class_uid: 0
field_mappings: []
    """)

    sample = tmp_path / "sample.log"
    sample.write_text("hello world")

    runner = CliRunner()
    result = runner.invoke(cli, ["parser", "test", str(parser_yaml), str(sample)])

    assert result.exit_code == 0
    assert "Match found using pattern: (?P<msg>.+)" in result.output
    assert "hello world" in result.output

def test_cli_parser_test_failure(tmp_path: Path) -> None:
    parser_yaml = tmp_path / "test.yaml"
    parser_yaml.write_text("""
name: dummy
version: 1.0.0
author: human
created_at: "2026-09-06T00:00:00Z"
vendor: unknown
log_format: json
match_patterns:
  - "^(?P<msg>unmatchable)$"
ocsf_class: base_event
ocsf_category_uid: 0
ocsf_class_uid: 0
field_mappings: []
    """)

    sample = tmp_path / "sample.log"
    sample.write_text("hello world")

    runner = CliRunner()
    result = runner.invoke(cli, ["parser", "test", str(parser_yaml), str(sample)])

    assert result.exit_code == 1
    assert "No match found" in result.output

def test_cli_parser_validation_failure(tmp_path: Path) -> None:
    parser_yaml = tmp_path / "test.yaml"
    parser_yaml.write_text("bad: yaml:")

    sample = tmp_path / "sample.log"
    sample.write_text("hello world")

    runner = CliRunner()
    result = runner.invoke(cli, ["parser", "test", str(parser_yaml), str(sample)])

    assert result.exit_code == 1
    assert "Parser validation failed" in result.output
