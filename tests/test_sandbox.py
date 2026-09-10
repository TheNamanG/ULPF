"""Tests for the hardened Jinja2 sandbox.

These tests verify that the sandbox (§3) correctly:
1. Renders safe templates.
2. Blocks SSTI (Server-Side Template Injection) payloads.
3. Restricts available filters to the allow-list.
4. Prevents access to dangerous attributes and builtins.
"""

from __future__ import annotations

import pytest
from jinja2.exceptions import SecurityError, TemplateAssertionError

from ulpf.parsers.sandbox import render_template


class TestSafeTemplateRendering:
    """Verify that legitimate parser templates render correctly."""

    def test_simple_variable_substitution(self) -> None:
        result = render_template("{{ name }}", {"name": "test"})
        assert result == "test"

    def test_filter_lower(self) -> None:
        result = render_template("{{ val | lower }}", {"val": "HELLO"})
        assert result == "hello"

    def test_filter_upper(self) -> None:
        result = render_template("{{ val | upper }}", {"val": "hello"})
        assert result == "HELLO"

    def test_filter_default(self) -> None:
        result = render_template("{{ missing | default('fallback') }}", {})
        assert result == "fallback"

    def test_filter_replace(self) -> None:
        result = render_template("{{ val | replace('a', 'b') }}", {"val": "aaa"})
        assert result == "bbb"

    def test_filter_int(self) -> None:
        result = render_template("{{ val | int }}", {"val": "42"})
        assert result == "42"

    def test_filter_strip(self) -> None:
        result = render_template("{{ val | trim }}", {"val": "  hello  "})
        assert result == "hello"

    def test_filter_split_join(self) -> None:
        result = render_template("{{ val | split(',') | join(';') }}", {"val": "a,b,c"})
        assert result == "a;b;c"

    def test_filter_regex_replace(self) -> None:
        result = render_template("{{ val | regex_replace('b+', 'd') }}", {"val": "abbc"})
        assert result == "adc"

    def test_conditional(self) -> None:
        result = render_template(
            "{% if status == 'ok' %}success{% else %}failure{% endif %}",
            {"status": "ok"},
        )
        assert result == "success"

    def test_arithmetic(self) -> None:
        result = render_template("{{ (pri | int) // 8 }}", {"pri": "134"})
        assert result == "16"

    def test_string_concatenation(self) -> None:
        result = render_template("{{ a ~ ':' ~ b }}", {"a": "host", "b": "22"})
        assert result == "host:22"


class TestSSTIPayloadsBlocked:
    """Verify that known SSTI attack vectors are blocked.

    The SandboxedEnvironment has two defense mechanisms:
    1. is_safe_attribute returns False → attribute resolves to Undefined (renders empty).
    2. Unsafe callable access → raises SecurityError.
    Both prevent exploitation. Tests verify the payload does NOT execute.
    """

    def test_class_access_blocked(self) -> None:
        """__class__ access should be blocked — renders empty, no real class info."""
        result = render_template("{{ ''.__class__ }}", {})
        # Must NOT contain the actual class name
        assert "str" not in result.lower()

    def test_subclasses_chain_blocked(self) -> None:
        """Multi-level SSTI chain must not leak class hierarchy."""
        # This should either raise SecurityError or render empty
        try:
            result = render_template("{{ ''.__class__.__subclasses__() }}", {})
            # If it didn't raise, it must have rendered empty/Undefined
            assert "class" not in result.lower()
        except SecurityError:
            pass  # Also acceptable — blocked at method call level

    def test_globals_chain_blocked(self) -> None:
        try:
            result = render_template("{{ ''.__class__.__init__.__globals__ }}", {})
            assert "__builtins__" not in result
        except SecurityError:
            pass

    def test_builtins_chain_blocked(self) -> None:
        try:
            result = render_template(
                "{{ ''.__class__.__init__.__globals__['__builtins__'] }}", {}
            )
            assert "import" not in result.lower()
        except SecurityError:
            pass

    def test_mro_chain_blocked(self) -> None:
        try:
            result = render_template("{{ ''.__class__.mro() }}", {})
            assert "object" not in result.lower()
        except SecurityError:
            pass

    def test_import_chain_blocked(self) -> None:
        """Direct __import__ calls must be blocked."""
        try:
            result = render_template(
                "{{ ''.__class__.__init__.__globals__['__builtins__']['__import__']('os') }}", {}
            )
            assert "module" not in result.lower()
        except SecurityError:
            pass

    def test_config_access_blocked(self) -> None:
        """config object (Flask SSTI vector) must not be in globals."""
        result = render_template("{{ config }}", {})
        assert "Config" not in result

    def test_underscore_attribute_blocked(self) -> None:
        """Any attribute starting with _ should be blocked (renders empty)."""
        result = render_template("{{ ''._formatter_parser }}", {})
        # Must not contain any real data — blocked by is_safe_attribute
        assert "formatter" not in result.lower()

    def test_lipsum_not_available(self) -> None:
        """lipsum (a common Jinja2 global) must not be available."""
        result = render_template("{{ lipsum }}", {})
        assert result == ""

    def test_cycler_not_available(self) -> None:
        """cycler (a common Jinja2 global) must not be available."""
        result = render_template("{{ cycler }}", {})
        assert result == ""

    def test_joiner_not_available(self) -> None:
        """joiner (a common Jinja2 global) must not be available."""
        result = render_template("{{ joiner }}", {})
        assert result == ""

    def test_namespace_not_available(self) -> None:
        """namespace must not be available."""
        result = render_template("{{ namespace }}", {})
        assert result == ""

    def test_safe_attribute_access_allowed(self) -> None:
        """Safe attribute access should be allowed and return correctly."""
        class SafeObj:
            safe_val = "hello"

        result = render_template("{{ obj.safe_val }}", {"obj": SafeObj()})
        assert result == "hello"


class TestFilterRestrictions:
    """Verify that only allow-listed filters are available."""

    def test_attr_filter_not_available(self) -> None:
        """The 'attr' filter enables attribute access SSTI bypasses."""
        with pytest.raises(TemplateAssertionError):
            render_template("{{ ''|attr('__class__') }}", {})

    def test_format_filter_not_available(self) -> None:
        """The 'format' filter can be used for SSTI in some contexts."""
        # 'format' is not in our allow-list
        with pytest.raises(TemplateAssertionError):
            render_template("{{ '%s'|format('test') }}", {})

    def test_allowed_filter_works(self) -> None:
        """Sanity check: an allow-listed filter should work."""
        result = render_template("{{ 'hello' | capitalize }}", {})
        assert result == "Hello"
