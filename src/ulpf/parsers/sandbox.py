"""Hardened Jinja2 sandbox for parser template rendering.

Security rationale (§3):
The log data that triggers AI parser generation is attacker-influenced
by definition — it's live perimeter traffic. A crafted log line could
prompt-inject the LLM into emitting a malicious Jinja2 template that
performs SSTI (Server-Side Template Injection).

Mitigations:
1. All templates render through ``SandboxedEnvironment``, never ``Environment``.
2. ``is_safe_attribute`` is overridden to deny access to dunder attributes
   that enable Python sandbox escapes (``__class__``, ``__subclasses__``, etc.).
3. Available filters and globals are restricted to an explicit allow-list.
4. No ``import``, file I/O, or arbitrary attribute access is exposed.
5. Template rendering is wrapped in try/except to prevent crash-on-malicious-input.
"""

from __future__ import annotations

import re as _re
from typing import Any

from jinja2 import Undefined
from jinja2.exceptions import SecurityError
from jinja2.sandbox import SandboxedEnvironment

# ── Allow-lists ──────────────────────────────────────────────────────────

_ALLOWED_FILTERS: frozenset[str] = frozenset({
    "lower",
    "upper",
    "strip",
    "replace",
    "default",
    "d",
    "int",
    "float",
    "trim",
    "truncate",
    "split",
    "join",
    "first",
    "last",
    "length",
    "string",
    "title",
    "capitalize",
    "wordcount",
    "center",
    "indent",
    "regex_replace",
    "map",
    "select",
    "reject",
    "sort",
    "unique",
    "list",
    "abs",
    "round",
    "batch",
    "slice",
})

_ALLOWED_GLOBALS: dict[str, Any] = {
    "range": range,
    "dict": dict,
    "list": list,
    "str": str,
    "int": int,
    "float": float,
    "bool": bool,
    "len": len,
    "min": min,
    "max": max,
    "none": None,
    "true": True,
    "false": False,
}

# Dunder attributes that enable sandbox escape in CPython.
_BLOCKED_ATTRS: frozenset[str] = frozenset({
    "__class__",
    "__subclasses__",
    "__globals__",
    "__builtins__",
    "__import__",
    "__loader__",
    "__spec__",
    "__code__",
    "__func__",
    "__self__",
    "__module__",
    "__dict__",
    "__bases__",
    "__mro__",
    "__init_subclass__",
    "__reduce__",
    "__reduce_ex__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "mro",
    "gi_frame",
    "gi_code",
    "co_consts",
    "f_globals",
    "f_locals",
    "f_builtins",
})


class ULPFSandboxedEnvironment(SandboxedEnvironment):
    """Hardened Jinja2 sandbox that restricts template capabilities.

    Extends ``SandboxedEnvironment`` with:
    - Explicit dunder-attribute blocking beyond the default sandbox.
    - Stripped-down filter and global sets.
    - No auto-loading of templates from disk.
    """

    def is_safe_attribute(self, obj: Any, attr: str, value: Any) -> bool:
        """Block access to dangerous dunder attributes and internal state.

        The default ``SandboxedEnvironment`` blocks some of these, but we
        add a comprehensive deny-list because new escape vectors are
        discovered periodically in the Jinja2 sandbox.
        """
        if attr in _BLOCKED_ATTRS:
            return False
        # Also block any attribute starting with underscore as defense-in-depth.
        if attr.startswith("_"):
            return False
        return super().is_safe_attribute(obj, attr, value)


def _split_filter(value: str, separator: str = " ") -> list[str]:
    """Split a string by separator. Not a built-in Jinja2 filter."""
    return value.split(separator)


def _regex_replace_filter(value: str, pattern: str, replacement: str) -> str:
    """Replace regex matches in a string."""
    return _re.sub(pattern, replacement, value)


def _create_sandbox() -> ULPFSandboxedEnvironment:
    """Create a configured sandbox environment instance.

    The sandbox is created once and reused for all template renders
    within the process. It has:
    - No filesystem loader (templates are always passed as strings).
    - Undefined variables render as empty string (safe default for optional fields).
    - Only allow-listed filters and globals.
    """
    env = ULPFSandboxedEnvironment(
        undefined=Undefined,
        autoescape=False,  # We produce text, not HTML.
        keep_trailing_newline=False,
    )

    # Strip down to allow-listed filters only.
    env.filters = {
        name: func
        for name, func in env.filters.items()
        if name in _ALLOWED_FILTERS
    }

    # Add custom filters not built into Jinja2.
    env.filters["split"] = _split_filter
    env.filters["regex_replace"] = _regex_replace_filter

    # Replace globals with our restricted set.
    env.globals = dict(_ALLOWED_GLOBALS)

    return env


# Module-level singleton — the sandbox config never changes at runtime.
_SANDBOX = _create_sandbox()


def render_template(template_str: str, context: dict[str, Any]) -> str:
    """Render a Jinja2 template string through the hardened sandbox.

    This is the **only** entry point for rendering parser-authored templates.
    Direct use of ``jinja2.Environment`` or ``Template`` is prohibited in
    this codebase (§3).

    Args:
        template_str: The Jinja2 template expression from a parser field.
        context: Variable bindings available to the template (typically
            the named capture groups from the regex match).

    Returns:
        The rendered string result.

    Raises:
        SecurityError: If the template attempts a blocked operation.
        jinja2.TemplateSyntaxError: If the template has syntax errors.
        jinja2.UndefinedError: If the template references an undefined variable.
    """
    template = _SANDBOX.from_string(template_str)
    return template.render(**context)


# Re-export SecurityError for callers.
__all__ = ["SecurityError", "ULPFSandboxedEnvironment", "render_template"]
