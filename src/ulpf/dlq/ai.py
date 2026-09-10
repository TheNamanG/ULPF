"""AI DLQ handlers for automatic parser generation."""

from __future__ import annotations

import re
import time
from pathlib import Path

import structlog
import yaml
from pydantic import ValidationError

from ulpf.dlq.ai_clients import (
    AICircuitBreakerTripped,
    AIClientConfig,
    BaseAIClient,
    OllamaClient,
    OpenAIClient,
)
from ulpf.dlq.base import BaseDLQHandler
from ulpf.metrics import ULPF_AI_GENERATION_LATENCY, ULPF_AI_GENERATION_TOTAL
from ulpf.parsers.schema import ParserDefinition

logger = structlog.get_logger(__name__)

# Basic system prompt instructing the AI how to write a valid parser.
_SYSTEM_PROMPT = """You are an expert SOC engineer configuring a log pipeline.
Your task is to write a YAML parser definition for a given raw log.
The output MUST be exactly valid YAML adhering to our schema.
Do NOT output markdown blocks, explanations, or any text other than the YAML.
The YAML must conform to the following rules:
- `name`: string, a short unique identifier for this log type.
- `version`: string (SemVer), e.g., "1.0.0".
- `author`: string. You MUST set this to "ai:{{model}}".
- `created_at`: ISO8601 UTC string (use current time).
- `vendor`: string, guess the vendor or "unknown".
- `log_format`: string, e.g. "syslog", "json", "csv".
- `match_patterns`: list of strings (regexes). MUST contain named capture groups like `(?P<ip>.+)`.
- `ocsf_class`: string, one of "base_event", "authentication", "network_activity".
- `ocsf_category_uid`: int, typically 0, 3, or 4.
- `ocsf_class_uid`: int, typically 0, 3002, or 4001.
- `field_mappings`: list of objects, each containing:
    - `ocsf_field`: string, dot-notation path in OCSF.
    - `type`: one of "str", "int", "float", "bool".
    - `jinja2_template`: (optional) string, a jinja2 template for transformation.

Extract meaningful fields like IPs, usernames, status codes into proper OCSF fields.
"""


class AIDLQHandler(BaseDLQHandler):
    """Abstract DLQ handler that uses an AI client to generate parsers.
    
    Implements the 2-retry self-healing loop:
    1. Ask AI to generate parser.
    2. Try to validate it with ParserDefinition.
    3. If invalid, pass the Pydantic error back to AI and retry.
    4. If valid, save to `parsers/pending/<sha256>.yaml` for human review.
    5. If all retries fail, fallback to Manual DLQ.
    """
    def __init__(self, client: BaseAIClient, pending_dir: Path, fallback_handler: BaseDLQHandler) -> None:
        self.client = client
        self.pending_dir = pending_dir
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.fallback_handler = fallback_handler

    def _extract_yaml(self, response: str) -> str:
        """Strip markdown formatting if the LLM ignores instructions."""
        # Remove markdown code blocks if present
        m = re.search(r"```(?:yaml)?\n(.*?)\n```", response, re.DOTALL)
        if m:
            return m.group(1).strip()
        return response.strip()

    async def handle(self, raw_payload: str, raw_sha256: str, error_reason: str) -> None:
        user_prompt = f"Raw Log:\n{raw_payload}\nError Reason: {error_reason}\nPlease output the YAML parser definition."
        system_prompt = _SYSTEM_PROMPT.replace("{{model}}", self.client.config.model)

        last_error = ""

        for attempt in range(self.client.config.max_retries + 1):
            try:
                if attempt > 0:
                    user_prompt += f"\nYour last attempt failed validation:\n{last_error}\nPlease fix the YAML."

                start_time = time.time()
                response_text = await self.client.generate_parser(system_prompt, user_prompt)
                latency = time.time() - start_time
                ULPF_AI_GENERATION_LATENCY.labels(model=self.client.config.model).observe(latency)

                yaml_text = self._extract_yaml(response_text)

                # Attempt to parse
                data = yaml.safe_load(yaml_text)
                if not isinstance(data, dict):
                    last_error = "The output was not a YAML dictionary."
                    continue

                # Validate against strict schema
                parser_def = ParserDefinition.model_validate(data)

                # Success! Write to pending directory for HITL (Human in the loop)
                dest_file = self.pending_dir / f"{raw_sha256}.yaml"
                dest_file.write_text(yaml_text, encoding="utf-8")

                logger.info(
                    "ai_parser_generated",
                    raw_sha256=raw_sha256,
                    parser_name=parser_def.name,
                    attempts=attempt + 1,
                    dest=str(dest_file),
                )
                ULPF_AI_GENERATION_TOTAL.labels(model=self.client.config.model, status="success").inc()
                return

            except yaml.YAMLError as exc:
                last_error = f"YAML Syntax Error: {exc}"
            except ValidationError as exc:
                last_error = f"Schema Validation Error:\n{exc}"
            except AICircuitBreakerTripped:
                logger.warning("ai_circuit_breaker_tripped_falling_back", raw_sha256=raw_sha256)
                break  # Exit loop immediately to fallback
            except Exception as exc:
                logger.error("ai_generation_unexpected_error", error=str(exc))
                last_error = f"Unexpected Error: {exc}"

            ULPF_AI_GENERATION_TOTAL.labels(model=self.client.config.model, status="error").inc()

        # If we exhausted retries or circuit breaker tripped, fallback
        logger.warning(
            "ai_parser_generation_failed",
            raw_sha256=raw_sha256,
            last_error=last_error,
        )
        await self.fallback_handler.handle(raw_payload, raw_sha256, f"AI generation failed: {last_error}")


class OllamaDLQHandler(AIDLQHandler):
    """Ollama implementation of the AI DLQ handler."""
    def __init__(self, config: AIClientConfig, pending_dir: Path, fallback_handler: BaseDLQHandler) -> None:
        client = OllamaClient(config)
        super().__init__(client, pending_dir, fallback_handler)


class OpenAIDLQHandler(AIDLQHandler):
    """OpenAI implementation of the AI DLQ handler."""
    def __init__(self, config: AIClientConfig, pending_dir: Path, fallback_handler: BaseDLQHandler) -> None:
        client = OpenAIClient(config)
        super().__init__(client, pending_dir, fallback_handler)
