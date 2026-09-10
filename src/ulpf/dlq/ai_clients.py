"""Asynchronous HTTP clients for AI backends (Ollama and OpenAI)."""

from __future__ import annotations

import aiohttp
import structlog
from pydantic import BaseModel

logger = structlog.get_logger(__name__)


class AICircuitBreakerTripped(Exception):
    """Raised when the AI client fails repeatedly and trips the circuit breaker."""
    pass


class AIClientError(Exception):
    """Raised when an individual AI request fails."""
    pass


class AIClientConfig(BaseModel):
    """Configuration for an AI client."""
    base_url: str
    api_key: str | None = None
    model: str
    max_retries: int = 2
    timeout_seconds: int = 15
    circuit_breaker_threshold: int = 5


class BaseAIClient:
    """Base class for AI HTTP clients with circuit breaker logic."""
    def __init__(self, config: AIClientConfig) -> None:
        self.config = config
        self._consecutive_failures = 0
        self._circuit_open = False

    def _record_success(self) -> None:
        self._consecutive_failures = 0
        if self._circuit_open:
            logger.info("ai_circuit_breaker_closed", model=self.config.model)
            self._circuit_open = False

    def _record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.config.circuit_breaker_threshold:
            if not self._circuit_open:
                logger.error(
                    "ai_circuit_breaker_tripped",
                    model=self.config.model,
                    failures=self._consecutive_failures,
                )
                self._circuit_open = True

    def check_circuit(self) -> None:
        """Check if the circuit is open. Raises AICircuitBreakerTripped if so."""
        if self._circuit_open:
            raise AICircuitBreakerTripped("AI backend circuit breaker is open.")

    async def generate_parser(self, system_prompt: str, user_prompt: str) -> str:
        """Generate a parser. Must be implemented by subclasses."""
        raise NotImplementedError


class OpenAIClient(BaseAIClient):
    """Client for OpenAI's Chat Completions API."""

    async def generate_parser(self, system_prompt: str, user_prompt: str) -> str:
        self.check_circuit()
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.0,
        }

        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session, session.post(
                f"{self.config.base_url.rstrip('/')}/v1/chat/completions",
                headers=headers,
                json=payload,
            ) as resp:
                if resp.status != 200:
                    err_text = await resp.text()
                    raise AIClientError(f"OpenAI error {resp.status}: {err_text}")
                data = await resp.json()
                content = data["choices"][0]["message"]["content"]
                self._record_success()
                return str(content)
        except Exception as exc:
            self._record_failure()
            raise AIClientError(f"Failed to generate from OpenAI: {exc}") from exc


class OllamaClient(BaseAIClient):
    """Client for Ollama's Chat API."""

    async def generate_parser(self, system_prompt: str, user_prompt: str) -> str:
        self.check_circuit()
        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "temperature": 0.0,
            }
        }

        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session, session.post(
                f"{self.config.base_url.rstrip('/')}/api/chat",
                json=payload,
            ) as resp:
                if resp.status != 200:
                    err_text = await resp.text()
                    raise AIClientError(f"Ollama error {resp.status}: {err_text}")
                data = await resp.json()
                content = data["message"]["content"]
                self._record_success()
                return str(content)
        except Exception as exc:
            self._record_failure()
            raise AIClientError(f"Failed to generate from Ollama: {exc}") from exc
