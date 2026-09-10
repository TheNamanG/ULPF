# AGENTS.md — Universal Log Pre-processing Framework (ULPF)

> Project rules for any AI coding agent (Antigravity, Claude Code, Cursor, etc.)
> working in this repository. Read this in full before planning or writing any code.

## 1. Mission

Build the **Universal Log Pre-processing Framework (ULPF)** for **SIH26156**
(National Technical Research Organisation, Smart India Hackathon 2026): a
vendor-agnostic, lossless, high-throughput log ingestion pipeline that converts
heterogeneous perimeter logs into the standardized **OCSF (Open Cybersecurity
Schema Framework) v1.3** schema.

This is security-critical software written for a national technical
intelligence organisation's evaluation. Make every design decision the way a
Principal Cybersecurity Engineer preparing for an enterprise SOC production
deployment would — not the way a hackathon demo would. Correctness,
auditability, and defensibility under review matter more than speed of
delivery.

## 2. Non-negotiable architecture

- **Language/runtime:** Python 3.12+, `asyncio` + `uvloop` (guard the `uvloop`
  import/install — it does not support Windows).
- **Config & parsing:** Declarative YAML parser definitions + Jinja2
  templating — a zero-code parser registry. Onboarding a new vendor log
  format must never require writing Python.
- **Validation:** Pydantic v2, strict OCSF v1.3 models. An event is not
  "parsed" until it passes OCSF validation.
- **Lossless forensic envelope:** every parsed event carries the original
  `raw_payload` and a `raw_sha256` hash of those exact bytes. Never transform,
  truncate, or re-encode raw input before hashing — that breaks chain of
  custody.
- **Dead Letter Queue (DLQ):** any log that fails to match a parser, or fails
  OCSF validation, is dead-lettered — never dropped, never able to crash the
  pipeline.
- **Pluggable AI Auto-Parser (Strategy Pattern):** the DLQ handler is selected
  at runtime via `DLQ_MODE`:
  - `manual` — persist to disk + log a warning. No AI. This is the safe
    default.
  - `ollama` — send to a local Ollama instance (`OLLAMA_HOST`) for fully
    air-gapped parser generation.
  - `openai` — use `OPENAI_API_KEY` for teams without local GPU capacity.
- **Human-in-the-Loop (HITL) is mandatory and non-bypassable:** AI-drafted
  parsers are written to `parsers/pending/` and are never auto-loaded into the
  running pipeline. Only a human moving a file into `parsers/active/`
  activates it. Do not build any code path that skips this step.
- **Self-healing:** before a pending parser is saved, validate its YAML syntax
  and its schema (§4). On failure, feed the error back to the AI and retry,
  capped at 2 retries, then fall back to a plain DLQ write with the failure
  reason attached.

## 3. Security requirements — not optional polish

- **Treat every AI-drafted parser as untrusted, even after human approval.**
  The log data that triggers AI parser generation is attacker-influenced by
  definition — it's live perimeter traffic. A crafted log line that
  prompt-injects the LLM into emitting a malicious Jinja2 template is a
  realistic threat specific to this architecture.
  - Render all parser-authored Jinja2 templates through `SandboxedEnvironment`,
    never the default `Environment`.
  - Restrict available filters/globals to an explicit allow-list. Never expose
    `import`, file I/O, or arbitrary attribute access to template authors,
    human or AI.
  - Validate the parser **definition YAML itself** against a strict Pydantic
    schema (field names, types, allowed regex/Jinja2 constructs) before it is
    even written to `parsers/pending/` — don't validate only the OCSF
    *output* of running it.
- **Secrets never live in code or in committed files.** `OPENAI_API_KEY` and
  any other credential comes from the environment only. `.env` is gitignored;
  `.env.example` never contains a real value.
- **Bound every queue and every network read.** Unbounded queues and
  unbounded single-message reads are a memory-exhaustion DoS vector on a
  syslog listener facing untrusted network input. Enforce a max message size
  and a bounded, backpressured queue between ingestion and the parser engine;
  when full, shed load and increment a metric — never block indefinitely or
  let memory grow unbounded.
- **Rate/cost-guard the AI DLQ handlers.** `openai` mode needs a configurable
  max request rate and a circuit breaker: repeated AI-backend errors or
  timeouts must auto-fall-back to `manual` mode with a clear operator
  warning, not block the DLQ.
- **Tamper-evident promotion trail.** When a human promotes a file from
  `parsers/pending/` to `parsers/active/`, log who/when/which-file-hash to an
  append-only audit log — this is the chain-of-custody record for why a
  parser is trusted in production.

## 4. Data contracts

- OCSF Pydantic models live in `src/ulpf/core/`, pinned to OCSF **v1.3**.
- The YAML **parser-definition format** (what a human or the AI writes into
  `parsers/*/`) is itself a Pydantic model in `src/ulpf/parsers/schema.py`,
  validated on load — not "whatever loads as valid YAML."
- Every parser file carries `version`, `author` (`human` or `ai:<model>`), and
  `created_at` metadata for audit purposes.

## 5. Reliability requirements

- Graceful shutdown on `SIGTERM`/`SIGINT`: drain in-flight events before
  exit; a routine redeploy must not drop events mid-flight.
- Idempotency: dedupe on `raw_sha256` so a replayed or retried log isn't
  double-counted downstream.
- Degrade, don't crash: if disk is full (DLQ write fails) or the sink is
  unreachable, log/alert and shed load — a downstream outage must never take
  down ingestion.

## 6. Observability requirements

- Structured logging (`structlog`), JSON-formatted, with a correlation ID
  that follows a given raw log from ingestion → parse/DLQ → sink.
- Prometheus-style metrics on a `/metrics` endpoint: ingest EPS, parse
  success/failure rate, DLQ depth, AI-parser generation latency and success
  rate, per-parser hit counts.
- `/healthz` and `/readyz` HTTP endpoints — needed for container/orchestrator
  health checks even though Step 5 only asks for Docker Compose.

## 7. Testing requirements

- **Golden-file tests:** every parser in `parsers/active/` gets a fixture
  pair (`tests/fixtures/<vendor>.log` + expected OCSF JSON), run in CI, so an
  edited parser can't silently regress.
- **Lossless round-trip test:** assert `raw_payload` byte-equality and
  `raw_sha256` verification on every code path, including the DLQ and
  AI-repaired paths — this is the proof behind the "lossless" claim, not an
  assumption.
- **Fuzz/robustness test** on the syslog listener: malformed, truncated,
  oversized, and non-UTF-8 packets must never crash the process.
- Target ≥85% coverage on `src/ulpf/core/` and `src/ulpf/parsers/` — the
  correctness-critical layers.

## 8. Usability requirements — "zero-code" must actually mean zero-code

- Ship a CLI: `ulpf parser test <parser.yaml> <sample.log>` that runs one
  parser against one sample and prints the resulting OCSF JSON or the
  validation error. A SOC analyst must be able to iterate on a new parser
  without restarting the pipeline.
- Ship at least 3 working example parsers in `parsers/active/` (e.g. Linux
  `sshd`/auth.log, Cisco ASA, a generic RFC5424 fallback) so the system
  produces normalized output within minutes of first clone.
- `README.md` needs a "quick start" that goes from `git clone` to a visibly
  normalized event in under 10 commands.

## 9. Coding standards

- Full type hints, `mypy --strict` clean.
- Docstrings on every public function/class explaining *why*, not just
  *what*.
- `ruff` clean, 100-char line length.
- Keep the Strategy Pattern boundary real: a new DLQ provider is a new class
  implementing `BaseDLQHandler`, with zero changes to the factory's call
  sites.

## 10. Working agreement for the agent

- Follow `task.md` in phase order — Step 2 depends on Step 1's config module,
  Step 3 depends on Step 2's event shape, and so on. Don't parallelize across
  phases; parallelize *within* a phase only where there's no shared-state
  conflict.
- Keep subtasks small (aim for ≤1 hour of agent work each) so plan review and
  diff review stay meaningful.
- If a requirement here is ambiguous, or a decision has real security
  implications (sandboxing approach, secrets handling, anything in §3), stop
  and ask rather than guessing.
- After finishing a phase: run the full test suite, report pass/fail, and
  wait for explicit go-ahead before starting the next phase.
