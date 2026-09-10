"""Prometheus metrics registry for ULPF.

Tracks ingestion throughput, parsing success/failure, DLQ depth, and AI stats.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# Counters
ULPF_INGEST_TOTAL = Counter(
    "ulpf_ingest_total",
    "Total number of logs ingested",
)

ULPF_PARSE_SUCCESS_TOTAL = Counter(
    "ulpf_parse_success_total",
    "Total number of logs successfully parsed into OCSF",
    ["parser"]
)

ULPF_DLQ_TOTAL = Counter(
    "ulpf_dlq_total",
    "Total number of logs sent to the Dead Letter Queue",
    ["reason", "dlq_mode"]
)

# AI specific metrics
ULPF_AI_GENERATION_TOTAL = Counter(
    "ulpf_ai_generation_total",
    "Total number of AI parser generation attempts",
    ["model", "status"]
)

ULPF_AI_GENERATION_LATENCY = Histogram(
    "ulpf_ai_generation_latency_seconds",
    "Latency of AI parser generation requests",
    ["model"]
)

# Gauges
ULPF_QUEUE_DEPTH = Gauge(
    "ulpf_queue_depth",
    "Current number of items in the ingestion queue",
)

ULPF_DEDUP_TOTAL = Counter(
    "ulpf_dedup_total",
    "Total number of duplicate events skipped via SHA-256 dedup",
)

ULPF_OCSF_VALIDATION_FAIL = Counter(
    "ulpf_ocsf_validation_fail_total",
    "Total number of events that matched a parser but failed OCSF validation",
    ["parser"],
)
