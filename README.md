# Universal Log Pre-processing Framework (ULPF)

**Mission:** A vendor-agnostic, lossless, high-throughput log ingestion pipeline that converts heterogeneous perimeter logs into the standardized OCSF v1.3 schema. Developed for SIH26156.

## Features
- **Zero-Code Parsers:** Add new log formats instantly using YAML and Jinja2.
- **AI Auto-Parsing:** Unmatched logs are routed to an LLM (Ollama/OpenAI) that drafts new YAML parsers automatically.
- **Lossless Forensics:** Every event carries a cryptographic `raw_sha256` hash of the exact original bytes.
- **Robust Ingestion:** Asynchronous UDP Syslog listener with backpressured queues and multi-worker pools.
- **Pluggable Sinks:** Output to JSONL files (Data Lake ready) or stdout.

## 🚀 Quick Start (Docker)

The easiest way to run the entire ULPF pipeline and the interactive dashboard is via Docker Compose.

1. **Clone the repository:**
   ```bash
   git clone <repository_url>
   cd "SIH 2026"
   ```

2. **Start the stack:**
   ```bash
   docker compose up -d
   ```

3. **Verify it's running:**
   - **Dashboard:** Open `http://localhost:8888` in your browser.
   - **Metrics:** Open `http://localhost:8080/metrics`

4. **Test Live Ingestion:**
   Send a test syslog message to the UDP listener:
   ```bash
   echo "sample unparsed log message" | nc -u -w1 127.0.0.1 5140
   ```
   Check the dashboard to see it appear in the stream (likely tagged as DLQ until a parser is written).

## 🛠️ Manual Setup (Python Native)

If you prefer to run natively without Docker:

1. **Set up the virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

2. **Install ULPF:**
   ```bash
   pip install -e .
   ```

3. **Run the pipeline:**
   ```bash
   python -m ulpf.pipeline
   ```

4. **Test the CLI (Offline Parsing):**
   ```bash
   echo "sample log" > sample.log
   ulpf parser test parsers/active/rfc5424_fallback.yaml sample.log
   ```

## ⚙️ Configuration Reference

ULPF is entirely driven by environment variables (or a `.env` file in the root directory).

| Variable | Default | Description |
|:---------|:--------|:------------|
| `ULPF_LISTEN_PORT` | `514` | UDP port for syslog ingestion (5140 in docker). |
| `ULPF_DLQ_MODE` | `manual` | Strategy for unmatched logs: `manual`, `ollama`, or `openai`. |
| `ULPF_SINK_MODE` | `jsonl` | Output destination: `stdout` or `jsonl`. |
| `ULPF_WORKER_COUNT` | `4` | Number of concurrent async workers. |
| `ULPF_OLLAMA_HOST` | `http://localhost:11434` | URL to local Ollama instance (Air-gapped AI). |
| `ULPF_OPENAI_API_KEY` | `None` | Required if DLQ_MODE is `openai`. |

## 📚 Architecture

See the [ARCHITECTURE.md](ARCHITECTURE.md) document for a detailed system diagram and data flow explanation.
