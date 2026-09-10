# Builder stage
FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install build dependencies and build the wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel

# Runtime stage
FROM python:3.12-slim

WORKDIR /app

# Create unprivileged user
RUN useradd -m -U -s /bin/false ulpf && \
    mkdir -p /app/data/dlq /app/data/output /app/parsers/active /app/parsers/pending && \
    chown -R ulpf:ulpf /app

# Copy the built wheel from builder
COPY --from=builder /app/dist/*.whl ./

# Install the wheel and uvloop for performance
RUN pip install --no-cache-dir *.whl uvloop

# Copy active parsers and dashboard
COPY --chown=ulpf:ulpf parsers/active/ /app/parsers/active/
COPY --chown=ulpf:ulpf dashboard/ /app/dashboard/

USER ulpf

# Expose ports: 5140 (syslog UDP), 8080 (metrics/API)
EXPOSE 5140/udp 8080/tcp

ENV ULPF_LISTEN_HOST="0.0.0.0"
ENV ULPF_LISTEN_PORT=5140

ENTRYPOINT ["python", "-m", "ulpf.pipeline"]
