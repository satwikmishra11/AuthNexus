# Build stage
FROM python:3.11-slim-bookworm as builder

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONPYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install build dependencies
COPY pyproject.toml .
RUN pip install --upgrade pip && \
    pip install wheel && \
    pip install --no-cache-dir .

# Production stage
FROM python:3.11-alpine3.18

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONPYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"

# Copy virtual environment
COPY --from=builder /opt/venv /opt/venv

# Runtime dependencies
RUN apk add --no-cache libstdc++ su-exec

# Create non-root user
RUN addgroup -S authnexus && \
    adduser -S authnexus -G authnexus -h /app && \
    chown -R authnexus:authnexus /app

# Copy application
COPY --chown=authnexus:authnexus . .

# Security hardening
RUN find /app -type d -exec chmod 755 {} \; && \
    find /app -type f -exec chmod 644 {} \; && \
    chmod 755 /app/entrypoint.sh

USER authnexus
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
