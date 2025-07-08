# Dockerfile for containerized vulnerability analyzer
FROM python:3.11-slim as base

# Set environment variables for container
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        wget \
        build-essential \
        git \
        sqlite3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast package management
RUN pip install uv

# Create app directory and user
RUN groupadd --gid 1000 appuser && \
    useradd --uid 1000 --gid appuser --shell /bin/bash --create-home appuser

WORKDIR /app

# ==================================
# Main stage
# ==================================
FROM base

# Copy necessary files
COPY pyproject.toml README.md ./
COPY vuln_analyzer/ ./vuln_analyzer/
COPY scripts/ ./scripts/
COPY examples/ ./examples/
COPY docs/ ./docs/

# Install dependencies
RUN uv pip install --system .

# Create directories for data and configuration
RUN mkdir -p /app/data/cvelistV5/cves \
             /app/data/databases \
             /app/data/downloads \
             /app/config \
             /app/logs \
    && chown -R appuser:appuser /app

# Copy entrypoint script
COPY --chown=appuser:appuser docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER appuser

# Set container-friendly environment variables
ENV CVE_DATA_PATH=/app/data/cvelistV5/cves \
    KEV_FILE_PATH=/app/data/known_exploited_vulnerabilities.json \
    DATABASE_PATH=/app/data/databases/cve_database.db \
    DOWNLOAD_DIR=/app/data/downloads \
    LOG_LEVEL=INFO \
    PYTHONPATH=/app

# Create health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import vuln_analyzer; print('OK')" || exit 1

# Expose port for future web interface
EXPOSE 8000

# Set entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"] 