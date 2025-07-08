# Use Python 3.11 as base image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Copy project files
COPY pyproject.toml .
COPY README.md .
COPY vuln_analyzer/ ./vuln_analyzer/

# Install Python dependencies using uv
RUN uv pip install --system .

# Create CVE data directory (will be mounted as volume)
RUN mkdir -p ./cvelistV5/cves

# Create a non-root user
RUN useradd --create-home --shell /bin/bash appuser
RUN chown -R appuser:appuser /app
USER appuser

# Set environment variables
ENV PYTHONPATH=/app
ENV CVE_DATA_PATH=/app/cvelistV5/cves

# Expose port (if needed for future web interface)
EXPOSE 8000

# Default command
ENTRYPOINT ["vuln-analyzer"]
CMD ["--help"] 