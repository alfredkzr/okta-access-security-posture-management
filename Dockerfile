# ---- Build stage ----
FROM python:3.13-slim AS builder

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# ---- Runtime stage ----
FROM python:3.13-slim

# Create non-root user
RUN groupadd -r aspm && useradd -r -g aspm -d /app -s /sbin/nologin aspm

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=aspm:aspm . .

# Ensure entrypoint is executable
RUN chmod +x docker-entrypoint.sh

# Create reports directory
RUN mkdir -p /data/reports && chown aspm:aspm /data/reports

USER aspm

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health')" || exit 1

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
