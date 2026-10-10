# NetMind AI - Container Image for FastAPI Backend and Background Worker
FROM python:3.11-slim

# System dependencies for network tooling, compilation, and PostgreSQL driver
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source modules, models, logs, and scripts
COPY src/ ./src/
COPY netmind/ ./netmind/
COPY models/ ./models/
COPY scripts/ ./scripts/
COPY logs/ ./logs/

# Configure Python path and output buffering
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1

EXPOSE 8000

# Default command launches FastAPI backend
CMD ["uvicorn", "src.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
