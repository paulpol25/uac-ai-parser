# UAC AI Parser Dockerfile
FROM python:3.11-slim

LABEL maintainer="UAC AI Parser Team"
LABEL description="AI-powered UAC forensic artifact parser"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy project files
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package
RUN pip install --upgrade pip && \
    pip install -e .

# Create directories for data
RUN mkdir -p /data/input /data/output /data/vectorstore

# Set default environment variables
ENV UAC_CHROMA_PERSIST_DIR=/data/vectorstore
ENV UAC_OUTPUT_DIR=/data/output

# Default command
ENTRYPOINT ["uac-ai"]
CMD ["--help"]
