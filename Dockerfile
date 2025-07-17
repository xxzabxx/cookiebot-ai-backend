# Multi-stage Docker build for production deployment
FROM python:3.11-slim as base
# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*
# Create app user
RUN groupadd -r appuser && useradd -r -g appuser appuser
# Set work directory
WORKDIR /app
# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy application code
COPY . .
# Change ownership to app user
RUN chown -R appuser:appuser /app
USER appuser
# Expose port
EXPOSE 8080
# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/api/health || exit 1
# Production stage
FROM base as production
# Set production environment
ENV FLASK_ENV=production
# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--timeout", "120", "app:app"]
# Development stage
FROM base as development
# Set development environment
ENV FLASK_ENV=development
# Run development server
CMD ["python", "app.py"]
