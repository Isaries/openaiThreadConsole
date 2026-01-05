# Base Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for WeasyPrint
RUN apt-get update && apt-get install -y \
    libcairo2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    gobject-introspection \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (Waitress defaults to 8081 in run_server.py)
EXPOSE 8000

# Environment variables (Can be overridden at runtime)
# FLASK_DEBUG is explicitly False for safety
ENV FLASK_DEBUG=False
ENV PORT=8000

# Run the production server
CMD ["python", "run_server.py"]
