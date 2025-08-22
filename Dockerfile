FROM python:3.11-slim

# Install system dependencies for matplotlib and lief
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY analyzers/ ./analyzers/

# Create tmp directory for file processing
RUN mkdir -p /tmp

# Expose port
EXPOSE 3000

# Run the application
CMD ["python", "app.py"]