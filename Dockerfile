FROM python:3.11-slim

LABEL maintainer="PENTRAX Security Research Team"
LABEL description="PENTRAX Enterprise Attack Surface Discovery & Red Team Scanner"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure data and scan output directories exist
RUN mkdir -p /app/data /app/scans

EXPOSE 8080

ENTRYPOINT ["python3", "run_server.py", "--host", "0.0.0.0", "--port", "8080"]

