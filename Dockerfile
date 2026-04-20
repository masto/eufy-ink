FROM python:3.11-slim

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY eufy_ink.py .

# Run in watch mode with metrics endpoint by default when using CMD
CMD ["python", "eufy_ink.py", "--watch", "--interval", "900", "--metrics-port", "8080"]
