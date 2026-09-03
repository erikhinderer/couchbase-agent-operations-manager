FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

EXPOSE 8100

HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=15 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8100/healthz')" || exit 1

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]
