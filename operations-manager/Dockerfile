FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install the CPU-only build of torch first so pip doesn't pull in the
# default CUDA/cuDNN/Triton-enabled build when resolving
# sentence-transformers' dependency on torch - this container only runs a
# small embedding model on CPU.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY config.py .
COPY app ./app

ENV TOKENIZERS_PARALLELISM=false

EXPOSE 8090

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=20 \
    CMD curl -f http://localhost:8090/api/health || exit 1

CMD ["python3", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090"]
