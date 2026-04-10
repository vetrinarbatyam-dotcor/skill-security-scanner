FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Claude CLI for LLM review layer
# (requires API key mounted as env var at runtime)
RUN apt-get update && apt-get install -y --no-install-recommends curl docker.io && rm -rf /var/lib/apt/lists/*

COPY . .

EXPOSE 8990

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8990"]
