# syntax=docker/dockerfile:1
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip pip install -r requirements.txt
COPY insurer_mcp ./insurer_mcp
USER 1000
CMD ["python", "-m", "insurer_mcp.app"]
