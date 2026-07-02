FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY db ./db

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
