FROM python:3.11-slim@sha256:e031123e3d85762b141ad1cbc56452ba69c6e722ebf2f042cc0dc86c47c0d8b3

WORKDIR /app

RUN apt-get update \
    && apt-get install --yes --no-install-recommends iproute2 iptables \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "blake3>=0.4,<2" "dnspython>=2.6,<3"

COPY src/argus_egress ./argus_egress
COPY src/argus_runtime/__init__.py ./argus_runtime/__init__.py
COPY src/argus_runtime/s10_egress_proxy_service.py ./argus_runtime/s10_egress_proxy_service.py

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1
