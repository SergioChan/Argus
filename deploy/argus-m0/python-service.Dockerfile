FROM rust:1.85-slim AS rust-builder

WORKDIR /app

COPY bindings/rust ./bindings/rust

RUN cargo build --manifest-path bindings/rust/Cargo.toml --release --bin argus-s8-ledger-writer

FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY schemas ./schemas
COPY db ./db
COPY --from=rust-builder /app/bindings/rust/target/release/argus-s8-ledger-writer /usr/local/bin/argus-s8-ledger-writer

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
