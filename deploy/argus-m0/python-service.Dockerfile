FROM rust:1.85-slim AS rust-builder

WORKDIR /app

COPY bindings/rust ./bindings/rust

RUN cargo build --manifest-path bindings/rust/Cargo.toml --release --bin argus-s8-ledger-writer \
    && cargo build --manifest-path bindings/rust/Cargo.toml --release --bin argus-s3-report-signer \
    && cargo build --manifest-path bindings/rust/Cargo.toml --release --bin argus-s10-audit-ledger-writer

FROM ghcr.io/sigstore/cosign/cosign:v2.6.3@sha256:4bedb8de1c5c1abd8dea60de704ba449402d238623fa8bb33d2ccaa9beffcbf5 AS cosign

FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY schemas ./schemas
COPY db ./db
COPY --from=rust-builder /app/bindings/rust/target/release/argus-s8-ledger-writer /usr/local/bin/argus-s8-ledger-writer
COPY --from=rust-builder /app/bindings/rust/target/release/argus-s3-report-signer /usr/local/bin/argus-s3-report-signer
COPY --from=rust-builder /app/bindings/rust/target/release/argus-s10-audit-ledger-writer /usr/local/bin/argus-s10-audit-ledger-writer
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
