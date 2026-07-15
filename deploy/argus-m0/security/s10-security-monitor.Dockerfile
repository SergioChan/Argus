FROM rust:1.85-slim AS rust-builder

WORKDIR /app

COPY bindings/rust ./bindings/rust

RUN cargo build \
    --manifest-path bindings/rust/Cargo.toml \
    --release \
    --bin argus-s10-security-monitor

FROM falcosecurity/falco@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b

COPY --from=rust-builder \
    /app/bindings/rust/target/release/argus-s10-security-monitor \
    /usr/local/bin/argus-s10-security-monitor
COPY deploy/argus-m0/security/argus-falco-rules.yaml /etc/falco/argus_rules.yaml

ENV ARGUS_S10_SECURITY_MONITOR_BIND=0.0.0.0:8765
ENV ARGUS_S10_SECURITY_MONITOR_PORT=8765
ENV ARGUS_S10_HOST_PROC_ROOT=/host/proc
ENV ARGUS_S10_FALCO_BIN=/usr/bin/falco
ENV ARGUS_S10_FALCO_RULES_PATH=/etc/falco/argus_rules.yaml

ENTRYPOINT ["/usr/local/bin/argus-s10-security-monitor"]
