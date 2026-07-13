FROM python:3.11-slim

COPY scripts/gvisor_security_probe.py /opt/argus/gvisor_security_probe.py

USER 65532:65532
ENTRYPOINT ["python3", "/opt/argus/gvisor_security_probe.py"]
