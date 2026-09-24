ARG BASE=python:3.12-slim
FROM ${BASE}
COPY test-agent/test_agent.py /app/test_agent.py
# Pre-create the output mount point writable by the unprivileged agent user.
RUN mkdir -p /workspace/output && chown 65534:65534 /workspace/output
USER 65534:65534
WORKDIR /workspace
