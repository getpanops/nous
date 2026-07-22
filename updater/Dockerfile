FROM python:3.13-slim

ARG ORAS_VERSION=1.2.0
ARG COSIGN_VERSION=2.4.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        wget tar ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && wget -qO /tmp/oras.tar.gz \
        "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/oras.tar.gz -C /usr/local/bin oras \
    && chmod +x /usr/local/bin/oras \
    && rm /tmp/oras.tar.gz \
    && oras version

RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && wget -qO /usr/local/bin/cosign \
        "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-${ARCH}" \
    && chmod +x /usr/local/bin/cosign \
    && cosign version

WORKDIR /app
RUN pip install --no-cache-dir pyyaml

# Build context is repo root — COPY paths are relative to nous/
COPY sources.yaml /app/sources.yaml
COPY updater/src/nous-update.py /app/nous-update.py

ENV RULES_DIR=/rules
ENV SOURCES_FILE=/app/sources.yaml
ENTRYPOINT ["python3", "/app/nous-update.py"]
