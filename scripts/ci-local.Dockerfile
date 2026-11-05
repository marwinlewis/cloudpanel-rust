# Mirrors the GitHub Actions CI runner (ubuntu-latest = Ubuntu 24.04) closely enough
# to catch CI failures locally. Used by scripts/ci-local.sh.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl git build-essential pkg-config shellcheck xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Node 22, as on the GitHub runner.
ARG NODE_VERSION=22.12.0
RUN arch=$(dpkg --print-architecture | sed 's/amd64/x64/') \
 && curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
    | tar -xJ -C /usr/local --strip-components=1

# GitHub's runner is an unprivileged user (no root, no chown to other users).
RUN useradd -m -s /bin/bash runner
USER runner
ENV PATH=/home/runner/.cargo/bin:$PATH
RUN curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs \
    | sh -s -- -y --profile minimal --default-toolchain stable -c rustfmt -c clippy
# Cache volumes mount here; creating them as runner makes the volumes runner-owned.
RUN mkdir -p /home/runner/.cargo/registry /home/runner/target /home/runner/work
WORKDIR /home/runner/work
