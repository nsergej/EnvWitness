# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.13-slim@sha256:6771159cd4fa5d9bba1258caf0b82e6b73458c694d178ad97c5e925c2d0e1a91

FROM ${PYTHON_IMAGE} AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM ${PYTHON_IMAGE} AS runtime

LABEL org.opencontainers.image.title="EnvWitness" \
      org.opencontainers.image.description="Privacy-first diagnostic environment evidence capsules" \
      org.opencontainers.image.source="https://github.com/nsergej/EnvWitness" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="1.0.0"

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && apt-get install --no-install-recommends --yes git \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 envwitness \
    && useradd --system --uid 10001 --gid envwitness --create-home envwitness
COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/envwitness-*.whl \
    && rm -rf /wheels
COPY docker/envwitness.yml /etc/envwitness/envwitness.yml

WORKDIR /workspace
USER 10001:10001

ENTRYPOINT ["envwitness"]
CMD ["--help"]
