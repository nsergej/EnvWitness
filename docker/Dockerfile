# syntax=docker/dockerfile:1.7

FROM python:3.13-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip wheel --wheel-dir /wheels .

FROM python:3.13-slim AS runtime

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system --gid 10001 envwitness \
    && useradd --system --uid 10001 --gid envwitness --create-home envwitness
COPY --from=builder /wheels /wheels
RUN python -m pip install /wheels/envwitness-*.whl \
    && rm -rf /wheels
COPY docker/envwitness.yml /etc/envwitness/envwitness.yml

WORKDIR /workspace
USER 10001:10001

ENTRYPOINT ["envwitness"]
CMD ["--help"]
