# syntax=docker/dockerfile:1
# Multi-stage image for Hugging Face Spaces (Docker SDK).
#
# Stage 1 (builder) live-fetches the NIST catalog + CISA KEV feed and builds the
# persistent Chroma index, so the deployed container starts with a WARM index and
# no cold-start embedding pass. Stage 2 (runtime) carries only the built venv, the
# embedding-model cache, the app, and the pre-built index — no compiler toolchain.
#
# GROQ_API_KEY is never referenced at build time and never copied into the image;
# it is injected at runtime from a Space secret. Absent it, explanations degrade to
# templates and the page still renders (the LLM only writes prose, never a score).

##############################  Stage 1: builder  ##############################
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/hf-cache

# build-essential: some transitive wheels (e.g. hnswlib via chromadb) may compile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# self-contained venv we lift wholesale into the runtime stage
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# CPU-only torch from PyTorch's own index BEFORE the project install — avoids the
# multi-GB bundled-CUDA wheel that `sentence-transformers` would otherwise pull.
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch

# Editable install keeps config.py's parents[2] data-path resolution anchored at /app.
COPY pyproject.toml ./
COPY src ./src
RUN pip install -e .

COPY data ./data
COPY templates ./templates

# Build-time warm-up: live-fetch NIST + KEV, download the embedding model into
# HF_HOME, and build the persistent Chroma index under /app/cache. No Groq call.
RUN python -m riskagent.prewarm

##############################  Stage 2: runtime  #############################
FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    HF_HOME=/opt/hf-cache \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1

# Hugging Face Spaces runs the container as uid 1000; own the app tree so the
# service can write cache/ (traces, refreshed KEV/NIST) at runtime.
RUN useradd --create-home --uid 1000 user

WORKDIR /app

COPY --from=builder --chown=user:user /opt/venv /opt/venv
COPY --from=builder --chown=user:user /opt/hf-cache /opt/hf-cache
COPY --from=builder --chown=user:user /app /app

USER user

EXPOSE 7860

# HF_HUB_OFFLINE stops a model re-download; KEV/NIST still live-fetch at startup
# (plain urllib, unaffected) and fall back to the baked cache when offline.
CMD ["uvicorn", "riskagent.app:app", "--host", "0.0.0.0", "--port", "7860"]
