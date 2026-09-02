# syntax=docker/dockerfile:1
# Multi-stage image for Render (Docker runtime, free tier — 512MB RAM).
#
# The embedding model runs at BUILD time only: stage 1 embeds the NIST catalog into
# a persistent Chroma index AND precomputes the query vector for every finding, then
# builds a second, core-only virtualenv that has NO torch / sentence-transformers.
# Stage 2 ships only that core venv + the app + the pre-built data pack, so the
# running service does retrieval by vector lookup — it never imports torch and stays
# well under 512MB. A new finding at runtime would need a rebuild (see README).
#
# GROQ_API_KEY is never referenced at build time and never copied into the image; it
# is injected at runtime as a Render environment variable. Absent it, explanations
# degrade to templates and the page still renders (the LLM only writes prose).

##############################  Stage 1: builder  ##############################
FROM python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    HF_HOME=/opt/hf-cache

# build-essential: hnswlib (via chromadb) compiles from source on slim.
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src
COPY data ./data
COPY templates ./templates

# (a) full build venv: CPU-only torch + the `build` extra (sentence-transformers).
#     CPU torch from PyTorch's index avoids the multi-GB bundled-CUDA wheel.
RUN python -m venv /opt/venv-build \
    && /opt/venv-build/bin/pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && /opt/venv-build/bin/pip install -e ".[build]"

# Build the data pack: embed the catalog into Chroma AND precompute query vectors.
# No Groq call, so no API key is needed or present. Writes /app/cache/*.
RUN /opt/venv-build/bin/python -m riskagent.prewarm

# (b) core-only runtime venv: NO torch, NO sentence-transformers. Compiled here
#     (build-essential present) so the final stage needs no toolchain. Built at its
#     FINAL path (/opt/venv) so console-script shebangs stay valid after the copy.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install -e .

##############################  Stage 2: final  ###############################
FROM python:3.13-slim AS final

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    ANONYMIZED_TELEMETRY=False

# Render runs the container as an unprivileged user; own the app tree so the service
# can write cache/ (traces, and the KEV copy it refreshes at startup) at runtime.
RUN useradd --create-home --uid 1000 user

WORKDIR /app

# core-only venv (no torch), the app source, and the pre-built data pack
COPY --from=builder --chown=user:user /opt/venv /opt/venv
COPY --from=builder --chown=user:user /app /app

USER user

# Render provides $PORT; default 7860 for local `docker run`. KEV still live-fetches
# at startup (plain urllib); NIST is read from the baked pack to match the index.
# `python -m uvicorn` avoids any reliance on console-script shebangs.
EXPOSE 7860
CMD ["sh", "-c", "exec python -m uvicorn riskagent.app:app --host 0.0.0.0 --port ${PORT:-7860}"]
