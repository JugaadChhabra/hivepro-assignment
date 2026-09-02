"""FastAPI service (§6). The pipeline runs ONCE at startup and is cached.

Read-only, five routes. ``/api/findings`` returns all 114 scored findings, which
is how a reviewer verifies nothing was truncated before scoring. ``/healthz``
returns real provenance (not a bare status), doubling as the keep-alive target.

KEV fields on ``/healthz`` and the ``/traces`` payload are populated in phase 7
(kev.py, trace.py); the routes and keys exist now so the shape is stable.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from riskagent import config
from riskagent.generate.assemble import AppState, Provenance, RiskBrief, build_state
from riskagent.generate.llm import GroqClient
from riskagent.generate.render import render_html
from riskagent.ingest.csv_loader import load_all
from riskagent.ingest.kev import load_kev
from riskagent.ingest.nist import load_catalog
from riskagent.models import EnrichedFinding
from riskagent.rag.index import ChromaControlStore


def default_state_builder() -> AppState:
    """Build the real cached state: data + NIST catalog + Chroma + Groq.

    Two modes, chosen by whether the build-time query-vector pack is present:

    * **Data-pack (deployed)** — ``cache/query_embeddings.json`` exists: retrieval
      uses precomputed query vectors, so no embedding model is loaded (no torch,
      fits Render's 512MB). The NIST catalog is read from the baked cache so it
      matches the shipped index exactly; a live re-fetch could differ and would
      need re-embedding, which the runtime deliberately cannot do.
    * **Model (local dev)** — no pack: the catalog is fetched live and the model
      embeds queries on demand, exactly as before.

    KEV is fetched live at startup in BOTH modes (it needs no embedding)."""
    data = load_all()
    use_pack = config.QUERY_EMBEDDINGS_PATH.exists()
    if use_pack:
        from riskagent.rag.pack import PrecomputedEmbedder

        catalog = load_catalog(offline=True)  # the baked catalog behind the shipped index
        store = ChromaControlStore(embed_fn=PrecomputedEmbedder.load())
    else:
        catalog = load_catalog()  # live fetch
        store = ChromaControlStore()
    kev = load_kev()  # live fetch; falls back to cache, or None if wholly unavailable
    store.build(catalog.controls, catalog_sha256=catalog.catalog_sha256)  # skips if index matches
    meta = store.collection_metadata()
    provenance = Provenance(
        nist_catalog_version=meta.get("nist_catalog_version", ""),
        nist_catalog_sha256=meta.get("catalog_sha256", ""),
        index_built_at=meta.get("index_built_at", ""),
        nist_fetched_at=catalog.fetched_at.isoformat(),
        generated_at=datetime.now(UTC).isoformat(),
    )
    # No key -> GroqClient.complete raises -> guard degrades to template sentences.
    client = GroqClient(
        api_key=os.environ.get("GROQ_API_KEY", ""),
        model=config.GROQ_MODEL,
        temperature=config.GROQ_TEMPERATURE,
        timeout_s=config.GROQ_TIMEOUT_S,
    )
    return build_state(
        data=data, store=store, complete=client.complete, provenance=provenance, kev=kev
    )


def _state(request: Request) -> AppState:
    return cast(AppState, request.app.state.pipeline)


def create_app(state_builder: Callable[[], AppState] = default_state_builder) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.pipeline = state_builder()  # runs the pipeline once, caches it
        yield

    app = FastAPI(title="TawasolPay Cyber Risk Assistant", lifespan=lifespan)

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> str:
        return render_html(_state(request).brief)

    @app.get("/api/risks")
    def api_risks(request: Request) -> RiskBrief:
        return _state(request).brief

    @app.get("/api/findings")
    def api_findings(request: Request) -> list[EnrichedFinding]:
        return _state(request).findings  # all 114 — nothing truncated before scoring

    @app.get("/traces")
    def traces(request: Request) -> list[dict[str, object]]:
        from riskagent.generate.trace import read_traces

        return read_traces(n=20)  # last N run traces, newest last

    @app.get("/healthz")
    def healthz(request: Request) -> dict[str, object]:
        p = _state(request).brief.provenance
        return {
            "status": "ok",
            "nist_catalog_version": p.nist_catalog_version,
            "nist_catalog_sha256": p.nist_catalog_sha256,
            "index_built_at": p.index_built_at,
            "nist_fetched_at": p.nist_fetched_at,
            "generated_at": p.generated_at,
            # how many of the 5 explanations were real LLM prose vs template — so a
            # reviewer can see the model is contributing, not silently degraded.
            "explanations_llm": p.explanations_llm,
            "explanations_template": p.explanations_template,
            "kev_fetched_at": p.kev_fetched_at,
            "kev_coverage_pct": p.kev_coverage_pct,
            "kev_staleness_warning": p.kev_staleness_warning,
        }

    return app


app = create_app()
