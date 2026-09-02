"""Precomputed query-vector pack (§8 deploy) — how the deployed service retrieves
without the embedding model.

Both the corpus (NIST controls) and the query set are static and known at build
time: at most 114 findings, each producing exactly one deterministic templated
query (``build_query`` over structured fields). So at build time we embed every
finding's query once and ship the ``{query_text: vector}`` table in the image; at
runtime ``PrecomputedEmbedder`` answers each query by table lookup — no
sentence-transformers, no torch, no model load.

The vectors are the SAME vectors the index was built with (same model, same
normalisation, via ``ChromaControlStore.embed``), so retrieval — and therefore
recall@3 — is byte-for-byte unchanged. A query text absent from the table raises
loudly rather than silently degrading: a missing key is a wiring bug, not a
fallback. This is a QUERY cache; nothing here is ever written into Chroma.
"""

from __future__ import annotations

import json
from pathlib import Path

from riskagent import config
from riskagent.generate.assemble import score_all_findings
from riskagent.ingest.csv_loader import DataBundle
from riskagent.rag.families import classify_finding_type
from riskagent.rag.index import ChromaControlStore
from riskagent.rag.retrieve import build_query


def finding_query_texts(data: DataBundle) -> list[str]:
    """Every distinct production query text, sorted — one per finding, deduped."""
    findings = score_all_findings(data)
    texts = {build_query(f, classify_finding_type(f)) for f in findings}
    return sorted(texts)


def build_query_pack(data: DataBundle, store: ChromaControlStore) -> dict[str, list[float]]:
    """Embed every finding's query with the model the index was built with.

    Embedded ONE text at a time to exactly match ``retrieve``'s single-text
    ``_embed([text])`` call — batch encoding perturbs the vectors at ~1e-7, enough
    to make the byte-for-byte equality check flaky though never enough to reorder
    results. Single-encode makes the precomputed vector identical to what a live
    model call would produce."""
    texts = finding_query_texts(data)
    return {text: store.embed([text])[0] for text in texts}


def save_pack(table: dict[str, list[float]], path: Path = config.QUERY_EMBEDDINGS_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(table), encoding="utf-8")


def load_pack(path: Path = config.QUERY_EMBEDDINGS_PATH) -> dict[str, list[float]]:
    raw: dict[str, list[float]] = json.loads(path.read_text(encoding="utf-8"))
    return raw


class PrecomputedEmbedder:
    """``embed_fn`` for ``ChromaControlStore``: query-text -> precomputed vector.

    A miss raises ``KeyError`` — the deployed data pack must cover every query the
    app can issue, so an absent key means the pack and the code diverged, which must
    fail loudly rather than fall back to a model that isn't installed."""

    def __init__(self, table: dict[str, list[float]]) -> None:
        self._table = table

    @classmethod
    def load(cls, path: Path = config.QUERY_EMBEDDINGS_PATH) -> PrecomputedEmbedder:
        return cls(load_pack(path))

    def __call__(self, texts: list[str]) -> list[list[float]]:
        try:
            return [self._table[t] for t in texts]
        except KeyError as exc:
            raise KeyError(f"query text absent from precomputed pack (wiring bug): {exc}") from exc
