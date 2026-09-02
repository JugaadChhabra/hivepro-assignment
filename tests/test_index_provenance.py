"""Fast regression for the index provenance + idempotent-skip contract (§8 deploy).

No model: a stub ``embed_fn`` supplies vectors, so this runs on the fast gate. It
pins the bug that broke the model-free deploy — ``get_or_create_collection`` does
not update an existing collection's metadata, so ``build`` must delete-then-recreate
for the provenance to persist. If it does not persist, a later ``build`` cannot skip
and (with no model) would try to re-embed and crash.
"""

from __future__ import annotations

from pathlib import Path

from riskagent.models import ControlRecord
from riskagent.rag.index import ChromaControlStore

_DIM = 8


def _controls() -> list[ControlRecord]:
    return [
        ControlRecord(
            control_id=f"AC-{i}", family="AC", title=f"c{i}",
            statement=f"statement {i}", discussion="", related_controls=[],
        )
        for i in range(1, 6)
    ]


def _stub_embed(texts: list[str]) -> list[list[float]]:
    return [[0.1] * _DIM for _ in texts]


def _store(persist_dir: Path, calls: list[int]) -> ChromaControlStore:
    def counting(texts: list[str]) -> list[list[float]]:
        calls.append(len(texts))
        return _stub_embed(texts)

    return ChromaControlStore(
        persist_dir=str(persist_dir), collection_name="test_prov", embed_fn=counting
    )


def test_provenance_persists_and_second_build_skips(tmp_path: Path) -> None:
    controls = _controls()
    calls: list[int] = []
    store = _store(tmp_path, calls)

    store.build(controls, catalog_sha256="deadbeef")
    meta = store.collection_metadata()
    assert meta["catalog_sha256"] == "deadbeef"  # provenance actually persisted
    assert meta["nist_catalog_version"]
    assert meta["index_built_at"]
    assert sum(calls) > 0  # it embedded on the first build

    # A fresh store over the SAME dir + same catalog hash must skip — no re-embed.
    calls2: list[int] = []
    store2 = _store(tmp_path, calls2)
    store2.build(controls, catalog_sha256="deadbeef")
    assert calls2 == []  # skipped: embed_fn never called
    assert store2.count() == len(controls)


def test_changed_catalog_hash_triggers_rebuild(tmp_path: Path) -> None:
    controls = _controls()
    store = _store(tmp_path, [])
    store.build(controls, catalog_sha256="hash-v1")

    calls: list[int] = []
    store2 = _store(tmp_path, calls)
    store2.build(controls, catalog_sha256="hash-v2")  # different catalog -> rebuild
    assert sum(calls) > 0
    assert store2.collection_metadata()["catalog_sha256"] == "hash-v2"
