"""Build and query the NIST control vector store (§5).

ONE CONTROL PER CHUNK — the document's own boundary, which makes ``control_id``
the citation. The embedded text is ``"{control_id} {title}\\n{statement}"`` only;
``discussion`` is carried in metadata and shown in output but never embedded.

INVARIANT: nothing but NIST controls is ever written here. No CVSS score, no asset
attribute, no vulnerability row. ``build`` accepts ``ControlRecord`` and nothing
else, and the only text it embeds comes from those records.

Provenance is stored on the collection: the SHA-256 of the fetched catalog bytes
(the fact), the version label (human-readable), and the build timestamp — so
"was this index built from the current catalog" is a real hash comparison, not a
hardcoded assertion. A build against a different catalog hash rebuilds the index.

Chroma sits behind the ``ControlStore`` Protocol so it can be swapped without
touching ``retrieve``.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from riskagent import config
from riskagent.models import ControlRecord

if TYPE_CHECKING:
    from chromadb.api import ClientAPI
    from chromadb.api.models.Collection import Collection
    from sentence_transformers import SentenceTransformer


@dataclass(frozen=True)
class ControlChunk:
    control_id: str
    family: str
    title: str
    statement: str
    discussion: str
    distance: float


class ControlStore(Protocol):
    """Swappable interface over the control index."""

    def build(self, controls: list[ControlRecord], *, catalog_sha256: str) -> None: ...

    def count(self) -> int: ...

    def query(self, text: str, *, families: list[str] | None, k: int) -> list[ControlChunk]: ...

    def get(self, control_id: str) -> ControlChunk | None: ...


def chunk_text(control: ControlRecord) -> str:
    """The embedded text for one control. Statement only — discussion is metadata."""
    return f"{control.control_id} {control.title}\n{control.statement}"


class ChromaControlStore:
    """``ControlStore`` backed by a persistent Chroma collection + all-MiniLM."""

    def __init__(
        self,
        *,
        persist_dir: str | None = None,
        collection_name: str | None = None,
        model_name: str | None = None,
        catalog_version: str = config.NIST_CATALOG_VERSION,
    ) -> None:
        self._persist_dir = persist_dir or str(config.CHROMA_DIR)
        self._collection_name = collection_name or config.CHROMA_COLLECTION
        self._model_name = model_name or config.EMBED_MODEL_NAME
        self._catalog_version = catalog_version
        self._model: SentenceTransformer | None = None
        self._client = self._make_client()

    def _make_client(self) -> ClientAPI:
        import chromadb

        config.CHROMA_DIR.parent.mkdir(parents=True, exist_ok=True)
        return chromadb.PersistentClient(path=self._persist_dir)

    def _embed(self, texts: list[str]) -> list[list[float]]:
        if self._model is None:
            from sentence_transformers import SentenceTransformer

            self._model = SentenceTransformer(self._model_name)
        vectors = self._model.encode(texts, normalize_embeddings=True)
        return [[float(x) for x in row] for row in vectors]

    def _collection(self, provenance: dict[str, str] | None = None) -> Collection:
        metadata = {"hnsw:space": "cosine"}
        if provenance:
            metadata.update(provenance)
        return self._client.get_or_create_collection(name=self._collection_name, metadata=metadata)

    def count(self) -> int:
        return int(self._collection().count())

    def collection_metadata(self) -> dict[str, str]:
        return dict(self._collection().metadata or {})

    def build(
        self, controls: list[ControlRecord], *, catalog_sha256: str, batch_size: int = 256
    ) -> None:
        collection = self._collection()
        stored = collection.metadata or {}
        # Idempotent: skip only if the row count AND the catalog hash both match.
        if collection.count() == len(controls) and stored.get("catalog_sha256") == catalog_sha256:
            return
        if collection.count() > 0:
            self._client.delete_collection(self._collection_name)  # catalog changed -> rebuild
        collection = self._collection(
            provenance={
                "nist_catalog_version": self._catalog_version,
                "catalog_sha256": catalog_sha256,
                "index_built_at": datetime.now(UTC).isoformat(),
            }
        )
        documents = [chunk_text(c) for c in controls]
        metadatas = [
            {
                "control_id": c.control_id, "family": c.family, "title": c.title,
                "statement": c.statement, "discussion": c.discussion,
            }
            for c in controls
        ]
        ids = [c.control_id for c in controls]
        for start in range(0, len(controls), batch_size):
            end = start + batch_size
            collection.add(
                ids=ids[start:end],
                documents=documents[start:end],
                embeddings=self._embed(documents[start:end]),
                metadatas=metadatas[start:end],
            )

    def _to_chunk(self, meta: dict[str, object], distance: float) -> ControlChunk:
        return ControlChunk(
            control_id=str(meta["control_id"]),
            family=str(meta["family"]),
            title=str(meta["title"]),
            statement=str(meta["statement"]),
            discussion=str(meta["discussion"]),
            distance=distance,
        )

    def query(self, text: str, *, families: list[str] | None, k: int) -> list[ControlChunk]:
        where = {"family": {"$in": families}} if families else None
        result = self._collection().query(
            query_embeddings=self._embed([text]), n_results=k, where=where
        )
        result_metas = result["metadatas"]
        result_dists = result["distances"]
        if not result_metas or not result_dists:
            return []
        return [
            self._to_chunk(meta, float(dist))
            for meta, dist in zip(result_metas[0], result_dists[0], strict=True)
        ]

    def get(self, control_id: str) -> ControlChunk | None:
        got = self._collection().get(ids=[control_id], include=["metadatas"])
        metadatas = got["metadatas"]
        if not metadatas:
            return None
        return self._to_chunk(metadatas[0], 0.0)  # caller supplies the matched distance

    def peek(self, n: int = 20) -> list[str]:
        """Return up to n stored documents (for contamination checks/inspection)."""
        got = self._collection().get(limit=n, include=["documents"])
        return [str(doc) for doc in (got["documents"] or [])]


def build_store(catalog_version: str = config.NIST_CATALOG_VERSION) -> ChromaControlStore:
    """Convenience: construct the default store (does not build the index)."""
    return ChromaControlStore(catalog_version=catalog_version)
