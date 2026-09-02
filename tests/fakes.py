"""In-memory ControlStore for fast, deterministic RAG logic tests.

The whole point of the ControlStore Protocol: the collapse-to-base logic, family
filtering, and fallback flagging can be exercised without embeddings, chromadb, a
model download, or the network. Distances are supplied per control, so a test
pins retrieval order exactly instead of hoping the embedder ranks a certain way.
"""

from __future__ import annotations

from riskagent.models import ControlRecord
from riskagent.rag.index import ControlChunk

_FAR = 9.0  # default distance for a control the test did not rank


def _c(control_id: str, family: str, title: str) -> ControlRecord:
    return ControlRecord(
        control_id=control_id,
        family=family,
        title=title,
        statement=f"{title} control statement, remediation guidance text.",
        discussion=f"{title} discussion and rationale.",
        related_controls=[],
    )


def mini_controls() -> list[ControlRecord]:
    """~25 real control IDs across the families the tests touch, incl. enhancements."""
    return [
        _c("SI-2", "SI", "Flaw Remediation"),
        _c("SI-2(5)", "SI", "Flaw Remediation | Automatic Software and Firmware Updates"),
        _c("SI-7", "SI", "Software, Firmware, and Information Integrity"),
        _c("SI-3", "SI", "Malicious Code Protection"),
        _c("SI-4", "SI", "System Monitoring"),
        _c("SI-10", "SI", "Information Input Validation"),
        _c("SI-19", "SI", "De-identification"),
        _c("RA-5", "RA", "Vulnerability Monitoring and Scanning"),
        _c("SA-22", "SA", "Unsupported System Components"),
        _c("SA-11", "SA", "Developer Testing and Evaluation"),
        _c("AC-3", "AC", "Access Enforcement"),
        _c("AC-6", "AC", "Least Privilege"),
        _c("AC-2", "AC", "Account Management"),
        _c("SC-7", "SC", "Boundary Protection"),
        _c("SC-28", "SC", "Protection of Information at Rest"),
        _c("CM-8", "CM", "System Component Inventory"),
        _c("CM-6", "CM", "Configuration Settings"),
        _c("CP-9", "CP", "System Backup"),
        _c("CP-9(1)", "CP", "System Backup | Testing for Reliability and Integrity"),
        _c("CP-10", "CP", "System Recovery and Reconstitution"),
        _c("CP-4", "CP", "Contingency Plan Testing"),
        _c("IA-2", "IA", "Identification and Authentication"),
        _c("IA-5", "IA", "Authenticator Management"),
        _c("AU-12", "AU", "Audit Record Generation"),
        _c("PM-5", "PM", "System Inventory"),
    ]


class FakeControlStore:
    """Deterministic ControlStore driven by a control_id -> distance map."""

    def __init__(self, controls: list[ControlRecord], distances: dict[str, float]) -> None:
        self._by_id = {c.control_id: c for c in controls}
        self._distances = distances

    def build(self, controls: list[ControlRecord], *, catalog_sha256: str) -> None:
        self._by_id = {c.control_id: c for c in controls}

    def count(self) -> int:
        return len(self._by_id)

    def _chunk(self, control: ControlRecord, distance: float) -> ControlChunk:
        return ControlChunk(
            control_id=control.control_id,
            family=control.family,
            title=control.title,
            statement=control.statement,
            discussion=control.discussion,
            distance=distance,
        )

    def query(self, text: str, *, families: list[str] | None, k: int) -> list[ControlChunk]:
        items = [c for c in self._by_id.values() if families is None or c.family in families]
        items.sort(key=lambda c: self._distances.get(c.control_id, _FAR))
        return [self._chunk(c, self._distances.get(c.control_id, _FAR)) for c in items[:k]]

    def get(self, control_id: str) -> ControlChunk | None:
        control = self._by_id.get(control_id)
        # match the real store: get() carries no distance; caller supplies it
        return self._chunk(control, 0.0) if control is not None else None
