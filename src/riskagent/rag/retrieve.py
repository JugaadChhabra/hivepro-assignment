"""Retrieve the top-k NIST controls for a finding (§5).

The query is TEMPLATED from structured fields, never raw free text — so what we
search with is auditable and deterministic. We pre-filter to the finding_type's
family hints; if the best hit is worse than the threshold we retry unfiltered and
flag ``family_filter_fallback``. Over-constraining is the one way the pre-filter
makes things worse, so it needs an escape hatch. The explicit ``"unknown"``
finding_type takes that path directly; any OTHER unmapped type is a programming
error and raises.

The index holds one chunk per control AND per enhancement (SI-2, SI-2(5), ...).
For citation we collapse enhancements to their base control and return k DISTINCT
base controls — but we CARRY the matched enhancement IDs and their text on the
result, because sometimes the enhancement is the actionable guidance (backup
immutability lives in a CP-9 enhancement, not CP-9's base text). Output reads
"CP-9 System Backup, particularly CP-9(1)": base for citation, enhancement for
specificity, one chunk still one control.

Dense-only by design — BM25/RRF is a phase-6 decision, made on a measurement.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from riskagent import config
from riskagent.models import EnrichedFinding
from riskagent.rag.families import (
    FAMILY_HINTS,
    FINDING_TYPE_QUERY,
    GAP_CONTROLS,
    GAP_FAMILY_HINTS,
    classify_finding_type,
)
from riskagent.rag.index import ControlChunk, ControlStore

_UNKNOWN = "unknown"


@dataclass(frozen=True)
class RetrievedControl:
    control: ControlChunk  # the base control — the citation and its text
    enhancements: tuple[ControlChunk, ...] = ()  # matched enhancements, best-distance first

    @property
    def control_id(self) -> str:
        return self.control.control_id

    @property
    def distance(self) -> float:
        return self.control.distance

    @property
    def enhancement_ids(self) -> tuple[str, ...]:
        return tuple(e.control_id for e in self.enhancements)


@dataclass(frozen=True)
class RetrievalResult:
    finding_type: str
    query: str
    chunks: list[RetrievedControl]  # top-k by similarity (family-union filtered)
    gap_controls: list[GapControl]  # rule-mapped from control_gaps; guaranteed, not searched
    flags: list[str]  # e.g. ["family_filter_fallback"]


@dataclass(frozen=True)
class GapControl:
    """A control that applies by DETERMINISTIC RULE from a control gap, not by
    similarity search (e.g. no_edr -> SI-3). A separate channel from ``chunks`` so
    recall is measured on retrieval alone and the trace can tell rule from search."""

    control_id: str
    title: str
    statement: str
    gap: str  # the control_gap that produced it
    source: str = "rule"


def build_query(finding: EnrichedFinding, finding_type: str) -> str:
    """Templated query text from structured fields only — never the raw report."""
    vuln = finding.vulnerability
    asset = finding.asset
    parts = [
        FINDING_TYPE_QUERY.get(finding_type, finding_type.replace("_", " ")),
        vuln.affected_component,
        "internet-facing" if asset.internet_exposed else "internal",
        "weaponised exploit available" if vuln.exploit_available else "",
        ", ".join(finding.control_gaps),
    ]
    return ". ".join(part for part in parts if part)


def _base_id(control_id: str) -> str:
    # "SI-2(5)" -> "SI-2"; "SI-2" -> "SI-2"
    return control_id.split("(", 1)[0]


def _collapse_to_base(
    raw: list[ControlChunk], store: ControlStore, k: int
) -> list[RetrievedControl]:
    """Collapse enhancement hits to distinct base controls, carrying enhancements."""
    best: dict[str, float] = {}
    order: list[str] = []
    enhancements: dict[str, list[ControlChunk]] = {}
    for hit in raw:
        base = _base_id(hit.control_id)
        if base not in best:
            best[base] = hit.distance
            order.append(base)
            enhancements[base] = []
        else:
            best[base] = min(best[base], hit.distance)
        if hit.control_id != base:
            enhancements[base].append(hit)

    collapsed: list[RetrievedControl] = []
    for base in order[:k]:
        chunk = store.get(base)
        if chunk is None:  # base control is always indexed; guard anyway
            continue
        collapsed.append(
            RetrievedControl(
                control=replace(chunk, distance=best[base]),
                enhancements=tuple(sorted(enhancements[base], key=lambda c: c.distance)),
            )
        )
    return collapsed


def retrieve(
    finding: EnrichedFinding,
    store: ControlStore,
    *,
    k: int = config.RETRIEVAL_TOP_K,
    finding_type: str | None = None,
    threshold: float = config.RETRIEVAL_DISTANCE_THRESHOLD,
) -> RetrievalResult:
    ft = finding_type if finding_type is not None else classify_finding_type(finding)
    if ft != _UNKNOWN and ft not in FAMILY_HINTS:
        raise ValueError(f"finding_type {ft!r} has no family mapping in FAMILY_HINTS")

    query = build_query(finding, ft)
    over = config.RETRIEVAL_OVERFETCH
    flags: list[str] = []

    if ft == _UNKNOWN:
        raw = store.query(query, families=None, k=over)  # no hint — unfiltered
        flags.append("family_filter_fallback")
    else:
        # union the finding_type families with each control gap's families, so a
        # second remediation dimension (e.g. no_edr -> SI-3/AU) stays reachable
        families = set(FAMILY_HINTS[ft])
        for gap in finding.control_gaps:
            families.update(GAP_FAMILY_HINTS.get(gap, ()))
        raw = store.query(query, families=sorted(families), k=over)
        if not raw or raw[0].distance > threshold:
            raw = store.query(query, families=None, k=over)
            flags.append("family_filter_fallback")

    chunks = _collapse_to_base(raw, store, k)
    gap_controls = _gap_controls(finding.control_gaps, chunks, store)
    return RetrievalResult(
        finding_type=ft, query=query, chunks=chunks, gap_controls=gap_controls, flags=flags
    )


def _gap_controls(
    gaps: list[str], chunks: list[RetrievedControl], store: ControlStore
) -> list[GapControl]:
    """Deterministic rule channel: map each control gap to its canonical control(s)
    (no_edr -> SI-3). Deduped against the retrieved chunks (prefer the search hit)
    and against each other. Never competes with chunks, so recall is unaffected."""
    shown = {c.control_id for c in chunks}
    result: list[GapControl] = []
    for gap in gaps:
        for control_id in GAP_CONTROLS.get(gap, ()):
            if control_id in shown:
                continue
            control = store.get(control_id)
            if control is not None:
                result.append(GapControl(control_id, control.title, control.statement, gap))
                shown.add(control_id)
    return result
