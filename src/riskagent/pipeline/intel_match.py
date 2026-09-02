"""Match threat intel to findings by EXACT CVE-key equality (§4).

The index is keyed on ``matched_cve_or_control`` and looked up with the
finding's ``vulnerability.cve`` verbatim — no ``.lower()``, no ``.strip()``, no
fuzzy/similarity matching, no embeddings. The dataset carries 16 deliberately
plausible noise records (real CVEs for products TawasolPay does not run, plus
non-CVE keys) precisely to punish a normalising matcher; 24 of 40 records match.

A relevance *weight* is computed on top of the match, but it is kept strictly
separate from the match boolean: it grades how strong an existing match is as
evidence for this org, and never creates, suppresses, or reorders a match.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date

from riskagent.models import EnrichedFinding, IntelRecord

# --- relevance weighting only (NOT the match) -------------------------------
# These graders use exact equality / set membership, never substring or case
# folding, so nothing here resembles the fuzzy matching the invariant forbids.
_HOME_REGION = "Middle East"  # TawasolPay is a UAE / Gulf fintech
_FINANCIAL_SECTORS = frozenset(
    {"Financial Services", "Fintech", "Finance", "Fintech and API-First", "Healthcare and Finance"}
)
_BROAD_SECTORS = frozenset({"All Sectors"})
_CONFIDENCE_WEIGHT = {"High": 1.0, "Medium": 0.6, "Low": 0.3}


def build_intel_index(intel: Iterable[IntelRecord]) -> dict[str, list[IntelRecord]]:
    """One-to-many index keyed on the exact ``matched_cve_or_control`` string."""
    index: dict[str, list[IntelRecord]] = {}
    for record in intel:
        index.setdefault(record.matched_cve_or_control, []).append(record)
    return index


def relevance_weight(intel: IntelRecord, reference_date: date) -> float:
    """Grade a matched record's evidential strength for this org, in [0,1].

    Combines region fit, sector fit, stated confidence, and recency relative to
    the freshest intel in the set. Auxiliary signal — the additive score in
    phase 3 reads the intel fields directly and does not consume this number.
    """
    if intel.target_region == _HOME_REGION:
        region = 1.0
    elif intel.target_region == "Global":
        region = 0.5
    else:
        region = 0.2

    if intel.target_sector in _FINANCIAL_SECTORS:
        sector = 1.0
    elif intel.target_sector in _BROAD_SECTORS:
        sector = 0.6
    else:
        sector = 0.3

    confidence = _CONFIDENCE_WEIGHT[intel.confidence]

    age_days = (reference_date - intel.active_last_seen).days
    if age_days <= 30:
        recency = 1.0
    elif age_days <= 90:
        recency = 0.6
    else:
        recency = 0.3

    return round((region + sector + confidence + recency) / 4, 4)


@dataclass(frozen=True)
class IntelMatchResult:
    findings: list[EnrichedFinding]
    matched_intel_count: int  # intel records whose key hit a finding's CVE (expect 24)
    unmatched_intel_count: int  # the deliberate noise (expect 16)


def match(findings: list[EnrichedFinding], intel: list[IntelRecord]) -> IntelMatchResult:
    """Populate each finding's ``.intel`` (and ``.intel_relevance``) in place."""
    index = build_intel_index(intel)
    reference_date = max((r.active_last_seen for r in intel), default=None)
    vuln_cves = {f.vulnerability.cve for f in findings}

    for finding in findings:
        matches = index.get(finding.vulnerability.cve, [])
        finding.intel = list(matches)  # insertion order preserved — one-to-many, not first-only
        if reference_date is not None:
            finding.intel_relevance = {
                r.intel_id: relevance_weight(r, reference_date) for r in matches
            }

    matched = sum(1 for r in intel if r.matched_cve_or_control in vuln_cves)
    return IntelMatchResult(
        findings=findings,
        matched_intel_count=matched,
        unmatched_intel_count=len(intel) - matched,
    )
