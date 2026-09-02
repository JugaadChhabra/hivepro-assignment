"""Apply parsed MDR campaigns to findings (§3, §4): objective + source cross-check.

Two jobs, both keyed on the exact CVE string (no fuzzy matching):

1. ``campaign_objective`` — a finding whose CVE sits in a campaign's ``cve_chain``
   inherits that campaign's objective. This activates the consequence term the
   scorer wired dormant in phase 6. Chains are disjoint in this data; overlap
   would be ambiguous, so we assert against it.

2. Cross-check report vs ``threat_intelligence.csv`` — DO NOT MERGE. Disagreement
   between two intel sources is a finding, not a conflict to resolve silently.
   Direction is report→CSV: every CVE the report attributes to an actor must be
   corroborated by a CSV record for the same actor (the §3 CrimsonJackal example).
   The CSV may carry MORE associations than the report — that is richness, not a
   conflict. On the corroborated pairs we also compare ransomware association; the
   CSV wins (scoring already reads the CSV's flag), and the disagreement is flagged.
   On real data: zero CVE conflicts, one ransomware conflict (WinterViper).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from riskagent.ingest.report_parser import Campaign, Objective
from riskagent.models import EnrichedFinding, IntelRecord

CVE_CONFLICT_FLAG = "report_cve_uncorroborated"
RANSOMWARE_CONFLICT_FLAG = "intel_ransomware_conflict"


@dataclass(frozen=True)
class CrossCheckConflict:
    actor: str
    cve: str
    kind: Literal["cve_uncorroborated", "ransomware_association"]
    detail: str


def objective_by_cve(campaigns: list[Campaign]) -> dict[str, Objective]:
    """Map each chained CVE to its campaign objective. Chains must be disjoint."""
    mapping: dict[str, Objective] = {}
    for c in campaigns:
        for cve in c.cve_chain:
            prior = mapping.get(cve)
            if prior is not None and prior != c.objective:
                raise ValueError(
                    f"CVE {cve} maps to two objectives ({prior}, {c.objective}) — ambiguous"
                )
            mapping[cve] = c.objective
    return mapping


def cross_check(campaigns: list[Campaign], intel: list[IntelRecord]) -> list[CrossCheckConflict]:
    """Corroborate the report's actor→CVE claims against the CSV; compare ransomware.

    report→CSV: a report claim uncorroborated by any CSV record is a conflict. The
    reverse (CSV richer than the report) is not. On corroborated pairs, a ransomware
    disagreement is a second, separate conflict."""
    csv_actor_cves = {(r.threat_actor, r.matched_cve_or_control) for r in intel}
    csv_by_actor_cve: dict[tuple[str, str], list[IntelRecord]] = {}
    for r in intel:
        csv_by_actor_cve.setdefault((r.threat_actor, r.matched_cve_or_control), []).append(r)

    conflicts: list[CrossCheckConflict] = []
    for c in campaigns:
        for cve in c.cve_chain:
            if (c.actor, cve) not in csv_actor_cves:
                conflicts.append(CrossCheckConflict(
                    c.actor, cve, "cve_uncorroborated",
                    f"report attributes {cve} to {c.actor}; no CSV record corroborates it",
                ))
                continue
            for r in csv_by_actor_cve[(c.actor, cve)]:
                if r.ransomware_association != c.ransomware:
                    conflicts.append(CrossCheckConflict(
                        c.actor, cve, "ransomware_association",
                        f"{c.actor}/{cve}: report ransomware={c.ransomware}, "
                        f"CSV {r.intel_id} ransomware={r.ransomware_association} — CSV preferred",
                    ))
    return conflicts


def apply_campaigns(
    findings: list[EnrichedFinding],
    campaigns: list[Campaign],
    intel: list[IntelRecord],
) -> list[CrossCheckConflict]:
    """Set campaign_objective and append cross-check flags in place. Returns the
    conflicts (also surfaced in the trace)."""
    objective = objective_by_cve(campaigns)
    conflicts = cross_check(campaigns, intel)
    # a finding carries a conflict flag if its CVE is the conflicting one
    cve_conflicts = {c.cve for c in conflicts if c.kind == "cve_uncorroborated"}
    ransomware_conflicts = {c.cve for c in conflicts if c.kind == "ransomware_association"}

    for f in findings:
        cve = f.vulnerability.cve
        obj = objective.get(cve)
        if obj is not None:
            f.campaign_objective = obj
        if cve in cve_conflicts and CVE_CONFLICT_FLAG not in f.data_flags:
            f.data_flags.append(CVE_CONFLICT_FLAG)
        if cve in ransomware_conflicts and RANSOMWARE_CONFLICT_FLAG not in f.data_flags:
            f.data_flags.append(RANSOMWARE_CONFLICT_FLAG)
    return conflicts
