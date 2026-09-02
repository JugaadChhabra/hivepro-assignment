"""Select the top-N risks for the brief (§6).

Sort by ``score.total``, then DEDUPE BEFORE TRUNCATING. Without the dedupe, four
of the top five would be two CVEs counted twice: vpn-edge-01/02 carry identical
Fortinet findings and load-balancer-prod-01/02 carry identical CitrixBleed
findings. We group on ``(cve, vulnerability_name)``, collapse to one entry with
``affected_assets: list[str]``, keep the highest-scoring representative, and only
then take the top N.
"""

from __future__ import annotations

from dataclasses import dataclass

from riskagent.models import EnrichedFinding, ScoreBreakdown


@dataclass(frozen=True)
class SelectedRisk:
    rank: int
    cve: str
    vulnerability_name: str
    affected_assets: list[str]  # every asset carrying this (cve, name), deduped
    affected_environments: list[str]  # environments those assets span (e.g. Production, Staging)
    finding: EnrichedFinding  # the highest-scoring representative

    @property
    def score(self) -> ScoreBreakdown:
        assert self.finding.score is not None  # select() only accepts scored findings
        return self.finding.score


def _total(finding: EnrichedFinding) -> float:
    assert finding.score is not None
    return finding.score.total


def select(
    findings: list[EnrichedFinding],
    *,
    top_n: int = 5,
    per_service_cap: int | None = None,
) -> list[SelectedRisk]:
    """Dedupe on (cve, vulnerability_name), then take the top N by score.

    ``per_service_cap`` optionally limits how many entries one business service
    may contribute, so the brief is not entirely Remote Access. Off by default.
    """
    scored = [f for f in findings if f.score is not None]

    groups: dict[tuple[str, str], list[EnrichedFinding]] = {}
    for finding in scored:
        key = (finding.vulnerability.cve, finding.vulnerability.vulnerability_name)
        groups.setdefault(key, []).append(finding)

    collapsed: list[tuple[EnrichedFinding, list[str], list[str]]] = []
    for group in groups.values():
        representative = max(group, key=_total)
        assets = sorted({f.asset.asset_name for f in group})
        environments = sorted({str(f.asset.environment) for f in group})
        collapsed.append((representative, assets, environments))

    # stable sort by score desc — deterministic tie-breaking by insertion order
    collapsed.sort(key=lambda item: _total(item[0]), reverse=True)

    if per_service_cap is not None:
        counts: dict[str, int] = {}
        capped: list[tuple[EnrichedFinding, list[str], list[str]]] = []
        for rep, assets, environments in collapsed:
            service = rep.service.business_service
            if counts.get(service, 0) >= per_service_cap:
                continue
            counts[service] = counts.get(service, 0) + 1
            capped.append((rep, assets, environments))
        collapsed = capped

    return [
        SelectedRisk(
            rank=index + 1,
            cve=rep.vulnerability.cve,
            vulnerability_name=rep.vulnerability.vulnerability_name,
            affected_assets=assets,
            affected_environments=environments,
            finding=rep,
        )
        for index, (rep, assets, environments) in enumerate(collapsed[:top_n])
    ]
