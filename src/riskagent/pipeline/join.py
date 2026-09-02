"""Join vulnerabilities to their asset and business service (§4, green path).

``vulnerabilities`` LEFT JOIN ``assets`` on ``asset_id``, then LEFT JOIN
``business_services`` on ``business_service``. Both joins are total for this data
(zero orphans, verified), so an orphan means something upstream broke — we raise
rather than silently drop a finding out of the ranking.

Exposure reconciliation: ``vulnerabilities.asset_exposure`` and
``assets.internet_exposed`` both encode exposure. Where they disagree we flag
``exposure_source_conflict`` and take the asset inventory as authoritative — we do
not silently pick one.
"""

from __future__ import annotations

from collections.abc import Iterable

from riskagent.models import Asset, BusinessService, EnrichedFinding, Vulnerability


class OrphanError(ValueError):
    """A join key pointed at a row that does not exist. For this data pack that
    is impossible, so it signals a broken pipeline, not a data variant."""


def transitive_dependent_counts(services: Iterable[BusinessService]) -> dict[str, int]:
    """How many services fail (directly or transitively) if each one fails (§7 blast radius).

    ``X depends_on d`` means X fails when d fails, so X is a dependent of d. We build
    the reverse graph and count reachable dependents. TRAVERSAL USES A VISITED SET —
    the data is acyclic today, but a cycle must terminate, not hang.
    """
    dependents: dict[str, set[str]] = {}  # d -> services that directly depend on d
    for service in services:
        needs = [t.strip() for t in (service.depends_on or "").split(",") if t.strip()]
        for dependency in needs:
            dependents.setdefault(dependency, set()).add(service.business_service)

    counts: dict[str, int] = {}
    for service in services:
        seen: set[str] = set()
        stack = list(dependents.get(service.business_service, ()))
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(dependents.get(node, ()))
        seen.discard(service.business_service)  # a cycle can revisit self; don't count it
        counts[service.business_service] = len(seen)
    return counts


def join(
    vulns: Iterable[Vulnerability],
    assets: Iterable[Asset],
    services: Iterable[BusinessService],
) -> list[EnrichedFinding]:
    asset_by_id = {a.asset_id: a for a in assets}
    service_by_name = {s.business_service: s for s in services}

    # annotate each service with its transitive-dependent count (blast radius, §7)
    counts = transitive_dependent_counts(service_by_name.values())
    for name, svc in service_by_name.items():
        svc.transitive_dependents = counts[name]

    findings: list[EnrichedFinding] = []
    for vuln in vulns:
        asset = asset_by_id.get(vuln.asset_id)
        if asset is None:
            raise OrphanError(
                f"vulnerability {vuln.vuln_id} references unknown asset {vuln.asset_id!r}"
            )
        service = service_by_name.get(asset.business_service)
        if service is None:
            raise OrphanError(
                f"asset {asset.asset_id} references unknown business_service "
                f"{asset.business_service!r}"
            )

        data_flags: list[str] = []
        # asset inventory is authoritative; a disagreement is recorded, not resolved away
        vuln_says_exposed = vuln.asset_exposure == "Internet"
        if vuln_says_exposed != asset.internet_exposed:
            data_flags.append("exposure_source_conflict")
        # cvss range check deferred from phase 1 (models.py): surface a bad value as
        # a flag rather than a hard model bound, so the finding is kept and scored.
        if not (0.0 <= vuln.cvss <= 10.0):
            data_flags.append("cvss_out_of_range")

        findings.append(
            EnrichedFinding(
                vulnerability=vuln,
                asset=asset,
                service=service,
                intel=[],
                data_flags=data_flags,
            )
        )
    return findings
