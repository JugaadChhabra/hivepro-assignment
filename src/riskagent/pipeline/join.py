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


def join(
    vulns: Iterable[Vulnerability],
    assets: Iterable[Asset],
    services: Iterable[BusinessService],
) -> list[EnrichedFinding]:
    asset_by_id = {a.asset_id: a for a in assets}
    service_by_name = {s.business_service: s for s in services}

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
