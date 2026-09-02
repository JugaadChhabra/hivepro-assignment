"""Derive the "missing compensating controls" tags (§4).

This is factor 5 of the report's rubric and has no single source column — it is
composed from asset and vulnerability attributes. The six tags:

* ``no_edr``                       — asset has no EDR agent (26 assets)
* ``unauthenticated_exploit_path`` — the vuln needs no auth
* ``no_vendor_patch``             — no patch is available
* ``stale_asset_record``          — asset last seen > 30 days ago
* ``no_owner``                    — asset has no owner team
* ``control_deficiency``          — a CTRL-SYN-* row: a control failure, not a
                                    software flaw, so remediation routing differs
"""

from __future__ import annotations

from collections.abc import Iterable

from riskagent.models import EnrichedFinding

_STALE_DAYS = 30


def control_gaps(finding: EnrichedFinding) -> list[str]:
    """Return the gap tags for one finding, in a fixed, deterministic order."""
    tags: list[str] = []
    if not finding.asset.edr_installed:
        tags.append("no_edr")
    if not finding.vulnerability.auth_required:
        tags.append("unauthenticated_exploit_path")
    if not finding.vulnerability.patch_available:
        tags.append("no_vendor_patch")
    if finding.asset.last_seen_days > _STALE_DAYS:
        tags.append("stale_asset_record")
    if finding.asset.owner_team is None:
        tags.append("no_owner")
    if finding.vulnerability.cve.startswith("CTRL-SYN-"):
        tags.append("control_deficiency")
    return tags


def annotate_control_gaps(findings: Iterable[EnrichedFinding]) -> list[EnrichedFinding]:
    """Set ``control_gaps`` on each finding in place; return the same list."""
    result = list(findings)
    for finding in result:
        finding.control_gaps = control_gaps(finding)
    return result
