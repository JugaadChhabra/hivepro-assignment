"""Deterministic additive risk score (§4).

``score()`` is a pure function ``EnrichedFinding -> ScoreBreakdown``: no I/O, no
model calls, no mutation of the input, no wall-clock. Every branch that fires
appends one human-readable string to ``reasons`` so the total is reconstructable
by hand — this is the evidence the LLM later turns into prose, and the audit
trail behind the ranking.

The LLM decides nothing here. Rank follows from ``total``; ``total`` follows from
the weights in ``config.py`` and the finding's own fields.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date

from riskagent import config
from riskagent.models import EnrichedFinding, IntelRecord, ScoreBreakdown

Weights = Mapping[str, Mapping[str, float]]


def _fits_region_or_sector(record: IntelRecord) -> bool:
    return record.target_region == config.HOME_REGION or record.target_sector in config.FIT_SECTORS


def score(
    finding: EnrichedFinding,
    *,
    weights: Weights | None = None,
    reference_date: date | None = None,
) -> ScoreBreakdown:
    w = weights if weights is not None else config.WEIGHTS
    ref = reference_date if reference_date is not None else config.REFERENCE_DATE
    reasons: list[str] = []
    asset = finding.asset
    vuln = finding.vulnerability
    service = finding.service

    # --- Exposure (max 25) ---
    exposure = 0.0
    if asset.internet_exposed:
        pts = w["exposure"]["internet_exposed"]
        exposure += pts
        reasons.append(f"internet-exposed (+{pts:g})")
    if asset.environment == "Production":
        pts = w["exposure"]["production"]
        exposure += pts
        reasons.append(f"production environment (+{pts:g})")

    # --- Exploitability (max 22) ---
    exploitability = 0.0
    # out-of-range cvss is already flagged in join; clamp here so it can't inflate the term
    cvss = min(max(vuln.cvss, 0.0), 10.0)
    cvss_pts = cvss / 10.0 * w["exploitability"]["cvss_scale"]
    if cvss_pts > 0:
        exploitability += cvss_pts
        if vuln.cvss != cvss:
            reasons.append(
                f"CVSS {vuln.cvss:g} out-of-range, clamped to {cvss:g} (+{cvss_pts:.2f})"
            )
        else:
            reasons.append(f"CVSS {vuln.cvss:g} (+{cvss_pts:.2f})")
    if vuln.exploit_available:
        pts = w["exploitability"]["exploit_available"]
        exploitability += pts
        reasons.append(f"public exploit available (+{pts:g})")
    if not vuln.auth_required:
        pts = w["exploitability"]["no_auth"]
        exploitability += pts
        reasons.append(f"no authentication required (+{pts:g})")
    if finding.kev_status == "listed":
        pts = w["exploitability"]["kev_listed"]
        exploitability += pts
        reasons.append(f"listed in CISA KEV (+{pts:g})")

    # --- Adversary (max 25) — entirely from matched intel; empty intel => 0 ---
    adversary = 0.0
    intel = finding.intel
    if intel:
        pts = w["adversary"]["intel_match"]
        adversary += pts
        reasons.append(f"matched threat intel (+{pts:g})")
        if any(r.ransomware_association for r in intel):
            pts = w["adversary"]["ransomware"]
            adversary += pts
            reasons.append(f"ransomware-associated campaign (+{pts:g})")
        # exploit maturity: take the strongest level across this finding's records.
        # Direct indexing (not .get) so an unmapped enum value crashes loudly here
        # rather than silently scoring zero.
        strongest = max(intel, key=lambda r: w["maturity"][r.exploit_maturity])
        maturity_pts = w["maturity"][strongest.exploit_maturity]
        adversary += maturity_pts
        if maturity_pts > 0:
            reasons.append(f"exploit maturity {strongest.exploit_maturity} (+{maturity_pts:g})")
        if any(_fits_region_or_sector(r) for r in intel):
            pts = w["adversary"]["region_or_sector_fit"]
            adversary += pts
            reasons.append(f"region/sector fit (+{pts:g})")
        if any((ref - r.active_last_seen).days <= config.RECENT_INTEL_DAYS for r in intel):
            pts = w["adversary"]["recent_activity"]
            adversary += pts
            reasons.append(f"intel active within {config.RECENT_INTEL_DAYS}d (+{pts:g})")

    # --- Business (max 20) ---
    business = 0.0
    # total map: every criticality level is defined (Low -> 0), so an unmapped
    # value crashes loudly rather than silently scoring zero.
    criticality_pts = w["criticality"][asset.criticality]
    business += criticality_pts
    if criticality_pts > 0:
        reasons.append(f"{asset.criticality}-criticality asset (+{criticality_pts:g})")
    if service.customer_facing:
        pts = w["business"]["customer_facing"]
        business += pts
        reasons.append(f"customer-facing service (+{pts:g})")
    scope_tokens = {token.strip() for token in service.compliance_scope.split(",")}
    if scope_tokens & config.PCI_GDPR_TOKENS:
        pts = w["business"]["compliance_pci_gdpr"]
        business += pts
        reasons.append(f"PCI/GDPR compliance scope (+{pts:g})")
    if service.revenue_impact in {"High", "Critical"}:
        pts = w["business"]["revenue_high_or_critical"]
        business += pts
        reasons.append(f"{service.revenue_impact.lower()} revenue impact (+{pts:g})")

    # --- Control gap (max 10) ---
    control_gap = 0.0
    if not asset.edr_installed:
        pts = w["control_gap"]["no_edr"]
        control_gap += pts
        reasons.append(f"no EDR agent (+{pts:g})")
    if not vuln.patch_available:
        pts = w["control_gap"]["no_vendor_patch"]
        control_gap += pts
        reasons.append(f"no vendor patch (+{pts:g})")
    if vuln.days_open > config.DAYS_OPEN_THRESHOLD:
        pts = w["control_gap"]["days_open"]
        control_gap += pts
        reasons.append(f"open {vuln.days_open} days (+{pts:g})")

    # --- Staleness: FLAG ONLY, contributes ZERO to the total (§4 point 2) ---
    if asset.last_seen_days > config.STALE_LAST_SEEN_DAYS:
        reasons.append(
            f"stale asset record: last seen {asset.last_seen_days}d ago (+0, flag only)"
        )

    total = exposure + exploitability + adversary + business + control_gap
    return ScoreBreakdown(
        exposure=exposure,
        exploitability=exploitability,
        adversary=adversary,
        business=business,
        control_gap=control_gap,
        total=total,
        reasons=reasons,
    )


def score_all(
    findings: list[EnrichedFinding],
    *,
    weights: Weights | None = None,
    reference_date: date | None = None,
) -> list[EnrichedFinding]:
    """Score every finding and set ``.score`` in place; return the same list.

    All 114 are scored — never retrieve-then-rank, never truncate before scoring.
    """
    for finding in findings:
        finding.score = score(finding, weights=weights, reference_date=reference_date)
    return findings
