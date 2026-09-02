"""Phase 3 tests: the deterministic scorer (§4).

Fixtures are hand-built, not loaded from the CSVs, so each test pins a specific
arithmetic property of the weights table rather than whatever the data happens
to produce. Test 6 is the one exception: it asserts a property over all 114.
"""

from __future__ import annotations

from datetime import date

from riskagent.config import REFERENCE_DATE, WEIGHTS
from riskagent.ingest.csv_loader import load_all
from riskagent.models import Asset, BusinessService, EnrichedFinding, IntelRecord, Vulnerability
from riskagent.pipeline.intel_match import match
from riskagent.pipeline.join import join
from riskagent.pipeline.score import score


def make_asset(**overrides: object) -> Asset:
    base: dict[str, object] = {
        "asset_id": "A-TEST",
        "asset_name": "test-box",
        "asset_type": "Web Server",
        "environment": "Production",
        "owner_team": "Blue Team",
        "business_service": "Payment Processing",
        "internet_exposed": False,
        "criticality": "Low",
        "data_classification": "Internal",
        "edr_installed": True,
        "last_seen_days": 5,
        "location": "UAE",
        "vendor_product": "nginx 1.22",
    }
    base.update(overrides)
    return Asset.model_validate(base)


def make_vuln(**overrides: object) -> Vulnerability:
    base: dict[str, object] = {
        "vuln_id": "V-TEST",
        "asset_id": "A-TEST",
        "vulnerability_name": "Test Vuln",
        "cve": "CVE-2024-0001",
        "severity": "High",
        "cvss": 5.0,
        "exploit_available": False,
        "patch_available": True,
        "days_open": 5,
        "asset_exposure": "Internal",
        "auth_required": True,
        "status": "Open",
        "affected_component": "Web Framework",
    }
    base.update(overrides)
    return Vulnerability.model_validate(base)


def make_service(**overrides: object) -> BusinessService:
    base: dict[str, object] = {
        "business_service": "Payment Processing",
        "business_owner": "CFO",
        "business_impact": "Payments fail",
        "customer_facing": False,
        "compliance_scope": "None",
        "revenue_impact": "Low",
        "rto_hours": 4,
        "depends_on": None,
        "risk_appetite": "Low",
    }
    base.update(overrides)
    return BusinessService.model_validate(base)


def make_intel(**overrides: object) -> IntelRecord:
    base: dict[str, object] = {
        "intel_id": "TI-TEST",
        "threat_actor": "TestActor",
        "campaign_name": "TestCampaign",
        "target_sector": "Financial Services",
        "target_region": "Middle East",
        "matched_cve_or_control": "CVE-2024-0001",
        "exploit_maturity": "Weaponized",
        "active_last_seen": date(2026, 4, 22),
        "ransomware_association": True,
        "confidence": "High",
        "summary": "test",
    }
    base.update(overrides)
    return IntelRecord.model_validate(base)


def make_finding(
    *,
    asset: Asset | None = None,
    vuln: Vulnerability | None = None,
    service: BusinessService | None = None,
    intel: list[IntelRecord] | None = None,
    kev_status: str = "unknown",
) -> EnrichedFinding:
    return EnrichedFinding(
        vulnerability=vuln or make_vuln(),
        asset=asset or make_asset(),
        service=service or make_service(),
        intel=intel if intel is not None else [],
        kev_status=kev_status,
    )


def test_worked_example_internal_cvss10_ranks_below_exposed_gateway() -> None:
    # Internal dev server, CVSS 10.0, no exploit, no intel.
    internal = make_finding(
        asset=make_asset(
            environment="Development", internet_exposed=False, criticality="Low"
        ),
        vuln=make_vuln(cvss=10.0, exploit_available=False, auth_required=True),
        service=make_service(customer_facing=False, compliance_scope="None", revenue_impact="Low"),
        intel=[],
    )
    # Internet-facing payment gateway, CVSS 8.1, exploit available, ransomware intel.
    gateway = make_finding(
        asset=make_asset(
            environment="Production", internet_exposed=True, criticality="Critical"
        ),
        vuln=make_vuln(cvss=8.1, exploit_available=True, auth_required=False),
        service=make_service(
            customer_facing=True, compliance_scope="PCI DSS", revenue_impact="Critical"
        ),
        intel=[make_intel(ransomware_association=True)],
    )
    assert score(internal).total < score(gateway).total


def test_internet_exposed_adds_exactly_18() -> None:
    closed = make_finding(asset=make_asset(internet_exposed=False))
    opened = make_finding(asset=make_asset(internet_exposed=True))
    assert score(opened).total - score(closed).total == 18.0


def test_ransomware_intel_adds_exactly_8() -> None:
    # identical single intel record, differing ONLY in ransomware_association
    without = make_finding(intel=[make_intel(ransomware_association=False)])
    with_rw = make_finding(intel=[make_intel(ransomware_association=True)])
    assert score(with_rw).total - score(without).total == 8.0


def test_empty_intel_scores_zero_adversary_and_does_not_crash() -> None:
    breakdown = score(make_finding(intel=[]))
    assert breakdown.adversary == 0.0
    assert breakdown.total >= 0.0  # did not crash, produced a number


def test_score_is_deterministic_including_reasons_order() -> None:
    finding = make_finding(
        asset=make_asset(internet_exposed=True, criticality="High"),
        vuln=make_vuln(cvss=7.5, exploit_available=True),
        intel=[make_intel()],
    )
    a = score(finding)
    b = score(finding)
    assert a == b
    assert a.reasons == b.reasons  # same order, not just same set


def test_reasons_non_empty_for_all_114_real_findings() -> None:
    b = load_all()
    findings = match(join(b.vulnerabilities, b.assets, b.services), b.intel).findings
    assert len(findings) == 114
    for f in findings:
        breakdown = score(f)
        assert breakdown.reasons, f"empty reasons for {f.vulnerability.vuln_id}"


def test_staleness_flags_but_adds_zero_points() -> None:
    fresh = make_finding(asset=make_asset(last_seen_days=5))
    stale = make_finding(asset=make_asset(last_seen_days=90))
    fresh_score = score(fresh)
    stale_score = score(stale)
    assert stale_score.total == fresh_score.total  # staleness contributes nothing
    assert any("stale asset record" in r for r in stale_score.reasons)
    assert not any("stale asset record" in r for r in fresh_score.reasons)


def test_blast_radius_scores_transitive_dependents() -> None:
    zero = make_finding(service=make_service())  # transitive_dependents defaults 0
    high = make_finding(service=make_service(transitive_dependents=5))
    low = make_finding(service=make_service(transitive_dependents=2))
    assert score(zero).blast_radius == 0.0
    assert score(high).blast_radius == WEIGHTS["blast_radius"]["dependents_high"]  # >=3 -> +6
    assert score(low).blast_radius == WEIGHTS["blast_radius"]["dependents_low"]  # 1..2 -> +3


def test_campaign_objective_is_dormant_for_all_114() -> None:
    # the objective term depends on phase-7 report_parser; it must contribute 0 now
    b = load_all()
    findings = match(join(b.vulnerabilities, b.assets, b.services), b.intel).findings
    assert all(f.campaign_objective is None for f in findings)
    # a finding's blast_radius equals its dependents-only contribution (no objective points)
    for f in findings:
        dependents = f.service.transitive_dependents
        expected = 6.0 if dependents >= 3 else 3.0 if dependents >= 1 else 0.0
        assert score(f).blast_radius == expected


def test_every_scored_enum_value_is_mapped() -> None:
    """Guard against the maturity bug recurring: every enum value the scorer looks
    up in a TOTAL map must have a defined branch, so none can silently score 0.

    Covers the two total lookup maps score.py currently reads (maturity,
    criticality); if a third is added, extend this list. Predicate-style enums
    (environment == Production, revenue_impact in {High, Critical}) are exempt by
    design — non-matching values legitimately score 0, there is no map to omit
    a value from.
    """
    b = load_all()
    lookups: dict[str, set[str]] = {
        "maturity": {i.exploit_maturity for i in b.intel},
        "criticality": {str(a.criticality) for a in b.assets},
    }
    for group, observed in lookups.items():
        missing = observed - set(WEIGHTS[group])
        assert not missing, f"WEIGHTS[{group!r}] does not map: {missing}"


def test_active_exploitation_scores_maturity() -> None:
    # regression for the enum gap: Active Exploitation must score, not zero out.
    active = make_intel(exploit_maturity="Active Exploitation", ransomware_association=False)
    poc = make_intel(exploit_maturity="Proof of Concept", ransomware_association=False)
    delta = score(make_finding(intel=[active])).total - score(make_finding(intel=[poc])).total
    expected = WEIGHTS["maturity"]["Active Exploitation"] - WEIGHTS["maturity"]["Proof of Concept"]
    assert delta == expected == 3.0


def test_maturity_takes_strongest_across_records() -> None:
    weak = make_intel(intel_id="TI-A", exploit_maturity="Proof of Concept")
    strong = make_intel(intel_id="TI-B", exploit_maturity="Active Exploitation")
    strong_only = score(make_finding(intel=[strong])).adversary
    weak_only = score(make_finding(intel=[weak])).adversary
    combined_ab = score(make_finding(intel=[weak, strong])).adversary
    combined_ba = score(make_finding(intel=[strong, weak])).adversary
    # order-invariant AND it is the STRONGEST that wins — a min()-for-max()
    # regression would make combined == weak_only and fail the first assert.
    assert combined_ab == combined_ba == strong_only
    assert strong_only > weak_only


def test_reference_date_default_matches_config() -> None:
    # recency uses the pinned config date, not wall-clock: a record 20 days before
    # REFERENCE_DATE counts as recent regardless of when the test runs.
    recent = make_intel(active_last_seen=date(2026, 4, 4))  # 20d before 2026-04-24
    f = make_finding(intel=[recent])
    assert any("active within" in r for r in score(f).reasons)
    assert REFERENCE_DATE == date(2026, 4, 24)  # noqa: SIM300 — literal-on-right reads clearest here
