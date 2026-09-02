"""Phase 2 tests: exact-key intel matching (§4).

The last test (lowercase near-miss) is the important one: it proves the matcher
does not normalise, which is what keeps the 16 noise records from attaching.
"""

from __future__ import annotations

from datetime import date

from riskagent.ingest.csv_loader import load_all
from riskagent.models import EnrichedFinding, IntelRecord
from riskagent.pipeline.intel_match import match, relevance_weight
from riskagent.pipeline.join import join


def _intel(
    *, region: str, sector: str, confidence: str, last_seen: date
) -> IntelRecord:
    return IntelRecord(
        intel_id="TI-X",
        threat_actor="X",
        campaign_name="X",
        target_sector=sector,
        target_region=region,
        matched_cve_or_control="CVE-0000-0000",
        exploit_maturity="Weaponized",
        active_last_seen=last_seen,
        ransomware_association=False,
        confidence=confidence,
        summary="x",
    )


def _matched() -> tuple[list[EnrichedFinding], list[IntelRecord]]:
    b = load_all()
    findings = join(b.vulnerabilities, b.assets, b.services)
    result = match(findings, b.intel)
    return result.findings, b.intel


def test_matched_and_unmatched_counts() -> None:
    b = load_all()
    findings = join(b.vulnerabilities, b.assets, b.services)
    result = match(findings, b.intel)
    assert result.matched_intel_count == 24
    assert result.unmatched_intel_count == 16
    assert result.matched_intel_count + result.unmatched_intel_count == len(b.intel) == 40


def test_noise_records_match_nothing() -> None:
    findings, intel = _matched()
    # Real CVEs for products TawasolPay does not run, plus non-CVE keys.
    noise_keys = {"CVE-2024-3400", "CVE-2025-0282", "PHISH-SYN-001", "INSIDER-SYN-001"}
    # each noise key exists in the intel feed but matches no finding's CVE
    present_in_feed = {r.matched_cve_or_control for r in intel}
    assert noise_keys <= present_in_feed
    matched_keys = {r.matched_cve_or_control for f in findings for r in f.intel}
    assert noise_keys.isdisjoint(matched_keys)
    # and none of those intel records is attached to any finding
    noise_ids = {r.intel_id for r in intel if r.matched_cve_or_control in noise_keys}
    attached_ids = {r.intel_id for f in findings for r in f.intel}
    assert noise_ids.isdisjoint(attached_ids)


def test_cve_with_two_intel_records_returns_both() -> None:
    findings, _ = _matched()
    # CVE-2024-4577 carries two intel records (TI-3013, TI-3016) — both, not first.
    fs = [f for f in findings if f.vulnerability.cve == "CVE-2024-4577"]
    assert fs, "expected at least one finding for CVE-2024-4577"
    for f in fs:
        assert {r.intel_id for r in f.intel} == {"TI-3013", "TI-3016"}


def test_positive_control_fortinet_matches() -> None:
    findings, _ = _matched()
    fs = [f for f in findings if f.vulnerability.cve == "CVE-2024-21762"]
    assert fs, "expected a Fortinet CVE-2024-21762 finding"
    assert all("TI-3001" in {r.intel_id for r in f.intel} for f in fs)


def test_lowercase_near_miss_does_not_match() -> None:
    """A lowercase key must NOT attach to an uppercase CVE — no normalisation."""
    b = load_all()
    findings = join(b.vulnerabilities, b.assets, b.services)
    # fabricate a record whose only difference from a real match is letter case
    decoy = IntelRecord(
        intel_id="TI-DECOY",
        threat_actor="LowercaseGoblin",
        campaign_name="Case Confusion",
        target_sector="Financial Services",
        target_region="Middle East",
        matched_cve_or_control="cve-2024-21762",  # lowercase of a real, matching CVE
        exploit_maturity="Weaponized",
        active_last_seen=date(2026, 4, 22),
        ransomware_association=True,
        confidence="High",
        summary="decoy",
    )
    result = match(findings, [*b.intel, decoy])
    fortinet = [f for f in result.findings if f.vulnerability.cve == "CVE-2024-21762"]
    assert fortinet
    for f in fortinet:
        ids = {r.intel_id for r in f.intel}
        assert "TI-3001" in ids  # the real, exact match still lands
        assert "TI-DECOY" not in ids  # the lowercase decoy does not
    # the decoy inflates the unmatched count, never the matched one
    assert result.matched_intel_count == 24
    assert result.unmatched_intel_count == 17


def test_relevance_weight_is_separate_from_match() -> None:
    findings, _ = _matched()
    for f in findings:
        # weight exists for exactly the matched records, but a match is a match
        # regardless of its weight (weights never gate membership)
        assert set(f.intel_relevance) == {r.intel_id for r in f.intel}
        assert all(0.0 <= w <= 1.0 for w in f.intel_relevance.values())


def test_relevance_weight_formula_pinned() -> None:
    """Pin the weight to a hand calculation so a bug in the graders is caught.

    weight = mean(region, sector, confidence, recency), each in [0,1].
    """
    ref = date(2026, 5, 1)
    # strongest: Middle East(1.0) + Financial Services(1.0) + High(1.0) + <=30d(1.0)
    strong = _intel(
        region="Middle East", sector="Financial Services", confidence="High",
        last_seen=date(2026, 4, 22),
    )
    assert relevance_weight(strong, ref) == 1.0
    # middling: Global(0.5) + All Sectors(0.6) + Medium(0.6) + 60d recency(0.6)
    mid = _intel(
        region="Global", sector="All Sectors", confidence="Medium",
        last_seen=date(2026, 3, 2),  # 60 days before ref
    )
    assert relevance_weight(mid, ref) == round((0.5 + 0.6 + 0.6 + 0.6) / 4, 4)  # 0.575
    # weakest: other region(0.2) + other sector(0.3) + Low(0.3) + >90d(0.3)
    weak = _intel(
        region="Antarctica", sector="Agriculture", confidence="Low",
        last_seen=date(2025, 1, 1),
    )
    assert relevance_weight(weak, ref) == round((0.2 + 0.3 + 0.3 + 0.3) / 4, 4)  # 0.275
