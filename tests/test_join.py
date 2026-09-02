"""Phase 2 tests: join + control gaps (§4)."""

from __future__ import annotations

import pytest

from riskagent.ingest.csv_loader import load_all
from riskagent.models import Asset, BusinessService, EnrichedFinding, Vulnerability
from riskagent.pipeline.control_gaps import annotate_control_gaps, control_gaps
from riskagent.pipeline.join import OrphanError, join, transitive_dependent_counts


def _joined() -> list[EnrichedFinding]:
    b = load_all()
    return join(b.vulnerabilities, b.assets, b.services)


def test_join_row_count_and_no_orphans() -> None:
    findings = _joined()
    assert len(findings) == 114  # one per vulnerability, none dropped
    # both joins total: every finding carries a real asset and service
    assert all(f.asset is not None and f.service is not None for f in findings)
    assert all(f.asset.asset_id == f.vulnerability.asset_id for f in findings)
    assert all(f.service.business_service == f.asset.business_service for f in findings)


def test_orphan_vuln_raises() -> None:
    b = load_all()
    ghost = b.vulnerabilities[0].model_copy(update={"asset_id": "A-DOES-NOT-EXIST"})
    with pytest.raises(OrphanError):
        join([ghost], b.assets, b.services)


def test_orphan_service_raises() -> None:
    b = load_all()
    ghost_asset = b.assets[0].model_copy(update={"business_service": "No Such Service"})
    vuln = next(v for v in b.vulnerabilities if v.asset_id == ghost_asset.asset_id)
    with pytest.raises(OrphanError):
        join([vuln], [ghost_asset], b.services)


def test_exposure_conflict_flagged_and_asset_authoritative() -> None:
    findings = _joined()
    conflicted = [f for f in findings if "exposure_source_conflict" in f.data_flags]
    # exactly one row disagrees: V-2014 (asset says exposed, vuln says Internal)
    assert [f.vulnerability.vuln_id for f in conflicted] == ["V-2014"]
    f = conflicted[0]
    assert f.vulnerability.asset_exposure == "Internal"
    assert f.asset.internet_exposed is True  # asset inventory is authoritative


def test_cvss_out_of_range_flagged() -> None:
    # Honors the phase-1 deferral: a bad CVSS is surfaced as a flag, not dropped.
    b = load_all()
    bad_vuln: Vulnerability = b.vulnerabilities[0].model_copy(update={"cvss": 11.0})
    asset: Asset = next(a for a in b.assets if a.asset_id == bad_vuln.asset_id)
    findings = join([bad_vuln], [asset], b.services)
    assert "cvss_out_of_range" in findings[0].data_flags


def test_no_edr_tag_counts() -> None:
    b = load_all()
    # The verified invariant lives in the ASSET INVENTORY: 26 of 60 lack EDR.
    assert sum(1 for a in b.assets if not a.edr_installed) == 26
    findings = annotate_control_gaps(join(b.vulnerabilities, b.assets, b.services))
    no_edr = [f for f in findings if "no_edr" in f.control_gaps]
    # Those 26 assets map to 48 findings across only 18 assets — the other 8
    # no-EDR assets have no open vulnerabilities, so they never enter the join.
    assert len(no_edr) == 48
    assert len({f.asset.asset_id for f in no_edr}) == 18
    # the tag is present iff the asset truly lacks EDR
    assert all(not f.asset.edr_installed for f in no_edr)
    assert all(f.asset.edr_installed for f in findings if "no_edr" not in f.control_gaps)


def test_control_gap_tags_trace_to_source() -> None:
    findings = annotate_control_gaps(_joined())
    for f in findings:
        assert ("no_owner" in f.control_gaps) == (f.asset.owner_team is None)
        assert ("no_vendor_patch" in f.control_gaps) == (not f.vulnerability.patch_available)
        assert ("unauthenticated_exploit_path" in f.control_gaps) == (
            not f.vulnerability.auth_required
        )
        assert ("stale_asset_record" in f.control_gaps) == (f.asset.last_seen_days > 30)
        assert ("control_deficiency" in f.control_gaps) == f.vulnerability.cve.startswith(
            "CTRL-SYN-"
        )


def _svc(name: str, depends_on: str | None) -> BusinessService:
    return BusinessService.model_validate(
        {"business_service": name, "business_owner": "o", "business_impact": "x",
         "customer_facing": True, "compliance_scope": "None", "revenue_impact": "Low",
         "rto_hours": 1, "depends_on": depends_on, "risk_appetite": "Low"}
    )


def test_transitive_dependents_match_expected() -> None:
    # §7 blast radius — if these differ, the traversal direction is wrong
    counts = transitive_dependent_counts(load_all().services)
    assert counts["Identity Verification"] == 5
    assert counts["Customer Login"] == 4
    assert counts["Payment Processing"] == 1
    assert counts["Software Delivery"] == 1
    assert counts["Testing Platform"] == 0


def test_transitive_dependents_cycle_terminates() -> None:
    # a cyclic depends_on graph must terminate via the visited set, not hang
    services = [_svc("A", "B"), _svc("B", "C"), _svc("C", "A")]
    counts = transitive_dependent_counts(services)
    assert counts == {"A": 2, "B": 2, "C": 2}  # each reaches the other two, not infinite


def test_empty_depends_on_has_zero_dependents() -> None:
    counts = transitive_dependent_counts([_svc("Lonely", None), _svc("Blank", "")])
    assert counts["Lonely"] == 0
    assert counts["Blank"] == 0


def test_control_gaps_pure_function_no_mutation() -> None:
    # control_gaps() reads, it must not write .control_gaps as a side effect
    b = load_all()
    findings = join(b.vulnerabilities, b.assets, b.services)
    f = findings[0]
    before = list(f.control_gaps)
    _ = control_gaps(f)
    assert f.control_gaps == before
