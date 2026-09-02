"""Phase 4 FAST tests: retrieval logic against a fake store (§5).

No network, no chromadb, no model weights — these run in the CI gate. Retrieval
QUALITY against the real catalog + real embeddings lives in test_rag_integration.py
behind the `network` marker. This split keeps the interesting logic (collapse,
family filter, fallback, raise) covered even when csrc.nist.gov is unreachable.
"""

from __future__ import annotations

import re

import pytest

from fakes import FakeControlStore, mini_controls
from riskagent.ingest.csv_loader import load_all
from riskagent.models import Asset, BusinessService, EnrichedFinding, Vulnerability
from riskagent.pipeline.control_gaps import annotate_control_gaps
from riskagent.pipeline.join import join
from riskagent.rag.families import FAMILY_HINTS, classify_finding_type
from riskagent.rag.index import chunk_text
from riskagent.rag.retrieve import retrieve

# The 22 finding types the golden set's retrieval labels (R01-R22) exercise.
_GOLDEN_FINDING_TYPES = {
    "unpatched_software", "end_of_life_software", "exposed_admin_interface", "missing_edr",
    "excessive_privilege", "audit_logging_disabled", "missing_encryption_at_rest",
    "orphaned_asset", "backup_deficiency", "dr_not_tested", "authentication_bypass",
    "credential_reuse", "secrets_exposed", "public_storage_policy", "firewall_misconfiguration",
    "input_validation", "insecure_direct_object_reference", "session_management",
    "missing_rate_limiting", "certificate_expiry", "data_masking_absent",
    "container_misconfiguration",
}


def _finding(*, name: str = "x", comp: str = "x", gaps: list[str] | None = None) -> EnrichedFinding:
    asset = Asset.model_validate(
        {"asset_id": "A-9", "asset_name": "b", "asset_type": "x", "environment": "Production",
         "owner_team": "T", "business_service": "S", "internet_exposed": True,
         "criticality": "High", "data_classification": "x", "edr_installed": True,
         "last_seen_days": 1, "location": "UAE", "vendor_product": "x"}
    )
    vuln = Vulnerability.model_validate(
        {"vuln_id": "V-9", "asset_id": "A-9", "vulnerability_name": name, "cve": "CVE-2024-0001",
         "severity": "High", "cvss": 8.0, "exploit_available": True, "patch_available": False,
         "days_open": 10, "asset_exposure": "Internet", "auth_required": False, "status": "Open",
         "affected_component": comp}
    )
    service = BusinessService.model_validate(
        {"business_service": "S", "business_owner": "O", "business_impact": "x",
         "customer_facing": True, "compliance_scope": "PCI DSS", "revenue_impact": "High",
         "rto_hours": 1, "depends_on": None, "risk_appetite": "Low"}
    )
    return EnrichedFinding(
        vulnerability=vuln, asset=asset, service=service, intel=[], control_gaps=gaps or []
    )


def test_collapse_to_base_carries_enhancements() -> None:
    # SI-2(5) is the closest hit; it must collapse to SI-2 (the citation) while
    # carrying SI-2(5) as an enhancement — the specificity the base text lacks.
    store = FakeControlStore(
        mini_controls(), {"SI-2(5)": 0.30, "SI-7": 0.40, "SI-2": 0.55, "RA-5": 0.60}
    )
    result = retrieve(_finding(), store, finding_type="unpatched_software")
    ids = [c.control_id for c in result.chunks]
    assert ids[0] == "SI-2"  # base is the citation, not SI-2(5)
    assert "SI-2(5)" in result.chunks[0].enhancement_ids  # enhancement carried
    assert result.chunks[0].distance == 0.30  # best distance across base+enhancement
    assert ids == ["SI-2", "SI-7", "RA-5"]  # distinct base controls, no enhancement flooding


def test_family_filter_narrows_results() -> None:
    # AC-3 is closest overall but out of family for unpatched_software {SI, RA}.
    store = FakeControlStore(
        mini_controls(), {"AC-3": 0.10, "SI-2": 0.40, "SI-7": 0.45, "RA-5": 0.50}
    )
    hint = FAMILY_HINTS["unpatched_software"]
    filtered = store.query("q", families=hint, k=8)
    unfiltered = store.query("q", families=None, k=8)
    assert all(c.family in hint for c in filtered)
    assert any(c.family not in hint for c in unfiltered)  # filter removed AC-3
    assert [c.control_id for c in filtered] != [c.control_id for c in unfiltered]


def test_fallback_fires_on_unknown_finding_type() -> None:
    store = FakeControlStore(mini_controls(), {"AC-3": 0.2, "SI-2": 0.3})
    result = retrieve(_finding(), store, finding_type="unknown")
    assert "family_filter_fallback" in result.flags
    assert result.chunks  # still returns results, just unfiltered


def test_unmapped_finding_type_raises() -> None:
    # A type that is neither mapped nor the "unknown" sentinel is a bug, not a fallback.
    store = FakeControlStore(mini_controls(), {"SI-2": 0.3})
    with pytest.raises(ValueError, match="no family mapping"):
        retrieve(_finding(), store, finding_type="not_a_real_type")


def test_threshold_fallback_flags() -> None:
    # Family {CP} best hit is worse than the threshold; retry unfiltered and flag.
    store = FakeControlStore(mini_controls(), {"CP-9": 1.5, "SI-2": 0.2})
    result = retrieve(_finding(), store, finding_type="backup_deficiency", threshold=1.0)
    assert "family_filter_fallback" in result.flags
    assert result.chunks[0].control_id == "SI-2"  # the closer, out-of-family hit


def test_retrieval_is_deterministic() -> None:
    store = FakeControlStore(mini_controls(), {"SI-2(5)": 0.3, "SI-7": 0.4, "RA-5": 0.5})
    a = retrieve(_finding(), store, finding_type="unpatched_software")
    b = retrieve(_finding(), store, finding_type="unpatched_software")
    assert [(c.control_id, c.distance) for c in a.chunks] == [
        (c.control_id, c.distance) for c in b.chunks
    ]


def test_chunk_text_has_no_contamination() -> None:
    # chunk_text is the ONLY text embedded; it must carry no CVSS/asset_id/CVE.
    asset_id = re.compile(r"\bA-1\d{3}\b")
    cvss = re.compile(r"cvss", re.IGNORECASE)
    cve = re.compile(r"\bCVE-\d{4}\b")
    for control in mini_controls():
        text = chunk_text(control)
        assert not asset_id.search(text)
        assert not cvss.search(text)
        assert not cve.search(text)


def test_classifier_outputs_are_all_mapped() -> None:
    # Every finding_type the classifier emits over the real 114 must be mapped
    # (or the "unknown" sentinel) — so retrieve never raises on real data.
    b = load_all()
    findings = annotate_control_gaps(join(b.vulnerabilities, b.assets, b.services))
    emitted = {classify_finding_type(f) for f in findings}
    unmapped = emitted - set(FAMILY_HINTS) - {"unknown"}
    assert not unmapped, f"classifier emits unmapped finding_types: {unmapped}"


def test_family_hints_cover_all_22_golden_types() -> None:
    missing = _GOLDEN_FINDING_TYPES - set(FAMILY_HINTS)
    assert not missing, f"FAMILY_HINTS missing golden finding_types: {missing}"


def test_gap_controls_are_a_separate_rule_channel() -> None:
    # no_edr must surface SI-3 by RULE — in gap_controls, not by evicting a chunk.
    store = FakeControlStore(mini_controls(), {"SI-2": 0.2, "SI-7": 0.3, "RA-5": 0.4})
    finding = _finding(comp="FortiOS firmware", gaps=["no_vendor_patch", "no_edr"])
    result = retrieve(finding, store, finding_type="unpatched_software")
    chunk_ids = {c.control_id for c in result.chunks}
    gap_ids = {g.control_id for g in result.gap_controls}
    assert "SI-3" in gap_ids  # guaranteed by the no_edr rule
    assert "SI-3" not in chunk_ids  # it did NOT displace a retrieval hit
    assert all(g.source == "rule" for g in result.gap_controls)
    assert all(g.gap == "no_edr" for g in result.gap_controls if g.control_id == "SI-3")


def test_gap_control_deduped_against_retrieval_hit() -> None:
    # if SI-3 is already a retrieval hit, it must NOT be duplicated in gap_controls
    store = FakeControlStore(mini_controls(), {"SI-3": 0.1, "SI-2": 0.2, "SI-7": 0.3})
    finding = _finding(comp="x", gaps=["no_edr"])
    result = retrieve(finding, store, finding_type="unpatched_software")
    assert "SI-3" in {c.control_id for c in result.chunks}
    assert "SI-3" not in {g.control_id for g in result.gap_controls}  # prefer the hit
