"""Phase 4 INTEGRATION tests: real NIST catalog + real embeddings (§5).

Marked `network` and run as a separate CI job — a NIST outage or slow model
download must not red the main gate. These assert retrieval QUALITY (does the
real embedder put SI-2/SA-22 in the top 3), the true chunk count, contamination
on the real store, provenance metadata, and the offline cache fallback.
"""

from __future__ import annotations

import re

import pytest

from riskagent.ingest.nist import NistCatalog, load_catalog
from riskagent.models import Asset, BusinessService, EnrichedFinding, Vulnerability
from riskagent.rag.index import ChromaControlStore
from riskagent.rag.retrieve import retrieve

pytestmark = pytest.mark.network


@pytest.fixture(scope="session")
def catalog() -> NistCatalog:
    return load_catalog()


@pytest.fixture(scope="session")
def store(catalog: NistCatalog) -> ChromaControlStore:
    s = ChromaControlStore()
    s.build(catalog.controls, catalog_sha256=catalog.catalog_sha256)
    return s


def _eol_finding(*, exposed: bool, exploit: bool) -> EnrichedFinding:
    return _finding(
        vulnerability_name="End-of-Life Windows Server 2008 R2",
        affected_component="Windows Server 2008 R2 (unsupported)",
        internet_exposed=exposed,
        exploit_available=exploit,
    )


def _finding(
    *,
    vulnerability_name: str,
    affected_component: str,
    internet_exposed: bool = True,
    exploit_available: bool = True,
    control_gaps: list[str] | None = None,
) -> EnrichedFinding:
    asset = Asset.model_validate(
        {"asset_id": "A-9001", "asset_name": "box", "asset_type": "Appliance",
         "environment": "Production", "owner_team": "Net", "business_service": "Remote Access",
         "internet_exposed": internet_exposed, "criticality": "High",
         "data_classification": "Internal", "edr_installed": True, "last_seen_days": 2,
         "location": "UAE", "vendor_product": "x"}
    )
    vuln = Vulnerability.model_validate(
        {"vuln_id": "V-9001", "asset_id": "A-9001", "vulnerability_name": vulnerability_name,
         "cve": "CVE-2024-0001", "severity": "Critical", "cvss": 9.0,
         "exploit_available": exploit_available, "patch_available": False, "days_open": 40,
         "asset_exposure": "Internet", "auth_required": False, "status": "Open",
         "affected_component": affected_component}
    )
    service = BusinessService.model_validate(
        {"business_service": "Remote Access", "business_owner": "CISO", "business_impact": "x",
         "customer_facing": False, "compliance_scope": "ISO 27001", "revenue_impact": "High",
         "rto_hours": 2, "depends_on": None, "risk_appetite": "Low"}
    )
    return EnrichedFinding(
        vulnerability=vuln, asset=asset, service=service, intel=[], control_gaps=control_gaps or []
    )


def test_index_one_chunk_per_control_none_empty(
    store: ChromaControlStore, catalog: NistCatalog
) -> None:
    assert store.count() == len(catalog.controls)
    assert 1100 <= store.count() <= 1250  # ~1100, one per control/enhancement
    assert all(doc.strip() for doc in store.peek(200))


def test_no_contamination_in_chunk_text(store: ChromaControlStore) -> None:
    asset_id = re.compile(r"\bA-1\d{3}\b")
    cvss = re.compile(r"cvss", re.IGNORECASE)
    cve = re.compile(r"\bCVE-\d{4}\b")
    for doc in store.peek(300):
        assert not asset_id.search(doc), doc
        assert not cvss.search(doc), doc
        assert not cve.search(doc), doc


def test_fortinet_unpatched_firmware_returns_si2(store: ChromaControlStore) -> None:
    finding = _finding(
        vulnerability_name="Fortinet SSL-VPN Heap Buffer Overflow RCE",
        affected_component="FortiOS SSL-VPN firmware",
        control_gaps=["no_vendor_patch", "no_edr"],
    )
    result = retrieve(finding, store)
    assert result.finding_type == "unpatched_software"
    assert "SI-2" in [c.control_id for c in result.chunks]


def test_unpatched_with_no_edr_surfaces_both_si2_and_si3(store: ChromaControlStore) -> None:
    # §7 item 3: unioning the gap families keeps the second remediation dimension
    # reachable — patching (SI-2) AND the missing monitoring (SI-3) both in top 3.
    finding = _finding(
        vulnerability_name="Fortinet SSL-VPN Heap Buffer Overflow RCE",
        affected_component="FortiOS SSL-VPN firmware",
        control_gaps=["no_vendor_patch", "no_edr"],
    )
    result = retrieve(finding, store)
    chunk_ids = {c.control_id for c in result.chunks}
    gap_ids = {g.control_id for g in result.gap_controls}
    assert "SI-2" in chunk_ids  # patch it — a retrieval hit
    assert "SI-3" in chunk_ids | gap_ids  # nothing would have noticed — the rule channel
    assert "SI-3" in gap_ids  # specifically: SI-3 arrives by rule, not by displacing a hit
    assert result.gap_controls[0].source == "rule"


def test_eol_internal_returns_sa22(store: ChromaControlStore) -> None:
    result = retrieve(_eol_finding(exposed=False, exploit=False), store)
    assert result.finding_type == "end_of_life_software"
    assert "SA-22" in [c.control_id for c in result.chunks]


def test_eol_exposed_exploitable_still_returns_sa22(store: ChromaControlStore) -> None:
    # Decision 7: real EOL boxes sit on exposed, exploitable assets. If SA-22 only
    # survived on a clean query, the template would be over-weighting exposure.
    result = retrieve(_eol_finding(exposed=True, exploit=True), store)
    assert "SA-22" in [c.control_id for c in result.chunks]


def test_collapse_carries_enhancement_text(store: ChromaControlStore) -> None:
    # The retrieved base control must carry its matched enhancements' full text.
    result = retrieve(_eol_finding(exposed=False, exploit=False), store)
    sa22 = next(c for c in result.chunks if c.control_id == "SA-22")
    assert sa22.enhancement_ids  # at least SA-22(1)
    assert all(e.statement for e in sa22.enhancements)


def test_collection_metadata_has_provenance(
    store: ChromaControlStore, catalog: NistCatalog
) -> None:
    meta = store.collection_metadata()
    assert re.fullmatch(r"[0-9a-f]{64}", meta["catalog_sha256"])  # the hash, the fact
    assert meta["catalog_sha256"] == catalog.catalog_sha256
    assert meta["nist_catalog_version"]  # human label present
    assert meta["index_built_at"]


def test_offline_fallback_uses_cache(catalog: NistCatalog) -> None:
    # catalog fixture already fetched live and wrote the cache; offline must serve it.
    cached = load_catalog(offline=True)
    assert cached.source == "cache"
    assert cached.catalog_sha256 == catalog.catalog_sha256


def test_precomputed_pack_retrieval_matches_model_exactly(store: ChromaControlStore) -> None:
    """§8 deploy invariant: the deployed model-free path must return byte-identical
    retrieval to the model path. Precomputed vectors ARE the model's vectors, so any
    divergence here is a wiring bug — the exact check the spec asks for."""
    import json

    from riskagent.generate.assemble import score_all_findings
    from riskagent.ingest.csv_loader import load_all
    from riskagent.rag.pack import PrecomputedEmbedder, build_query_pack

    data = load_all()
    pack = build_query_pack(data, store)  # embedded with the same model the index used
    pack = json.loads(json.dumps(pack))  # round-trip exactly as the shipped file does
    # a model-free store over the SAME index, embedding only via the precomputed table
    packed = ChromaControlStore(embed_fn=PrecomputedEmbedder(pack))

    findings = score_all_findings(data)
    assert len(findings) == 114  # all findings covered, nothing truncated
    for finding in findings:
        ref = retrieve(finding, store)
        got = retrieve(finding, packed)
        assert [c.control_id for c in got.chunks] == [c.control_id for c in ref.chunks]
        assert [c.distance for c in got.chunks] == [c.distance for c in ref.chunks]
        assert [g.control_id for g in got.gap_controls] == [g.control_id for g in ref.gap_controls]
        assert got.flags == ref.flags
