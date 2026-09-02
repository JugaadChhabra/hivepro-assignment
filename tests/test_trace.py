"""Phase 7 tests: per-run observability trace (§6)."""

from __future__ import annotations

from pathlib import Path

from riskagent.generate.assemble import Provenance, RiskBrief
from riskagent.generate.trace import (
    RiskTrace,
    build_trace,
    hash_inputs,
    read_traces,
    write_trace,
)
from riskagent.models import ScoreBreakdown


def _brief() -> RiskBrief:
    prov = Provenance(
        nist_catalog_version="SP 800-53 Rev 5", nist_catalog_sha256="0" * 64,
        index_built_at="t", nist_fetched_at="t", generated_at="2026-09-02T00:00:00+00:00",
        explanations_llm=3, explanations_template=2,
        kev_fetched_at="2026-09-02T00:00:00+00:00", kev_coverage_pct=25.4,
    )
    score = ScoreBreakdown(
        exposure=25, exploitability=20, adversary=0, business=20, control_gap=2,
        blast_radius=6, total=73, reasons=["internet-exposed (+18)"],
    )
    from riskagent.generate.assemble import RiskEntry

    entry = RiskEntry(
        rank=1, cve="CVE-2023-4966", vulnerability_name="CitrixBleed",
        affected_assets=["lb-01"], affected_environments=["Production"], multi_env_note="",
        service_name="Payment", service_owner="CFO", rto_hours=1, cvss=9.4,
        internet_exposed=True, exploit_available=True, auth_required=False, days_open=180,
        edr_installed=False, intel=[], threat_summary="x", control_id="SI-2",
        control_title="Flaw Remediation", control_summary="patch", enhancements=[],
        enhancement_match_count=0, gap_controls=[], why_ranked="because", explanation_source="llm",
        data_flags=["exposure_model_mismatch"], score=score,
    )
    return RiskBrief(entries=[entry], provenance=prov)


def test_hash_inputs_covers_all_six_inputs() -> None:
    h = hash_inputs()
    assert set(h) == {
        "assets.csv", "vulnerabilities.csv", "threat_intelligence.csv",
        "business_services.csv", "remediation_guidance.csv", "synthetic_threat_report.md",
    }
    assert all(len(v) == 64 for v in h.values())  # sha256 hex


def test_build_trace_captures_score_and_grounding() -> None:
    from riskagent.ingest.kev import KevJoin

    rec = build_trace(_brief(), KevJoin(kev_lookups=40, kev_hits=29, kev_checkable=40,
                                        kev_coverage_pct=25.4))
    assert rec.kev_hits == 29
    assert rec.explanations_llm == 3
    assert len(rec.risks) == 1
    r: RiskTrace = rec.risks[0]
    assert r.control_id == "SI-2"
    assert r.explanation_source == "llm"  # the grounding verdict is captured
    assert r.score.total == 73
    assert "exposure_model_mismatch" in r.data_flags


def test_write_then_read_roundtrip_returns_last_n(tmp_path: Path) -> None:
    path = tmp_path / "traces.jsonl"
    for _ in range(3):
        write_trace(build_trace(_brief(), None), path=path)
    got = read_traces(path, n=2)
    assert len(got) == 2  # last N only
    last = got[-1]
    assert last["run_at"] == "2026-09-02T00:00:00+00:00"
    risks = last["risks"]
    assert isinstance(risks, list)
    assert risks[0]["control_id"] == "SI-2"


def test_read_traces_missing_file_is_empty(tmp_path: Path) -> None:
    assert read_traces(tmp_path / "nope.jsonl") == []
