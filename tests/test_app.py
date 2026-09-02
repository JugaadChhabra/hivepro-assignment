"""Phase 5 tests: the served app (§6). No network, LLM mocked via a fake complete."""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fakes import FakeControlStore, mini_controls
from riskagent.app import create_app
from riskagent.generate.assemble import AppState, Provenance, _build_entry, build_state
from riskagent.generate.guard import template_result
from riskagent.generate.select import SelectedRisk
from riskagent.ingest.csv_loader import load_all
from riskagent.models import (
    Asset,
    BusinessService,
    EnrichedFinding,
    ScoreBreakdown,
    Vulnerability,
)
from riskagent.rag.index import ControlChunk
from riskagent.rag.retrieve import RetrievedControl

_FIRST_CONTROL = re.compile(r"RETRIEVED CONTROLS.*?\n([A-Z]{2,}-\d+(?:\(\d+\))?)", re.DOTALL)


def _fake_complete(prompt: str) -> str:
    # Echo the first retrieved control id and a number/CVE/actor-free sentence,
    # so the guard accepts it as grounded LLM prose.
    match = _FIRST_CONTROL.search(prompt)
    control_id = match.group(1) if match else ""
    return (
        '{"why_ranked": "Internet-facing and unpatched, a direct path to the service.", '
        f'"control_id": "{control_id}", "control_summary": "Apply the cited control."}}'
    )


def _builder() -> AppState:
    provenance = Provenance(
        nist_catalog_version="SP 800-53 Rev 5",
        nist_catalog_sha256="0" * 64,
        index_built_at="2026-04-24T00:00:00+00:00",
        nist_fetched_at="2026-04-24T00:00:00+00:00",
        generated_at="2026-09-02T00:00:00+00:00",
    )
    return build_state(
        data=load_all(),
        store=FakeControlStore(mini_controls(), {}),
        complete=_fake_complete,
        provenance=provenance,
    )


def test_api_findings_returns_all_114() -> None:
    with TestClient(create_app(_builder)) as client:
        body = client.get("/api/findings").json()
    assert len(body) == 114  # nothing truncated before scoring
    assert all(f["score"] is not None for f in body)


def test_api_risks_returns_five_entries() -> None:
    with TestClient(create_app(_builder)) as client:
        body = client.get("/api/risks").json()
    assert len(body["entries"]) == 5
    assert [e["rank"] for e in body["entries"]] == [1, 2, 3, 4, 5]


def test_index_renders_html_brief() -> None:
    with TestClient(create_app(_builder)) as client:
        resp = client.get("/")
    assert resp.status_code == 200
    assert "Top 5 Cyber Risks" in resp.text
    assert "#1" in resp.text


def test_traces_endpoint_returns_run_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # /traces must return real run traces, not the phase-5 empty stub. Point the trace
    # file at a temp path so both the write (in build_state) and read (in the endpoint)
    # use the same isolated file.
    from riskagent import config

    trace_file = tmp_path / "traces.jsonl"
    monkeypatch.setattr(config, "TRACE_PATH", trace_file)
    with TestClient(create_app(_builder)) as client:
        traces = client.get("/traces").json()
    assert isinstance(traces, list) and traces  # non-empty
    last = traces[-1]
    assert last["run_at"] == "2026-09-02T00:00:00+00:00"
    assert len(last["risks"]) == 5  # the top five
    assert "input_sha256" in last and len(last["input_sha256"]) == 6


def test_exposure_model_mismatch_banner_renders_in_html() -> None:
    # phase 7: the public-object-storage reachability flag must reach the RENDERED
    # report, not just the trace. V-2071 (backup bucket) is in the top-5, so its
    # banner text must appear in the served HTML.
    with TestClient(create_app(_builder)) as client:
        html = client.get("/").text
    assert "object policy may make it reachable via the provider URL" in html


def test_healthz_returns_provenance_not_bare_status() -> None:
    with TestClient(create_app(_builder)) as client:
        health = client.get("/healthz").json()
    assert health["status"] == "ok"
    assert health["nist_catalog_version"] == "SP 800-53 Rev 5"
    assert "kev_staleness_warning" in health  # key present even before phase 7


def test_explanations_are_grounded_llm_prose() -> None:
    # the fake echoes a valid retrieved control id + a clean sentence => guard passes
    with TestClient(create_app(_builder)) as client:
        entries = client.get("/api/risks").json()["entries"]
    assert any(e["explanation_source"] == "llm" for e in entries)


def test_healthz_reports_explanation_counts() -> None:
    with TestClient(create_app(_builder)) as client:
        health = client.get("/healthz").json()
    assert health["explanations_llm"] + health["explanations_template"] == 5


def test_llm_stage_deadline_falls_back_to_template() -> None:
    # A model that HANGS (never returns in time) must not stall startup: the outer
    # deadline cuts the stage and the brief renders with template explanations.
    # This is a different path from a model that raises — it must be tested too.
    def slow_complete(_prompt: str) -> str:
        time.sleep(2.0)  # sleeps far past the deadline; would be ~4s with the retry
        return "{}"

    provenance = Provenance(
        nist_catalog_version="v", nist_catalog_sha256="0" * 64, index_built_at="t",
        nist_fetched_at="t", generated_at="t",
    )
    started = time.monotonic()
    state = build_state(
        data=load_all(), store=FakeControlStore(mini_controls(), {}),
        complete=slow_complete, provenance=provenance, llm_deadline_s=0.2,
    )
    elapsed = time.monotonic() - started
    # shape: the deadline fired, so every entry is a template sentence
    assert all(e.explanation_source == "template" for e in state.brief.entries)
    assert all(e.why_ranked.startswith("Ranked on:") for e in state.brief.entries)
    # and it returned near the 0.2s deadline, NOT after the ~4s of sleeping calls;
    # 2.5 is a wide separator (>> 0.2 deadline, << 4s un-bounded) so it won't flake
    assert elapsed < 2.5


def _scored_finding() -> EnrichedFinding:
    asset = Asset.model_validate(
        {"asset_id": "A-9", "asset_name": "b", "asset_type": "x", "environment": "Production",
         "owner_team": "T", "business_service": "S", "internet_exposed": True,
         "criticality": "High", "data_classification": "x", "edr_installed": True,
         "last_seen_days": 1, "location": "UAE", "vendor_product": "x"}
    )
    vuln = Vulnerability.model_validate(
        {"vuln_id": "V-9", "asset_id": "A-9", "vulnerability_name": "Y", "cve": "CVE-2024-0001",
         "severity": "High", "cvss": 8.0, "exploit_available": True, "patch_available": False,
         "days_open": 10, "asset_exposure": "Internet", "auth_required": False, "status": "Open",
         "affected_component": "c"}
    )
    service = BusinessService.model_validate(
        {"business_service": "S", "business_owner": "O", "business_impact": "x",
         "customer_facing": True, "compliance_scope": "PCI DSS", "revenue_impact": "High",
         "rto_hours": 1, "depends_on": None, "risk_appetite": "Low"}
    )
    score = ScoreBreakdown(exposure=18, exploitability=8, adversary=0, business=9, control_gap=0,
                           blast_radius=0, total=35, reasons=["internet-exposed (+18)"])
    return EnrichedFinding(vulnerability=vuln, asset=asset, service=service, intel=[], score=score)


def _enh(control_id: str, distance: float) -> ControlChunk:
    return ControlChunk(
        control_id=control_id, family="SI", title="enh", statement="s",
        discussion="", distance=distance,
    )


def test_enhancement_threshold_and_cap() -> None:
    # Two enhancements matched: one close (0.30), one weak (0.90 > threshold 0.75).
    # The weak one must be suppressed; the pre-cap match count records both.
    base = ControlChunk(
        control_id="SI-2", family="SI", title="Flaw Remediation", statement="fix flaws.",
        discussion="", distance=0.2,
    )
    controls = [
        RetrievedControl(control=base, enhancements=(_enh("SI-2(5)", 0.30), _enh("SI-2(9)", 0.90)))
    ]
    risk = SelectedRisk(
        rank=1, cve="CVE-2024-0001", vulnerability_name="Y", affected_assets=["b"],
        affected_environments=["Production"], finding=_scored_finding(),
    )
    guard_result = template_result(risk.score.reasons, controls, "x")  # picks control_id SI-2
    entry = _build_entry(risk, controls, [], guard_result)
    assert entry.enhancement_match_count == 2  # both matches recorded
    assert [e.control_id for e in entry.enhancements] == ["SI-2(5)"]  # weak one suppressed
