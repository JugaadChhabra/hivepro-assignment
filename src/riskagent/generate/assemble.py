"""Assemble the full risk brief once (§6). Runs at startup and is cached.

Scores ALL 114 findings (never retrieve-then-rank), dedupes to the top 5, then
for each of the 5 retrieves controls and produces a guarded explanation. The five
explanations run concurrently under an outer deadline; a straggler falls to a
template so a slow-but-alive model cannot stall startup. The LLM writes only the
prose; rank, evidence, and control are already decided by the time it is called.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

from riskagent import config
from riskagent.generate.guard import GuardResult, enforce, template_result
from riskagent.generate.llm import build_control_text, build_evidence_block, build_prompt
from riskagent.generate.select import SelectedRisk, select
from riskagent.ingest.csv_loader import DataBundle
from riskagent.ingest.kev import KevCatalog, apply_kev
from riskagent.ingest.report_parser import parse_report
from riskagent.models import EnrichedFinding, IntelRecord, ScoreBreakdown
from riskagent.pipeline.campaign import apply_campaigns
from riskagent.pipeline.control_gaps import annotate_control_gaps
from riskagent.pipeline.intel_match import match
from riskagent.pipeline.join import join
from riskagent.pipeline.score import score_all
from riskagent.rag.index import ControlStore
from riskagent.rag.retrieve import GapControl, RetrievedControl, retrieve

# one context per selected risk: risk, retrieved controls, rule gap controls, evidence, prompt
_Context = tuple[SelectedRisk, list[RetrievedControl], list[GapControl], str, str]

# human phrase for why a rule control applies, keyed by the control_gap
_GAP_REASON = {
    "no_edr": "no EDR installed on this host",
    "no_owner": "asset has no assigned owner",
    "stale_asset_record": "asset inventory record is stale",
}


class Provenance(BaseModel):
    nist_catalog_version: str
    nist_catalog_sha256: str
    index_built_at: str
    nist_fetched_at: str
    generated_at: str
    # Populated after the LLM stage — how many of the 5 were real prose vs template.
    explanations_llm: int = 0
    explanations_template: int = 0
    # KEV fields are populated in phase 7; the keys exist now so the shape is stable.
    kev_fetched_at: str | None = None
    kev_coverage_pct: float | None = None
    kev_staleness_warning: bool = False


class EnhancementRef(BaseModel):
    control_id: str
    title: str


class GapControlRef(BaseModel):
    control_id: str
    title: str
    reason: str  # why it applies by rule (e.g. "no EDR installed on this host")
    source: str = "rule"


class RiskEntry(BaseModel):
    rank: int
    cve: str
    vulnerability_name: str
    affected_assets: list[str]
    affected_environments: list[str]
    multi_env_note: str  # shown when one finding spans several assets/environments
    service_name: str
    service_owner: str
    rto_hours: int
    cvss: float
    internet_exposed: bool
    exploit_available: bool
    auth_required: bool
    days_open: int
    edr_installed: bool
    intel: list[IntelRecord]
    threat_summary: str
    control_id: str
    control_title: str
    control_summary: str
    enhancements: list[EnhancementRef]
    enhancement_match_count: int  # pre-cap matches (a query-quality signal for phase 6)
    gap_controls: list[GapControlRef]  # rule-mapped controls (e.g. SI-3), separate channel
    why_ranked: str
    explanation_source: str
    data_flags: list[str]
    score: ScoreBreakdown


class RiskBrief(BaseModel):
    entries: list[RiskEntry]
    provenance: Provenance


@dataclass
class AppState:
    brief: RiskBrief
    findings: list[EnrichedFinding]  # all 114, scored — served at /api/findings


def score_all_findings(data: DataBundle) -> list[EnrichedFinding]:
    """The deterministic pipeline: join -> intel -> control gaps -> campaign objective
    -> score, all 114. Campaign parsing/cross-check is deterministic and offline, so it
    runs here (KEV, which needs the network, is layered on separately in the app)."""
    findings = match(join(data.vulnerabilities, data.assets, data.services), data.intel).findings
    annotate_control_gaps(findings)
    campaigns = parse_report(config.REPORT_PATH.read_text(encoding="utf-8"))
    apply_campaigns(findings, campaigns, data.intel)
    return score_all(findings)


def _threat_summary(intel: list[IntelRecord]) -> str:
    if not intel:
        return "no active campaign matched"
    parts = [
        f'{r.threat_actor} "{r.campaign_name}" — '
        f"{'ransomware' if r.ransomware_association else r.exploit_maturity}, "
        f"{r.confidence} confidence, {r.target_region}"
        for r in intel
    ]
    return "; ".join(parts)


def _multi_env_note(assets: list[str], environments: list[str]) -> str:
    if len(assets) <= 1:
        return ""
    return (
        f"highest-severity instance shown; affects {len(assets)} assets "
        f"across {', '.join(environments)}"
    )


def _build_entry(
    risk: SelectedRisk,
    controls: list[RetrievedControl],
    gap_controls: list[GapControl],
    guard_result: GuardResult,
) -> RiskEntry:
    finding = risk.finding
    chosen = next(
        (c for c in controls if c.control_id == guard_result.output.control_id),
        controls[0] if controls else None,
    )
    control_title = chosen.control.title if chosen is not None else ""
    match_count = len(chosen.enhancements) if chosen is not None else 0
    # threshold THEN cap: a weak match surfaces no enhancement, not the least-bad of many
    shown = (
        [e for e in chosen.enhancements if e.distance <= config.ENHANCEMENT_MAX_DISTANCE][
            : config.MAX_ENHANCEMENTS_SHOWN
        ]
        if chosen is not None
        else []
    )
    return RiskEntry(
        rank=risk.rank,
        cve=risk.cve,
        vulnerability_name=risk.vulnerability_name,
        affected_assets=risk.affected_assets,
        affected_environments=risk.affected_environments,
        multi_env_note=_multi_env_note(risk.affected_assets, risk.affected_environments),
        service_name=finding.service.business_service,
        service_owner=finding.service.business_owner,
        rto_hours=finding.service.rto_hours,
        cvss=finding.vulnerability.cvss,
        internet_exposed=finding.asset.internet_exposed,
        exploit_available=finding.vulnerability.exploit_available,
        auth_required=finding.vulnerability.auth_required,
        days_open=finding.vulnerability.days_open,
        edr_installed=finding.asset.edr_installed,
        intel=finding.intel,
        threat_summary=_threat_summary(finding.intel),
        control_id=guard_result.output.control_id,
        control_title=control_title,
        control_summary=guard_result.output.control_summary,
        enhancements=[EnhancementRef(control_id=e.control_id, title=e.title) for e in shown],
        enhancement_match_count=match_count,
        gap_controls=[
            GapControlRef(control_id=g.control_id, title=g.title,
                          reason=_GAP_REASON.get(g.gap, g.gap), source=g.source)
            for g in gap_controls
        ],
        why_ranked=guard_result.output.why_ranked,
        explanation_source=guard_result.explanation_source,
        data_flags=finding.data_flags,
        score=risk.score,
    )


def _explain_stage(
    contexts: list[_Context],
    complete: Callable[[str], str],
    known_actors: set[str],
    deadline_s: float,
) -> list[RiskEntry]:
    """Run the 5 guarded explanations concurrently under an outer wall-clock deadline."""

    def explain(context: _Context) -> RiskEntry:
        risk, controls, gap_controls, evidence_block, prompt = context
        guard_result = enforce(
            complete, prompt, evidence_block=evidence_block, retrieved=controls,
            intel_empty=not risk.finding.intel, known_actors=known_actors,
            reasons=risk.score.reasons,
            extra_control_ids=frozenset(g.control_id for g in gap_controls),
        )
        return _build_entry(risk, controls, gap_controls, guard_result)

    pool = ThreadPoolExecutor(max_workers=max(1, len(contexts)))
    try:
        submitted: list[tuple[_Context, Future[RiskEntry]]] = [
            (ctx, pool.submit(explain, ctx)) for ctx in contexts
        ]
        deadline = time.monotonic() + deadline_s
        entries: list[RiskEntry] = []
        for ctx, future in submitted:
            remaining = deadline - time.monotonic()
            try:
                entries.append(future.result(timeout=max(0.0, remaining)))
            except TimeoutError:
                risk, controls, gap_controls, _, _ = ctx
                fallback = template_result(
                    risk.score.reasons, controls, "llm stage deadline exceeded"
                )
                entries.append(_build_entry(risk, controls, gap_controls, fallback))
        return entries
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def build_state(
    *,
    data: DataBundle,
    store: ControlStore,
    complete: Callable[[str], str],
    provenance: Provenance,
    top_n: int = 5,
    llm_deadline_s: float = config.LLM_STAGE_DEADLINE_S,
    kev: KevCatalog | None = None,
    write_trace_to: Path | None = None,
) -> AppState:
    findings = score_all_findings(data)
    kev_join = None
    if kev is not None:
        # KEV is the one enrichment that needs the network, so it is layered on here
        # rather than in score_all_findings (which eval.py runs offline). kev_status
        # feeds the kev_listed term, so we MUST rescore after the join.
        kev_join = apply_kev(findings, kev)
        score_all(findings)
        provenance = provenance.model_copy(update={
            "kev_fetched_at": kev.fetched_at.isoformat(),
            "kev_coverage_pct": kev_join.kev_coverage_pct,
            "kev_staleness_warning": kev.staleness_warning,
        })
    selected = select(findings, top_n=top_n)
    known_actors = {r.threat_actor for r in data.intel} | {r.campaign_name for r in data.intel}

    # Retrieval is sequential and cheap — doing it here (not inside the thread pool)
    # loads the embedding model exactly once, and sentence-transformers is not safe
    # for concurrent encode() on a shared model (would give wrong results, not a crash).
    contexts: list[_Context] = []
    for risk in selected:
        result = retrieve(risk.finding, store)
        controls = result.chunks
        evidence_block = build_evidence_block(risk)
        control_text = build_control_text(controls)
        for gap in result.gap_controls:  # rule controls are also citable prose sources
            control_text += f"\n\n{gap.control_id} {gap.title}: {gap.statement}"
        prompt = build_prompt(evidence_block, risk.score.reasons, control_text)
        contexts.append((risk, controls, result.gap_controls, evidence_block, prompt))

    entries = _explain_stage(contexts, complete, known_actors, llm_deadline_s)

    provenance = provenance.model_copy(
        update={
            "explanations_llm": sum(1 for e in entries if e.explanation_source == "llm"),
            "explanations_template": sum(1 for e in entries if e.explanation_source == "template"),
        }
    )
    brief = RiskBrief(entries=entries, provenance=provenance)
    # observability: one JSONL trace per run. Lazy import breaks the assemble<->trace
    # cycle (trace needs RiskBrief's type).
    from riskagent.generate.trace import build_trace, write_trace

    write_trace(build_trace(brief, kev_join), path=write_trace_to)
    return AppState(brief=brief, findings=findings)
