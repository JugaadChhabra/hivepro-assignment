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

from pydantic import BaseModel

from riskagent import config
from riskagent.generate.guard import GuardResult, enforce, template_result
from riskagent.generate.llm import build_control_text, build_evidence_block, build_prompt
from riskagent.generate.select import SelectedRisk, select
from riskagent.ingest.csv_loader import DataBundle
from riskagent.models import EnrichedFinding, IntelRecord, ScoreBreakdown
from riskagent.pipeline.control_gaps import annotate_control_gaps
from riskagent.pipeline.intel_match import match
from riskagent.pipeline.join import join
from riskagent.pipeline.score import score_all
from riskagent.rag.index import ControlStore
from riskagent.rag.retrieve import RetrievedControl, retrieve

# one context per selected risk: the risk, its retrieved controls, evidence, prompt
_Context = tuple[SelectedRisk, list[RetrievedControl], str, str]


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
    """The deterministic pipeline: join -> intel -> control gaps -> score, all 114."""
    findings = match(join(data.vulnerabilities, data.assets, data.services), data.intel).findings
    annotate_control_gaps(findings)
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
    risk: SelectedRisk, controls: list[RetrievedControl], guard_result: GuardResult
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
        risk, controls, evidence_block, prompt = context
        guard_result = enforce(
            complete, prompt, evidence_block=evidence_block, retrieved=controls,
            intel_empty=not risk.finding.intel, known_actors=known_actors,
            reasons=risk.score.reasons,
        )
        return _build_entry(risk, controls, guard_result)

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
                risk, controls, _, _ = ctx
                fallback = template_result(
                    risk.score.reasons, controls, "llm stage deadline exceeded"
                )
                entries.append(_build_entry(risk, controls, fallback))
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
) -> AppState:
    findings = score_all_findings(data)
    selected = select(findings, top_n=top_n)
    known_actors = {r.threat_actor for r in data.intel} | {r.campaign_name for r in data.intel}

    # Retrieval is sequential and cheap — doing it here (not inside the thread pool)
    # loads the embedding model exactly once, and sentence-transformers is not safe
    # for concurrent encode() on a shared model (would give wrong results, not a crash).
    contexts: list[_Context] = []
    for risk in selected:
        controls = retrieve(risk.finding, store).chunks
        evidence_block = build_evidence_block(risk)
        prompt = build_prompt(evidence_block, risk.score.reasons, build_control_text(controls))
        contexts.append((risk, controls, evidence_block, prompt))

    entries = _explain_stage(contexts, complete, known_actors, llm_deadline_s)

    provenance = provenance.model_copy(
        update={
            "explanations_llm": sum(1 for e in entries if e.explanation_source == "llm"),
            "explanations_template": sum(1 for e in entries if e.explanation_source == "template"),
        }
    )
    return AppState(brief=RiskBrief(entries=entries, provenance=provenance), findings=findings)
