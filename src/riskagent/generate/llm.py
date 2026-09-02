"""The LLM boundary (§6). The model writes prose from evidence already decided.

The prompt carries ONLY three things: an explicit key-value evidence block, the
scorer's ``reasons`` list, and the retrieved control text verbatim. Rank,
evidence, and control are all determined before this call — the model chooses
none of them. It returns JSON: ``why_ranked``, ``control_id``, ``control_summary``.

The evidence block is also the guard's allow-list: every number and CVE-shaped
token the model is permitted to use lives here, so the block must contain every
fact the explanation may legitimately cite.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from riskagent.generate.select import SelectedRisk

if TYPE_CHECKING:
    from riskagent.rag.retrieve import RetrievedControl


@dataclass(frozen=True)
class LlmOutput:
    why_ranked: str
    control_id: str
    control_summary: str


class LlmClient(Protocol):
    def complete(self, prompt: str) -> str: ...


class GroqClient:
    """Groq chat completion, temperature 0. Constructed lazily so importing this
    module needs no API key and the test suite never touches the network."""

    def __init__(
        self, *, api_key: str, model: str, temperature: float = 0.0, timeout_s: float = 20.0
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._timeout_s = timeout_s

    def complete(self, prompt: str) -> str:
        from groq import Groq

        # Fail fast: a bounded timeout and no internal retries, so an unreachable
        # endpoint RAISES (guard's degradation path) instead of hanging startup.
        client = Groq(api_key=self._api_key, timeout=self._timeout_s, max_retries=0)
        response = client.chat.completions.create(
            model=self._model,
            temperature=self._temperature,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content or ""


def _yn(value: bool) -> str:
    return "yes" if value else "no"


def build_evidence_block(risk: SelectedRisk) -> str:
    """The explicit key-value evidence — and the guard's number/CVE allow-list."""
    finding = risk.finding
    vuln = finding.vulnerability
    asset = finding.asset
    service = finding.service
    score = risk.score

    lines = [
        f"rank: {risk.rank}",
        f"cve: {vuln.cve}",
        f"vulnerability_name: {vuln.vulnerability_name}",
        f"affected_assets: {', '.join(risk.affected_assets)}",
        f"affected_component: {vuln.affected_component}",
        f"cvss: {vuln.cvss:g}",
        f"severity: {vuln.severity}",
        f"exposure: {'internet-facing' if asset.internet_exposed else 'internal'}",
        f"exploit_available: {_yn(vuln.exploit_available)}",
        f"auth_required: {_yn(vuln.auth_required)}",
        f"days_open: {vuln.days_open}",
        f"environment: {asset.environment}",
        f"asset_criticality: {asset.criticality}",
        f"business_service: {service.business_service}",
        f"service_owner: {service.business_owner}",
        f"rto_hours: {service.rto_hours}",
        f"customer_facing: {_yn(service.customer_facing)}",
        f"compliance_scope: {service.compliance_scope}",
        f"revenue_impact: {service.revenue_impact}",
        f"edr: {'installed' if asset.edr_installed else 'absent'}",
        f"kev_status: {finding.kev_status}",
        f"control_gaps: {', '.join(finding.control_gaps) or 'none'}",
        f"data_flags: {', '.join(finding.data_flags) or 'none'}",
        f"risk_score: {score.total:g}",
    ]
    if finding.intel:
        for record in finding.intel:
            lines.append(
                f"intel: actor {record.threat_actor}, campaign \"{record.campaign_name}\", "
                f"ransomware {_yn(record.ransomware_association)}, "
                f"maturity {record.exploit_maturity}, region {record.target_region}, "
                f"sector {record.target_sector}, confidence {record.confidence}, "
                f"last_seen {record.active_last_seen.isoformat()}"
            )
    else:
        lines.append("intel: none — no active campaign matched")
    return "\n".join(lines)


def build_control_text(controls: list[RetrievedControl]) -> str:
    """The retrieved control text, verbatim — base controls plus matched enhancements."""
    blocks: list[str] = []
    for retrieved in controls:
        base = retrieved.control
        block = [f"{base.control_id} {base.title}: {base.statement}"]
        for enh in retrieved.enhancements:
            block.append(f"  enhancement {enh.control_id} {enh.title}: {enh.statement}")
        blocks.append("\n".join(block))
    return "\n\n".join(blocks)


_INSTRUCTIONS = (
    "You are writing one entry of a cyber risk brief. In EXACTLY two sentences, "
    "explain why this finding holds its rank. Reference ONLY facts present in the "
    "EVIDENCE block: do not introduce any CVE, number, or threat-actor name that is "
    "not in EVIDENCE. If the evidence says no active campaign was matched, say so "
    "rather than inventing one. Choose control_id from the RETRIEVED CONTROLS only, "
    "and let control_summary paraphrase that control in one sentence. "
    'Return ONLY JSON: {"why_ranked": "...", "control_id": "...", "control_summary": "..."}'
)


def build_prompt(evidence_block: str, reasons: list[str], control_text: str) -> str:
    reason_lines = "\n".join(f"- {r}" for r in reasons)
    return (
        f"{_INSTRUCTIONS}\n\n"
        f"EVIDENCE:\n{evidence_block}\n\n"
        f"SCORING FACTORS (already decided, do not recompute):\n{reason_lines}\n\n"
        f"RETRIEVED CONTROLS (choose control_id from these):\n{control_text}\n"
    )


class LlmParseError(ValueError):
    """The model returned something that is not the expected JSON object."""


def parse_output(raw: str) -> LlmOutput:
    start = raw.find("{")
    end = raw.rfind("}")
    if start == -1 or end == -1 or end < start:
        raise LlmParseError(f"no JSON object in model output: {raw!r}")
    try:
        payload = json.loads(raw[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LlmParseError(f"invalid JSON: {exc}") from exc
    try:
        return LlmOutput(
            why_ranked=str(payload["why_ranked"]),
            control_id=str(payload["control_id"]),
            control_summary=str(payload["control_summary"]),
        )
    except (KeyError, TypeError) as exc:
        raise LlmParseError(f"missing field: {exc}") from exc
