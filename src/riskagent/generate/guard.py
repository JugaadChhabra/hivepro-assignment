"""Ground the LLM output, or refuse it (§6).

This is what turns "the model might hallucinate" into an actual control. Every
explanation is validated against the evidence block and the retrieved control
set; a failure is retried once with the violation appended, and a second failure
falls back to a template sentence built from ``score.reasons``, tagged
``explanation_source="template"``. An ungrounded sentence is never shipped
silently — and if the model is unreachable entirely, the template path is the
degradation path (§6): the brief still renders, only the prose degrades.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from riskagent.generate.llm import LlmOutput, LlmParseError, parse_output

if TYPE_CHECKING:
    from riskagent.rag.retrieve import RetrievedControl

# CVE-shaped: a letter-led token with >=2 hyphen groups ending in digits, e.g.
# CVE-2024-21762, CVE-SYN-2026-0011, CTRL-SYN-009. Excludes control ids (SI-2).
_CVE_SHAPED = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){2,}\b")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
# Adversary claims that must not appear when NO intel matched — an unnamed
# "ransomware campaign" is still an ungrounded claim. This denylist is BEST-EFFORT
# defence-in-depth, not a complete filter: the exact named-actor check above (vs
# known_actors) is the precise guard, and the temperature-0 prompt instruction to
# say "no active campaign was matched" is the primary control. Subtle paraphrases
# can still pass (documented limitation — a semantic check is future work). Phrases
# are chosen for precision: they imply PRESENT adversary activity and rarely occur
# in grounded, hypothetical control language. Bare "campaign"/"attacker"/"exploit"
# are excluded so sanctioned phrasing and grounded exploit-availability aren't
# false-flagged.
_ADVERSARY_CLAIMS = (
    "ransomware", "actively exploited", "active exploitation", "exploited in the wild",
    "in the wild", "threat actor", "threat group", "adversary", "apt", "nation-state",
    "intrusion set", "criminal group", "crew is", "actor is", "attackers are",
    "attacker is", "campaign targeting", "actively targeting", "being targeted",
)


def _numbers(text: str) -> set[str]:
    # numbers OUTSIDE cve-shaped tokens, as whole tokens — exact, never substring
    return set(_NUMBER.findall(_CVE_SHAPED.sub(" ", text)))


@dataclass(frozen=True)
class GuardResult:
    output: LlmOutput
    explanation_source: Literal["llm", "template"]
    violations: list[str]  # what failed on the final rejected attempt (empty if llm ok)


def validate(
    output: LlmOutput,
    *,
    evidence_block: str,
    retrieved_ids: set[str],
    intel_empty: bool,
    known_actors: set[str],
) -> list[str]:
    """Return the list of violations (empty means the output is grounded)."""
    violations: list[str] = []
    why = output.why_ranked

    # control_id: EXACT membership, no normalisation — "si-2", "SI2", "SI-2 ",
    # and "SI-2(5)" are all rejected; only a verbatim retrieved id passes.
    if output.control_id not in retrieved_ids:
        violations.append(f"control_id {output.control_id!r} not in retrieved set")

    # CVE-shaped tokens: exact-token set membership, so a token cannot pass by
    # being a substring of an allowed one.
    evidence_cves = set(_CVE_SHAPED.findall(evidence_block))
    for token in _CVE_SHAPED.findall(why):
        if token not in evidence_cves:
            violations.append(f"CVE-shaped token {token!r} not in evidence")

    # numbers: exact-token set membership — "8" does NOT pass because evidence
    # contains "8.1", and "202" does NOT pass because evidence contains "2024".
    evidence_numbers = _numbers(evidence_block)
    for number in _numbers(why):
        if number not in evidence_numbers:
            violations.append(f"number {number!r} not grounded in evidence")

    if intel_empty:
        lowered = why.lower()
        for actor in known_actors:
            if actor and actor.lower() in lowered:
                violations.append(f"threat actor {actor!r} named when intel is empty")
        for claim in _ADVERSARY_CLAIMS:
            if claim in lowered:
                violations.append(f"ungrounded adversary claim {claim!r} when intel is empty")

    return violations


def _first_sentence(text: str) -> str:
    cleaned = " ".join(text.split())  # collapse the control statement's newlines
    head = cleaned.split(". ", 1)[0]
    return head if head.endswith(".") else f"{head}."


def _template_output(reasons: list[str], fallback: RetrievedControl | None) -> LlmOutput:
    meaningful = [r.strip() for r in reasons if r.strip()]
    top = "; ".join(meaningful[:4]) if meaningful else "the deterministic risk score"
    why = f"Ranked on: {top}."  # always a usable sentence, even with no reasons
    if fallback is not None:
        return LlmOutput(
            why_ranked=why,
            control_id=fallback.control_id,
            control_summary=_first_sentence(fallback.control.statement),
        )
    return LlmOutput(why_ranked=why, control_id="", control_summary="")


def template_result(
    reasons: list[str], retrieved: list[RetrievedControl], violation: str
) -> GuardResult:
    """A guarded result that skips the LLM entirely — the degradation path, also
    used when the whole LLM stage exceeds its deadline."""
    fallback = retrieved[0] if retrieved else None
    return GuardResult(
        output=_template_output(reasons, fallback),
        explanation_source="template",
        violations=[violation],
    )


def enforce(
    complete: Callable[[str], str],
    prompt: str,
    *,
    evidence_block: str,
    retrieved: list[RetrievedControl],
    intel_empty: bool,
    known_actors: set[str],
    reasons: list[str],
    extra_control_ids: frozenset[str] = frozenset(),
) -> GuardResult:
    """Call the model, validate, retry once on violation, else template fallback.

    ``extra_control_ids`` are also-valid citations beyond the retrieved set — the
    rule-mapped gap controls (e.g. SI-3), so the LLM citing SI-3 is not rejected."""
    retrieved_ids = {r.control_id for r in retrieved} | extra_control_ids
    fallback = retrieved[0] if retrieved else None
    current = prompt
    violations: list[str] = []

    for _ in range(2):  # one attempt + one retry
        try:
            output = parse_output(complete(current))
            violations = validate(
                output,
                evidence_block=evidence_block,
                retrieved_ids=retrieved_ids,
                intel_empty=intel_empty,
                known_actors=known_actors,
            )
        except LlmParseError as exc:
            violations = [f"parse error: {exc}"]
        except Exception as exc:
            violations = [f"model call failed: {exc}"]
        else:
            if not violations:
                return GuardResult(output=output, explanation_source="llm", violations=[])
        current = f"{prompt}\n\nVIOLATIONS (fix and return corrected JSON): {'; '.join(violations)}"

    return GuardResult(
        output=_template_output(reasons, fallback),
        explanation_source="template",
        violations=violations,
    )
