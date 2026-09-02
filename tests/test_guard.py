"""Phase 5 tests: the guard rejects ungrounded output and falls back safely (§6)."""

from __future__ import annotations

from riskagent.generate.guard import enforce, template_result, validate
from riskagent.generate.llm import LlmOutput
from riskagent.rag.index import ControlChunk
from riskagent.rag.retrieve import RetrievedControl

_EVIDENCE = (
    "rank: 1\ncve: CVE-2024-21762\ncvss: 9.8\ndays_open: 42\n"
    "exposure: internet-facing\nintel: none — no active campaign matched"
)


def _control(control_id: str, title: str = "Flaw Remediation") -> RetrievedControl:
    return RetrievedControl(
        control=ControlChunk(
            control_id=control_id, family=control_id.split("-")[0], title=title,
            statement="Identify, report, and correct system flaws.", discussion="", distance=0.1,
        )
    )


_RETRIEVED = [_control("SI-2"), _control("RA-5", "Vulnerability Monitoring")]
_RETRIEVED_IDS = {"SI-2", "RA-5"}
_ACTORS = {"CrimsonJackal", "Gateway Breaker"}


def _out(why: str, control_id: str = "SI-2") -> LlmOutput:
    return LlmOutput(why_ranked=why, control_id=control_id, control_summary="patch it")


def test_validate_accepts_grounded_output() -> None:
    out = _out("Internet-facing with a CVSS 9.8 flaw open 42 days; patch CVE-2024-21762.")
    assert validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    ) == []


def test_guard_rejects_fabricated_control_id() -> None:
    out = _out("Patch this flaw.", control_id="AC-99")  # not in retrieved set
    violations = validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("control_id" in v for v in violations)


def test_guard_rejects_cve_absent_from_evidence() -> None:
    out = _out("This is really CVE-2021-44228 Log4Shell.")  # not in the evidence block
    violations = validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("CVE-2021-44228" in v for v in violations)


def test_guard_rejects_number_absent_from_evidence() -> None:
    out = _out("Open for 999 days.")  # 999 is not in the evidence block
    violations = validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("999" in v for v in violations)


def test_guard_rejects_actor_name_when_intel_empty() -> None:
    out = _out("The CrimsonJackal crew is exploiting this.")  # intel is empty here
    violations = validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("CrimsonJackal" in v for v in violations)


def test_guard_rejects_number_that_is_substring_of_allowed() -> None:
    # evidence has 9.8 and 42; "8" is a substring of neither-as-a-token and must fail
    out = _out("Open 8 days.")
    violations = validate(
        out, evidence_block="cvss: 9.8\ndays_open: 42", retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("'8'" in v for v in violations)


def test_guard_rejects_year_substring_of_cve_digits() -> None:
    # "202" must not pass just because the CVE 2024 digits appear in evidence
    out = _out("Known since 202.")
    violations = validate(
        out, evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
        intel_empty=True, known_actors=_ACTORS,
    )
    assert any("'202'" in v for v in violations)


def test_guard_control_id_membership_is_exact_not_normalised() -> None:
    for bad in ("si-2", "SI2", "SI-2 ", "SI-2(5)"):
        violations = validate(
            _out("Patch it.", control_id=bad), evidence_block=_EVIDENCE,
            retrieved_ids=_RETRIEVED_IDS, intel_empty=True, known_actors=_ACTORS,
        )
        assert any("control_id" in v for v in violations), f"{bad!r} slipped through"


def test_guard_rejects_implied_adversary_when_intel_empty() -> None:
    # names no actor, but implies present adversary activity — still ungrounded.
    # (Denylist is best-effort; these are the high-signal phrasings it must catch.)
    for why in (
        "The ransomware campaign targeting this platform is active.",
        "An intrusion set is operating here.",
        "Attackers are exploiting this in the wild.",
        "A criminal group is targeting this service.",
        "This is being actively exploited.",
    ):
        violations = validate(
            _out(why), evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
            intel_empty=True, known_actors=_ACTORS,
        )
        assert any("adversary claim" in v for v in violations), f"slipped: {why!r}"


def test_guard_allows_sanctioned_and_grounded_phrasing() -> None:
    # sanctioned "no campaign" and grounded hypothetical exploit language must pass
    for why in (
        "No active campaign was matched to this finding.",
        "An attacker could reach this internet-facing service.",
    ):
        assert validate(
            _out(why), evidence_block=_EVIDENCE, retrieved_ids=_RETRIEVED_IDS,
            intel_empty=True, known_actors=_ACTORS,
        ) == [], f"false positive: {why!r}"


def test_template_output_usable_even_with_empty_reasons() -> None:
    result = template_result([], _RETRIEVED, "deadline")
    assert result.explanation_source == "template"
    assert len(result.output.why_ranked.split()) >= 3  # a real sentence, not empty/one word
    assert result.output.control_id == "SI-2"


def test_enforce_template_fallback_is_nonempty_from_reasons() -> None:
    # A model that always returns an invalid control_id must, after one retry,
    # fall back to a template sentence built from reasons[].
    def bad_complete(_prompt: str) -> str:
        return '{"why_ranked": "x", "control_id": "NOPE-1", "control_summary": "y"}'

    result = enforce(
        bad_complete, "prompt", evidence_block=_EVIDENCE, retrieved=_RETRIEVED,
        intel_empty=True, known_actors=_ACTORS,
        reasons=["internet-exposed (+18)", "public exploit available (+8)"],
    )
    assert result.explanation_source == "template"
    assert result.output.why_ranked.strip()  # non-empty
    assert "internet-exposed" in result.output.why_ranked  # built from reasons
    assert result.output.control_id == "SI-2"  # top retrieved control


def test_enforce_passes_grounded_llm_output() -> None:
    def good_complete(_prompt: str) -> str:
        return (
            '{"why_ranked": "Internet-facing flaw.", '
            '"control_id": "SI-2", "control_summary": "patch"}'
        )

    result = enforce(
        good_complete, "prompt", evidence_block=_EVIDENCE, retrieved=_RETRIEVED,
        intel_empty=True, known_actors=_ACTORS, reasons=["x"],
    )
    assert result.explanation_source == "llm"
    assert result.output.control_id == "SI-2"


def test_enforce_degrades_when_model_unreachable() -> None:
    # Groq down => complete raises => template fallback, brief still renders (§6).
    def dead_complete(_prompt: str) -> str:
        raise ConnectionError("groq unreachable")

    result = enforce(
        dead_complete, "prompt", evidence_block=_EVIDENCE, retrieved=_RETRIEVED,
        intel_empty=True, known_actors=_ACTORS, reasons=["internet-exposed (+18)"],
    )
    assert result.explanation_source == "template"
    assert result.output.why_ranked.strip()
