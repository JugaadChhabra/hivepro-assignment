"""Phase 7 tests: report_parser + campaign cross-check (§3)."""

from __future__ import annotations

from riskagent import config
from riskagent.ingest.csv_loader import DataBundle, load_all
from riskagent.ingest.report_parser import parse_report
from riskagent.models import EnrichedFinding
from riskagent.pipeline.campaign import apply_campaigns, cross_check, objective_by_cve
from riskagent.pipeline.control_gaps import annotate_control_gaps
from riskagent.pipeline.intel_match import match
from riskagent.pipeline.join import join


def _joined_scored(data: DataBundle) -> list[EnrichedFinding]:
    findings = match(join(data.vulnerabilities, data.assets, data.services), data.intel).findings
    annotate_control_gaps(findings)
    return findings

_REPORT = config.REPORT_PATH.read_text(encoding="utf-8")

# expected objective per actor — the mapping the parser must reproduce FROM PROSE
_EXPECTED_OBJECTIVE = {
    "CrimsonJackal": "ransomware_deployment",
    "RedMantis": "ip_theft",
    "SilentForge": "credential_theft",
    "IronVeil": "ransomware_deployment",
    "WinterViper": "payment_fraud",
}


def test_parser_extracts_five_campaigns_with_cve_chains() -> None:
    camps = parse_report(_REPORT)
    assert len(camps) == 5
    by_actor = {c.actor: c for c in camps}
    assert set(by_actor) == set(_EXPECTED_OBJECTIVE)
    assert by_actor["CrimsonJackal"].cve_chain == ["CVE-2024-21762", "CVE-2024-55591"]
    assert by_actor["IronVeil"].cve_chain == ["CVE-2023-4966"]
    assert by_actor["SilentForge"].cve_chain == [
        "CVE-2024-27198", "CVE-2024-23897", "CICD-SYN-001",
    ]
    assert all(c.cve_chain for c in camps)


def test_every_campaign_maps_to_non_unknown_objective() -> None:
    camps = parse_report(_REPORT)
    for c in camps:
        assert c.objective != "unknown"
        assert c.objective == _EXPECTED_OBJECTIVE[c.actor]


def test_objective_is_driven_by_prose_not_actor_name() -> None:
    # mutate the actor name in the raw text; the objective must not move. This is the
    # invariant "never infer objective from the actor name".
    mutated = _REPORT.replace("CrimsonJackal", "ZZTopActor")
    camps = {c.actor: c for c in parse_report(mutated)}
    assert "ZZTopActor" in camps
    assert camps["ZZTopActor"].objective == "ransomware_deployment"  # unchanged
    # and a ransomware-Yes-but-ip-theft campaign still resolves to ip_theft, not ransomware
    orig = {c.actor: c for c in parse_report(_REPORT)}
    assert orig["RedMantis"].ransomware is True
    assert orig["RedMantis"].objective == "ip_theft"


def test_cross_check_cve_passes_on_real_data_flags_on_mutation() -> None:
    camps = parse_report(_REPORT)
    intel = load_all().intel
    conflicts = cross_check(camps, intel)
    # real data: no CVE-corroboration conflict (report claims all appear in the CSV)
    assert not [c for c in conflicts if c.kind == "cve_uncorroborated"]
    # mutate a campaign's chain to a CVE the CSV does not attribute to that actor
    broken = [c.model_copy(update={"cve_chain": ["CVE-9999-0000"]}) if c.actor == "IronVeil"
              else c for c in camps]
    broken_conflicts = cross_check(broken, intel)
    assert any(c.kind == "cve_uncorroborated" and c.cve == "CVE-9999-0000"
               for c in broken_conflicts)


def test_winterviper_ransomware_conflict_fires_on_real_data() -> None:
    camps = parse_report(_REPORT)
    intel = load_all().intel
    conflicts = cross_check(camps, intel)
    rw = [c for c in conflicts if c.kind == "ransomware_association"]
    assert len(rw) == 1
    assert rw[0].actor == "WinterViper"
    assert rw[0].cve == "CVE-SYN-2026-0011"


def test_apply_campaigns_sets_objective_and_flags_conflict_finding() -> None:
    data = load_all()
    findings = _joined_scored(data)
    conflicts = apply_campaigns(findings, parse_report(_REPORT), data.intel)
    assert conflicts
    by_vuln = {f.vulnerability.vuln_id: f for f in findings}
    # Kong (WinterViper CVE-SYN-2026-0011) carries the ransomware-conflict flag + objective
    kong = by_vuln["V-2024"]
    assert "intel_ransomware_conflict" in kong.data_flags
    assert kong.campaign_objective == "payment_fraud"
    # objective map is disjoint (no CVE claimed by two campaigns)
    assert objective_by_cve(parse_report(_REPORT))["CVE-2023-4966"] == "ransomware_deployment"
