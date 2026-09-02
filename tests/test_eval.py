"""Phase 6 tests: the evaluation harness and the blast-radius before/after (§7).

No network: pairwise + precision@5 use only the deterministic scorer. recall@3
is measured in the network job (eval.py --retrieval), not here.
"""

from __future__ import annotations

import eval as harness  # eval.py at repo root

from riskagent import config
from riskagent.ingest.csv_loader import load_all


def test_blast_radius_improves_pairwise_discovered_through_eval() -> None:
    # The evidence that blast radius was DISCOVERED via evaluation, not assumed:
    # the before/after non-contested pairwise rate must strictly improve.
    data = load_all()
    golden = harness.load_golden()
    no_blast = harness._by_vuln(data, harness._WEIGHTS_NO_BLAST)
    full = harness._by_vuln(data, config.WEIGHTS)
    before = harness.pairwise_satisfaction(golden, no_blast)
    after = harness.pairwise_satisfaction(golden, full)
    assert after["rate"] > before["rate"], (before["rate"], after["rate"])


def test_pairwise_meets_regression_floor() -> None:
    data = load_all()
    golden = harness.load_golden()
    after = harness.pairwise_satisfaction(golden, harness._by_vuln(data, config.WEIGHTS))
    assert after["rate"] >= config.EVAL_PAIRWISE_FLOOR  # the CI regression gate


def test_precision_at_5_is_0_8_documented_pivot_gap() -> None:
    """precision@5 is 0.800, NOT 1.000, and that is a KNOWN, MEASURED limitation —
    pinned here so any change that moves it fires an alarm.

    The phase-7 exposure_model_mismatch rule correctly promotes V-2071 (public backup
    bucket, now scored internet-reachable) into the top-5. It displaces Fortinet
    (CVE-2024-21762, golden rank 2). Fortinet is the estate-wide initial-access pivot,
    but the scorer models business impact PER SERVICE, so Remote Access / VPN-edge
    infrastructure (customer_facing No, 0 dependents, no PCI/GDPR) is structurally
    under-weighted despite a VPN compromise being the pivot to everything else. That
    is this project's supporting-question-3 limitation, and 0.800 is its measured cost:
    exactly one golden top-5 slot. The named remedy — an asset-role signal separating
    pivot infrastructure from leaf services — is deliberately NOT built (out of scope,
    and it would be tuning toward the golden set after seeing the output).

    If this value ever changes, decide WHY before editing this number: a weight change
    that reshuffles the top-5 is a regression to investigate, not a line to update.
    """
    data = load_all()
    golden = harness.load_golden()
    findings = list(harness._by_vuln(data, config.WEIGHTS).values())
    assert harness.precision_at_5(golden, findings) == 0.8


def test_golden_pairwise_vuln_ids_resolve() -> None:
    # loader contract: every vuln_id in the golden set resolves to a scored finding
    data = load_all()
    golden = harness.load_golden()
    by_vuln = harness._by_vuln(data, config.WEIGHTS)
    for pair in golden["pairwise"]:
        assert pair["higher"]["vuln_id"] in by_vuln
        assert pair["lower"]["vuln_id"] in by_vuln
        assert pair["higher"]["vuln_id"] != pair["lower"]["vuln_id"]  # not both sides
