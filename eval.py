"""Evaluation harness (§7). Prints three numbers and dumps the scored findings.

    pairwise_satisfaction   satisfied / total, EXCLUDING contested pairs (primary)
    precision_at_5          |predicted top5 ∩ golden top5| / 5
    retrieval_recall_at_3   hit if an expected/acceptable control is in the top 3

Pairwise and precision need only the deterministic scorer (no network); recall@3
builds the real Chroma index (network) and runs only with --retrieval. The golden
data is judgement recorded before the scorer's output was trusted; this harness
measures the scorer against it, never the reverse.

Usage:
    python eval.py                 # pairwise + precision@5, and the before/after blast-radius rates
    python eval.py --dump FILE     # write all 114 scored findings to CSV, sorted by score
    python eval.py --retrieval     # also compute recall@3 (needs network + model)
"""

from __future__ import annotations

import argparse
import copy
import csv
import sys
from pathlib import Path
from typing import Any

import yaml

from riskagent import config
from riskagent.generate.assemble import score_all_findings
from riskagent.generate.select import select
from riskagent.ingest.csv_loader import DataBundle, load_all
from riskagent.models import EnrichedFinding
from riskagent.pipeline.score import Weights, score
from riskagent.rag.index import ControlStore

_GOLDEN = Path(__file__).resolve().parent / "tests" / "golden" / "golden_set.yaml"

# Weights with the blast-radius group zeroed — the "before" scorer, for the
# discovered-through-evaluation before/after evidence the plan requires.
_WEIGHTS_NO_BLAST: dict[str, dict[str, float]] = copy.deepcopy(config.WEIGHTS)
_WEIGHTS_NO_BLAST["blast_radius"] = dict.fromkeys(config.WEIGHTS["blast_radius"], 0.0)


def load_golden(path: Path = _GOLDEN) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data


def _by_vuln(data: DataBundle, weights: Weights) -> dict[str, EnrichedFinding]:
    findings = score_all_findings(data)
    for finding in findings:  # rescore with the given weights (for before/after)
        finding.score = score(finding, weights=weights)
    return {f.vulnerability.vuln_id: f for f in findings}


def pairwise_satisfaction(
    golden: dict[str, Any], by_vuln: dict[str, EnrichedFinding]
) -> dict[str, float]:
    counted = satisfied = contested_total = contested_ok = 0
    for pair in golden["pairwise"]:
        higher = by_vuln[pair["higher"]["vuln_id"]].score
        lower = by_vuln[pair["lower"]["vuln_id"]].score
        assert higher is not None and lower is not None
        ok = higher.total > lower.total
        if pair.get("contested"):
            contested_total += 1
            contested_ok += int(ok)
        else:
            counted += 1
            satisfied += int(ok)
    return {
        "rate": satisfied / counted if counted else 0.0,
        "satisfied": satisfied,
        "total": counted,
        "contested_rate": contested_ok / contested_total if contested_total else 0.0,
        "contested_total": contested_total,
    }


def precision_at_5(golden: dict[str, Any], findings: list[EnrichedFinding]) -> float:
    predicted = {s.cve for s in select(findings, top_n=5)}
    gold = {e["cve"] for e in golden["top_five"]["entries"]}
    return len(predicted & gold) / 5


def recall_at_3(
    golden: dict[str, Any],
    by_vuln: dict[str, EnrichedFinding],
    store: ControlStore,
) -> float:
    from riskagent.rag.retrieve import retrieve

    hits = total = 0
    for label in golden["retrieval"]:
        finding = by_vuln[label["example_vuln_id"]]
        acceptable = set(label["expected_controls"]) | set(label.get("acceptable_controls", []))
        result = retrieve(finding, store, finding_type=label["finding_type"])
        top3 = {c.control_id for c in result.chunks}
        hits += int(bool(top3 & acceptable))
        total += 1
    return hits / total if total else 0.0


def dump_csv(path: Path, findings: list[EnrichedFinding]) -> None:
    rows = sorted(findings, key=lambda f: f.score.total if f.score else 0.0, reverse=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "vuln_id", "cve", "vulnerability_name", "asset", "service", "environment",
            "criticality", "internet_exposed", "exploit_available", "auth_required", "cvss",
            "days_open", "edr", "transitive_dependents", "intel_count", "ransomware",
            "control_gaps", "kev_status", "exposure", "exploitability", "adversary",
            "business", "control_gap", "blast_radius", "total",
        ])
        for f in rows:
            s = f.score
            assert s is not None
            writer.writerow([
                f.vulnerability.vuln_id, f.vulnerability.cve, f.vulnerability.vulnerability_name,
                f.asset.asset_name, f.service.business_service, f.asset.environment,
                f.asset.criticality, f.asset.internet_exposed, f.vulnerability.exploit_available,
                f.vulnerability.auth_required, f.vulnerability.cvss, f.vulnerability.days_open,
                f.asset.edr_installed, f.service.transitive_dependents, len(f.intel),
                any(r.ransomware_association for r in f.intel), "|".join(f.control_gaps),
                f.kev_status, f"{s.exposure:g}", f"{s.exploitability:g}", f"{s.adversary:g}",
                f"{s.business:g}", f"{s.control_gap:g}", f"{s.blast_radius:g}", f"{s.total:g}",
            ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dump", type=Path, help="write all 114 scored findings to CSV")
    parser.add_argument("--retrieval", action="store_true", help="also compute recall@3 (network)")
    args = parser.parse_args()

    data = load_all()
    golden = load_golden()
    by_vuln_full = _by_vuln(data, config.WEIGHTS)
    findings_full = list(by_vuln_full.values())

    if args.dump:
        dump_csv(args.dump, findings_full)
        print(f"wrote {len(findings_full)} scored findings to {args.dump}")
        return 0

    before = pairwise_satisfaction(golden, _by_vuln(data, _WEIGHTS_NO_BLAST))
    after = pairwise_satisfaction(golden, by_vuln_full)
    prec = precision_at_5(golden, findings_full)

    print("=== Evaluation ===")
    print(f"pairwise_satisfaction (primary): {after['rate']:.3f}  "
          f"({after['satisfied']}/{after['total']} non-contested)")
    print(f"  before blast radius:           {before['rate']:.3f}  "
          f"({before['satisfied']}/{before['total']})")
    print(f"  contested (reported, not gated): {after['contested_rate']:.3f}  "
          f"({after['contested_total']} pairs)")
    print(f"precision_at_5:                  {prec:.3f}")

    if args.retrieval:
        from riskagent.ingest.nist import load_catalog
        from riskagent.rag.index import ChromaControlStore

        catalog = load_catalog()
        store = ChromaControlStore()
        store.build(catalog.controls, catalog_sha256=catalog.catalog_sha256)
        recall = recall_at_3(golden, by_vuln_full, store)
        print(f"retrieval_recall_at_3:           {recall:.3f}")

    # regression gate: a weight change that breaks a non-contested constraint fails CI
    return 0 if after["rate"] >= config.EVAL_PAIRWISE_FLOOR else 1


if __name__ == "__main__":
    sys.exit(main())
