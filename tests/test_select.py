"""Phase 5 tests: dedupe-before-truncate selection (§6)."""

from __future__ import annotations

from riskagent.generate.assemble import score_all_findings
from riskagent.generate.select import SelectedRisk, select
from riskagent.ingest.csv_loader import load_all


def _selected(top_n: int = 5) -> list[SelectedRisk]:
    return select(score_all_findings(load_all()), top_n=top_n)


def test_select_collapses_vpn_edge_into_one_entry() -> None:
    sel = _selected(top_n=10)
    fortinet = [s for s in sel if s.cve == "CVE-2024-21762"]
    assert len(fortinet) == 1  # one entry, not three
    # the same Fortinet finding sits on all three VPN hosts (V-2015/2019/2092) and
    # collapses to one entry — vpn-staging carries it too, not just the two edges
    assert fortinet[0].affected_assets == ["vpn-edge-01", "vpn-edge-02", "vpn-staging"]


def test_select_collapses_citrixbleed_before_truncating() -> None:
    sel = _selected(top_n=5)
    citrix = [s for s in sel if s.cve == "CVE-2023-4966"]
    assert len(citrix) == 1
    assert set(citrix[0].affected_assets) == {"load-balancer-prod-01", "load-balancer-prod-02"}


def test_select_returns_five_distinct_pairs() -> None:
    sel = _selected(top_n=5)
    assert len(sel) == 5
    pairs = {(s.cve, s.vulnerability_name) for s in sel}
    assert len(pairs) == 5  # no (cve, name) counted twice
    assert [s.rank for s in sel] == [1, 2, 3, 4, 5]


def test_per_service_cap_limits_one_service() -> None:
    capped = select(score_all_findings(load_all()), top_n=10, per_service_cap=2)
    counts: dict[str, int] = {}
    for s in capped:
        svc = s.finding.service.business_service
        counts[svc] = counts.get(svc, 0) + 1
    assert all(v <= 2 for v in counts.values())
