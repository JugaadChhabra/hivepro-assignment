"""Phase 7 tests: CISA KEV fetch/cache/join (§3, §7).

Deterministic tests build a KevCatalog by hand (no network). Two tests that assert
properties of the LIVE catalog are marked ``network``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from riskagent.generate.assemble import score_all_findings
from riskagent.ingest.csv_loader import load_all
from riskagent.ingest.kev import KevCatalog, _write_cache, apply_kev, is_real_cve, load_kev
from riskagent.models import KevEntry
from riskagent.pipeline.score import score_all


def _entry(cve: str) -> KevEntry:
    from datetime import date

    return KevEntry(
        cve_id=cve, vulnerability_name=f"{cve} name", date_added=date(2024, 1, 1),
        known_ransomware_campaign_use="Known", short_description="desc",
    )


def _catalog(
    cves: list[str], *, fetched_at: datetime | None = None, source: str = "live"
) -> KevCatalog:
    return KevCatalog(
        by_cve={c: _entry(c) for c in cves},
        fetched_at=fetched_at or datetime.now(UTC),
        catalog_version="test",
        source=source,  # type: ignore[arg-type]
    )


def test_real_cve_detection_excludes_synthetic() -> None:
    assert is_real_cve("CVE-2024-21762")
    assert not is_real_cve("CVE-SYN-2026-0011")
    assert not is_real_cve("K8S-SYN-001")
    assert not is_real_cve("CTRL-SYN-003")


def test_synthetic_id_is_unknown_not_not_listed() -> None:
    # a synthetic id is not checkable against KEV — it must be "unknown", never
    # "not_listed" (which would silently claim "confirmed not exploited").
    findings = score_all_findings(load_all())
    catalog = _catalog(["CVE-2024-21762"])  # real catalog, does NOT contain synthetics
    apply_kev(findings, catalog)
    by_vuln = {f.vulnerability.vuln_id: f for f in findings}
    kong = by_vuln["V-2024"]  # CVE-SYN-2026-0011
    assert kong.vulnerability.cve == "CVE-SYN-2026-0011"
    assert kong.kev_status == "unknown"
    # a real CVE present in the catalog is "listed"; a real CVE absent is "not_listed"
    fortinet = next(f for f in findings if f.vulnerability.cve == "CVE-2024-21762")
    assert fortinet.kev_status == "listed"
    absent = next(f for f in findings if f.vulnerability.cve == "CVE-2024-6387")
    assert absent.kev_status == "not_listed"


def test_no_catalog_marks_everything_unknown() -> None:
    findings = score_all_findings(load_all())
    apply_kev(findings, None)  # fetch failed, no cache
    assert all(f.kev_status == "unknown" for f in findings)


def test_offline_falls_back_to_cache_without_raising(tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    _write_cache(cache, _catalog(["CVE-2024-21762"], source="live"))
    got = load_kev(offline=True, cache_path=cache)  # must not raise, must not hit network
    assert got is not None
    assert "CVE-2024-21762" in got.by_cve
    assert got.source == "cache"
    # offline with NO cache returns None rather than raising
    assert load_kev(offline=True, cache_path=tmp_path / "absent.json") is None


def test_stale_cache_sets_warning_and_renders_banner(tmp_path: Path) -> None:
    # a cache fetched 10 days ago, served offline, must flip the staleness warning...
    cache = tmp_path / "kev.json"
    old = datetime.now(UTC) - timedelta(days=10)
    _write_cache(cache, _catalog(["CVE-2024-21762"], fetched_at=old, source="live"))
    catalog = load_kev(offline=True, cache_path=cache)
    assert catalog is not None
    assert catalog.staleness_warning is True

    # ...and the banner must actually RENDER, not just set a flag.
    from riskagent.generate.assemble import Provenance
    from riskagent.generate.render import render_html

    prov = Provenance(
        nist_catalog_version="v", nist_catalog_sha256="0" * 64, index_built_at="t",
        nist_fetched_at="t", generated_at="t",
        kev_fetched_at=old.isoformat(), kev_staleness_warning=True,
    )
    from riskagent.generate.assemble import RiskBrief

    html = render_html(RiskBrief(entries=[], provenance=prov))
    assert "KEV feed is more than 7 days stale" in html


def test_fresh_cache_no_warning(tmp_path: Path) -> None:
    cache = tmp_path / "kev.json"
    _write_cache(cache, _catalog(["CVE-2024-21762"], fetched_at=datetime.now(UTC)))
    catalog = load_kev(offline=True, cache_path=cache)
    assert catalog is not None and catalog.staleness_warning is False


@pytest.mark.network
def test_live_kev_coverage_in_band() -> None:
    catalog = load_kev()
    assert catalog is not None
    findings = score_all_findings(load_all())
    join = apply_kev(findings, catalog)
    # neither 0 nor 100 (both mean a broken join); ~25% expected
    assert 20.0 <= join.kev_coverage_pct <= 35.0, join.kev_coverage_pct
    assert 0 < join.kev_hits < join.kev_lookups


@pytest.mark.network
def test_kev_enrichment_does_not_change_golden_pairwise() -> None:
    # the point of building phase 6 first: KEV enrichment adds +2 to listed CVEs but
    # must not flip a golden pairwise constraint. Measured before vs after.
    from eval import load_golden, pairwise_satisfaction

    golden = load_golden()
    findings = score_all_findings(load_all())
    before = pairwise_satisfaction(golden, {f.vulnerability.vuln_id: f for f in findings})["rate"]
    apply_kev(findings, load_kev())
    score_all(findings)
    after = pairwise_satisfaction(golden, {f.vulnerability.vuln_id: f for f in findings})["rate"]
    assert after == before, f"KEV changed pairwise {before} -> {after}"
