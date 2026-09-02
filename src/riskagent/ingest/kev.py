"""Fetch, cache, and join the CISA KEV catalog (§3, §7).

Same fetch-live / cache-with-timestamp / fall-back-on-failure shape as ``nist.py``.
Two things are load-bearing and must not be "simplified":

* **Staleness is visible, not silent.** A live fetch stamps ``fetched_at = now`` so
  the served copy is fresh. A failed fetch serves the cached copy UNCHANGED, so its
  age stays truthful; if that age exceeds 7 days we set ``staleness_warning`` — which
  reaches ``/healthz`` and the rendered banner. A cache fallback that says nothing is
  itself a finding.
* **A miss is "unknown", not "not_listed".** Only a real CVE confirmed absent from a
  successfully-fetched catalog is ``not_listed``. A synthetic id (CVE-SYN-*, K8S-SYN-*,
  …) is not checkable against KEV at all, so it is ``unknown`` — never silently
  recorded as "not exploited". If the catalog could not be loaded, every finding is
  ``unknown``.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from riskagent import config
from riskagent.models import EnrichedFinding, KevEntry

_FETCH_TIMEOUT_S = 30
_USER_AGENT = "riskagent/0.1 (TawasolPay cyber-risk assistant; +https://github.com)"
_STALE_AFTER = timedelta(days=7)
# a REAL CVE id: "CVE-YYYY-NNNN+". Synthetic ids (CVE-SYN-2026-0001, K8S-SYN-001, …)
# do not match, so they are classified "unknown" (not checkable), never "not_listed".
_REAL_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass(frozen=True)
class KevCatalog:
    by_cve: dict[str, KevEntry]
    fetched_at: datetime
    catalog_version: str
    source: Literal["live", "cache"]

    @property
    def staleness_warning(self) -> bool:
        """True iff the SERVED copy is more than 7 days old (age measured to now)."""
        return datetime.now(UTC) - self.fetched_at > _STALE_AFTER


def is_real_cve(cve: str) -> bool:
    return bool(_REAL_CVE_RE.match(cve))


def parse_kev(raw: bytes) -> tuple[dict[str, KevEntry], str]:
    payload = json.loads(raw)
    version = str(payload.get("catalogVersion", ""))
    by_cve: dict[str, KevEntry] = {}
    for v in payload["vulnerabilities"]:
        entry = KevEntry(
            cve_id=v["cveID"],
            vulnerability_name=v.get("vulnerabilityName", ""),
            date_added=datetime.strptime(v["dateAdded"], "%Y-%m-%d").date(),
            known_ransomware_campaign_use=v.get("knownRansomwareCampaignUse", ""),
            short_description=v.get("shortDescription", ""),
        )
        by_cve[entry.cve_id] = entry
    return by_cve, version


def _write_cache(path: Path, catalog: KevCatalog) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": catalog.fetched_at.isoformat(),
        "catalog_version": catalog.catalog_version,
        "vulnerabilities": [e.model_dump(mode="json") for e in catalog.by_cve.values()],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read_cache(path: Path) -> KevCatalog:
    payload = json.loads(path.read_text(encoding="utf-8"))
    by_cve = {e["cve_id"]: KevEntry.model_validate(e) for e in payload["vulnerabilities"]}
    return KevCatalog(
        by_cve=by_cve,
        fetched_at=datetime.fromisoformat(payload["fetched_at"]),
        catalog_version=payload["catalog_version"],
        source="cache",
    )


def load_kev(
    *,
    offline: bool = False,
    url: str | None = None,
    cache_path: Path | None = None,
) -> KevCatalog | None:
    """Fetch KEV fresh, falling back to cache on failure. Returns None only when the
    catalog is entirely unavailable (offline with no cache, or fetch failed with no
    cache) — callers then mark every finding ``unknown`` rather than guessing."""
    url = url or config.KEV_URL
    cache_path = cache_path or config.KEV_CACHE_PATH

    if offline:
        return _read_cache(cache_path) if cache_path.exists() else None

    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_S) as response:
            raw = response.read()
        by_cve, version = parse_kev(raw)
        catalog = KevCatalog(
            by_cve=by_cve, fetched_at=datetime.now(UTC), catalog_version=version, source="live"
        )
        _write_cache(cache_path, catalog)
        return catalog
    except OSError:
        return _read_cache(cache_path) if cache_path.exists() else None


@dataclass(frozen=True)
class KevJoin:
    kev_lookups: int  # findings looked up (all of them)
    kev_hits: int  # findings whose CVE is KEV-listed
    kev_checkable: int  # of the lookups, how many had a real CVE to check (the rest -> unknown)
    kev_coverage_pct: float  # hits / lookups * 100 — "% of findings KEV flags as known-exploited"


def apply_kev(findings: list[EnrichedFinding], catalog: KevCatalog | None) -> KevJoin:
    """Set ``kev_status`` and ``kev`` on each finding in place; return join stats.

    coverage is hits / ALL findings (~25% expected). 100% or 0% signals a broken join:
    100% would mean every synthetic id somehow matched, 0% that no real CVE did."""
    hits = checkable = 0
    for f in findings:
        cve = f.vulnerability.cve
        if catalog is None or not is_real_cve(cve):
            f.kev_status = "unknown"  # not checkable — never silently "not_listed"
            f.kev = None
            continue
        checkable += 1
        entry = catalog.by_cve.get(cve)
        if entry is not None:
            f.kev_status = "listed"
            f.kev = entry
            hits += 1
        else:
            f.kev_status = "not_listed"
            f.kev = None
    lookups = len(findings)
    coverage = (hits / lookups * 100) if lookups else 0.0
    return KevJoin(
        kev_lookups=lookups, kev_hits=hits, kev_checkable=checkable,
        kev_coverage_pct=round(coverage, 1),
    )
