"""Fetch and cache the NIST SP 800-53 Rev 5 control catalog (§3, §5).

Fetch live, cache to disk WITH a timestamp, fall back to the cached copy when the
fetch fails. Parse to one ``ControlRecord`` per control/enhancement.

The 7-day staleness warning, /healthz surfacing, and rendered banner are phase 7;
here we only capture ``fetched_at`` so that check has something to measure.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from riskagent import config
from riskagent.models import ControlRecord

_EXPECTED_HEADER = ["identifier", "name", "control_text", "discussion", "related", ""]
_FETCH_TIMEOUT_S = 60
# csrc.nist.gov returns 403 to the default "Python-urllib" agent; identify ourselves.
_USER_AGENT = "riskagent/0.1 (TawasolPay cyber-risk assistant; +https://github.com)"


@dataclass(frozen=True)
class NistCatalog:
    controls: list[ControlRecord]
    fetched_at: datetime  # when the served copy was fetched live (UTC)
    catalog_version: str  # human label (the CSV carries no version field)
    catalog_sha256: str  # hash of the fetched CSV bytes — the provenance FACT
    source: Literal["live", "cache"]


def _parse_related(raw: str) -> list[str]:
    # "AC-2, AC-4, SI-3." -> ["AC-2", "AC-4", "SI-3"]
    return [token.strip(" .") for token in raw.split(",") if token.strip(" .")]


def parse_catalog(csv_text: str) -> list[ControlRecord]:
    reader = csv.reader(io.StringIO(csv_text))
    header = next(reader, None)
    if header != _EXPECTED_HEADER:
        raise ValueError(f"unexpected NIST catalog header: {header!r}")
    controls: list[ControlRecord] = []
    for row in reader:
        if not row or not row[0].strip():
            continue
        control_id = row[0].strip()
        controls.append(
            ControlRecord(
                control_id=control_id,
                family=control_id.split("-", 1)[0],
                title=row[1].strip(),
                statement=row[2].strip(),
                discussion=row[3].strip(),
                related_controls=_parse_related(row[4]),
            )
        )
    return controls


def _write_cache(
    path: Path, controls: list[ControlRecord], fetched_at: datetime, catalog_sha256: str
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": fetched_at.isoformat(),
        "catalog_version": config.NIST_CATALOG_VERSION,
        "catalog_sha256": catalog_sha256,
        "controls": [c.model_dump() for c in controls],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _read_cache(path: Path) -> NistCatalog:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return NistCatalog(
        controls=[ControlRecord.model_validate(c) for c in payload["controls"]],
        fetched_at=datetime.fromisoformat(payload["fetched_at"]),
        catalog_version=payload["catalog_version"],
        catalog_sha256=payload["catalog_sha256"],
        source="cache",
    )


def load_catalog(
    *,
    offline: bool = False,
    url: str | None = None,
    cache_path: Path | None = None,
) -> NistCatalog:
    """Fetch the catalog FRESH, falling back to the cached copy on failure.

    Fetching fresh at startup is the invariant; the cache is the fallback, not the
    primary. A live fetch refreshes the cache and its ``fetched_at``; a failed
    fetch serves the cached copy unchanged, so its age stays truthful for the
    phase-7 staleness check. ``offline=True`` skips the network entirely and
    requires a cache (used to exercise the fallback path deterministically).
    """
    url = url or config.NIST_CATALOG_URL
    cache_path = cache_path or config.NIST_CACHE_PATH

    if offline:
        if cache_path.exists():
            return _read_cache(cache_path)
        raise FileNotFoundError(f"offline and no NIST cache at {cache_path}")

    try:
        request = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        with urllib.request.urlopen(request, timeout=_FETCH_TIMEOUT_S) as response:
            raw = response.read()
        csv_text = raw.decode("utf-8")
        catalog_sha256 = hashlib.sha256(raw).hexdigest()
        controls = parse_catalog(csv_text)
        fetched_at = datetime.now(UTC)
        _write_cache(cache_path, controls, fetched_at, catalog_sha256)
        return NistCatalog(
            controls=controls,
            fetched_at=fetched_at,
            catalog_version=config.NIST_CATALOG_VERSION,
            catalog_sha256=catalog_sha256,
            source="live",
        )
    except OSError:
        if cache_path.exists():
            return _read_cache(cache_path)
        raise
