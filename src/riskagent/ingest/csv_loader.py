"""Load the five provided CSVs into typed pydantic models (§3).

Coercion rules, applied by the loader (models stay pure declarations):

* ``Yes`` / ``No`` -> ``bool`` (anything else raises)
* ISO date strings -> ``datetime.date``
* empty string in an *optional* column (``owner_team``, ``depends_on``) -> ``None``

Schema drift raises rather than defaulting: the header must match exactly, every
row must have exactly the expected number of fields, a blank cell in any column
that is not explicitly optional raises, and an unexpected enum value or bad number
propagates the underlying ``ValueError`` / ``ValidationError``.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from riskagent.models import (
    Asset,
    BusinessService,
    IntelRecord,
    RemediationGuidance,
    Vulnerability,
)

# repo-root/data, resolved from this file so the loader is CWD-independent:
# csv_loader.py -> ingest -> riskagent -> src -> <repo root>
DATA_DIR = Path(__file__).resolve().parents[3] / "data"


class SchemaError(ValueError):
    """Raised when a CSV's shape does not match the expected contract."""


def _bool(value: str, column: str) -> bool:
    if value == "Yes":
        return True
    if value == "No":
        return False
    raise SchemaError(f"{column}: expected 'Yes' or 'No', got {value!r}")


def _opt(value: str) -> str | None:
    return None if value == "" else value


def _read_rows(
    path: Path,
    expected_columns: list[str],
    optional_columns: frozenset[str] = frozenset(),
) -> list[dict[str, str]]:
    """Read a CSV, asserting header and per-row field count match exactly.

    A blank cell in any column not listed in ``optional_columns`` raises — so
    "fail loudly" holds for required *string* fields too, not just the numeric,
    date, and Literal fields whose own parsers already reject an empty cell.
    """
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise SchemaError(f"{path.name}: file is empty") from exc
        if header != expected_columns:
            raise SchemaError(
                f"{path.name}: header mismatch.\n  expected {expected_columns}\n  got      {header}"
            )
        rows: list[dict[str, str]] = []
        for line_no, record in enumerate(reader, start=2):
            if len(record) != len(expected_columns):
                raise SchemaError(
                    f"{path.name} line {line_no}: expected {len(expected_columns)} "
                    f"fields, got {len(record)}"
                )
            row = dict(zip(expected_columns, record, strict=True))
            for column, value in row.items():
                if value == "" and column not in optional_columns:
                    raise SchemaError(
                        f"{path.name} line {line_no}: required column {column!r} is blank"
                    )
            rows.append(row)
    return rows


_ASSET_COLUMNS = [
    "asset_id", "asset_name", "asset_type", "environment", "owner_team",
    "business_service", "internet_exposed", "criticality", "data_classification",
    "edr_installed", "last_seen_days", "location", "vendor_product",
]  # fmt: skip


def load_assets(path: Path | None = None) -> list[Asset]:
    path = path or DATA_DIR / "assets.csv"
    return [
        Asset(
            asset_id=r["asset_id"],
            asset_name=r["asset_name"],
            asset_type=r["asset_type"],
            environment=r["environment"],
            owner_team=_opt(r["owner_team"]),
            business_service=r["business_service"],
            internet_exposed=_bool(r["internet_exposed"], "internet_exposed"),
            criticality=r["criticality"],
            data_classification=r["data_classification"],
            edr_installed=_bool(r["edr_installed"], "edr_installed"),
            last_seen_days=int(r["last_seen_days"]),
            location=r["location"],
            vendor_product=r["vendor_product"],
        )
        for r in _read_rows(path, _ASSET_COLUMNS, optional_columns=frozenset({"owner_team"}))
    ]


_VULN_COLUMNS = [
    "vuln_id", "asset_id", "vulnerability_name", "cve", "severity", "cvss",
    "exploit_available", "patch_available", "days_open", "asset_exposure",
    "auth_required", "status", "affected_component",
]  # fmt: skip


def load_vulnerabilities(path: Path | None = None) -> list[Vulnerability]:
    path = path or DATA_DIR / "vulnerabilities.csv"
    return [
        Vulnerability(
            vuln_id=r["vuln_id"],
            asset_id=r["asset_id"],
            vulnerability_name=r["vulnerability_name"],
            cve=r["cve"],
            severity=r["severity"],
            cvss=float(r["cvss"]),
            exploit_available=_bool(r["exploit_available"], "exploit_available"),
            patch_available=_bool(r["patch_available"], "patch_available"),
            days_open=int(r["days_open"]),
            asset_exposure=r["asset_exposure"],
            auth_required=_bool(r["auth_required"], "auth_required"),
            status=r["status"],
            affected_component=r["affected_component"],
        )
        for r in _read_rows(path, _VULN_COLUMNS)
    ]


_INTEL_COLUMNS = [
    "intel_id", "threat_actor", "campaign_name", "target_sector", "target_region",
    "matched_cve_or_control", "exploit_maturity", "active_last_seen",
    "ransomware_association", "confidence", "summary",
]  # fmt: skip


def load_intel(path: Path | None = None) -> list[IntelRecord]:
    path = path or DATA_DIR / "threat_intelligence.csv"
    return [
        IntelRecord(
            intel_id=r["intel_id"],
            threat_actor=r["threat_actor"],
            campaign_name=r["campaign_name"],
            target_sector=r["target_sector"],
            target_region=r["target_region"],
            matched_cve_or_control=r["matched_cve_or_control"],
            exploit_maturity=r["exploit_maturity"],
            active_last_seen=date.fromisoformat(r["active_last_seen"]),
            ransomware_association=_bool(r["ransomware_association"], "ransomware_association"),
            confidence=r["confidence"],
            summary=r["summary"],
        )
        for r in _read_rows(path, _INTEL_COLUMNS)
    ]


_SERVICE_COLUMNS = [
    "business_service", "business_owner", "business_impact", "customer_facing",
    "compliance_scope", "revenue_impact", "rto_hours", "depends_on", "risk_appetite",
]  # fmt: skip


def load_services(path: Path | None = None) -> list[BusinessService]:
    path = path or DATA_DIR / "business_services.csv"
    return [
        BusinessService(
            business_service=r["business_service"],
            business_owner=r["business_owner"],
            business_impact=r["business_impact"],
            customer_facing=_bool(r["customer_facing"], "customer_facing"),
            compliance_scope=r["compliance_scope"],
            revenue_impact=r["revenue_impact"],
            rto_hours=int(r["rto_hours"]),
            depends_on=_opt(r["depends_on"]),
            risk_appetite=r["risk_appetite"],
        )
        for r in _read_rows(path, _SERVICE_COLUMNS, optional_columns=frozenset({"depends_on"}))
    ]


_GUIDANCE_COLUMNS = ["finding_type", "recommended_action", "priority_hint", "validation_evidence"]


def load_guidance(path: Path | None = None) -> list[RemediationGuidance]:
    path = path or DATA_DIR / "remediation_guidance.csv"
    return [
        RemediationGuidance(
            finding_type=r["finding_type"],
            recommended_action=r["recommended_action"],
            priority_hint=r["priority_hint"],
            validation_evidence=r["validation_evidence"],
        )
        for r in _read_rows(path, _GUIDANCE_COLUMNS)
    ]


@dataclass(frozen=True)
class DataBundle:
    """All five loaded datasets. Equality is structural, so two loads compare
    equal — the idempotency property the tests assert."""

    assets: list[Asset]
    vulnerabilities: list[Vulnerability]
    intel: list[IntelRecord]
    services: list[BusinessService]
    guidance: list[RemediationGuidance]


def load_all(data_dir: Path | None = None) -> DataBundle:
    data_dir = data_dir or DATA_DIR
    return DataBundle(
        assets=load_assets(data_dir / "assets.csv"),
        vulnerabilities=load_vulnerabilities(data_dir / "vulnerabilities.csv"),
        intel=load_intel(data_dir / "threat_intelligence.csv"),
        services=load_services(data_dir / "business_services.csv"),
        guidance=load_guidance(data_dir / "remediation_guidance.csv"),
    )
