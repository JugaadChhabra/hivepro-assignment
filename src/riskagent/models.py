"""Typed data contracts — the spine of the pipeline (§2 of implementation_plan.md).

Every downstream module consumes and returns these types, so wiring errors are
caught by ``mypy --strict`` before runtime. Two contract decisions are load
bearing and must not be "simplified":

* ``EnrichedFinding.kev_status`` is a three-valued ``Literal``, never a bool.
  ~75% of the CVE IDs are synthetic and absent from KEV; a bool would silently
  record "not checkable" as "not exploited".
* ``EnrichedFinding.intel`` is a ``list``, never ``IntelRecord | None``. One CVE
  can carry several intel records, and taking the first drops the ransomware
  signal when it arrives second.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict

# extra="forbid" turns an unexpected column into a validation error rather than a
# silently-ignored field — part of "fail loudly on schema drift".
_MODEL_CONFIG = ConfigDict(extra="forbid")


class Asset(BaseModel):
    model_config = _MODEL_CONFIG

    asset_id: str
    asset_name: str
    asset_type: str
    environment: Literal["Production", "Staging", "Development", "DR"]
    owner_team: str | None  # one row is blank — model it, don't crash on it
    business_service: str
    internet_exposed: bool
    criticality: Literal["Critical", "High", "Medium", "Low"]
    data_classification: str
    edr_installed: bool
    last_seen_days: int
    location: str
    vendor_product: str


class Vulnerability(BaseModel):
    model_config = _MODEL_CONFIG

    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str  # NOT always a real CVE — ~75% are synthetic (§4)
    severity: str
    # Intentionally unbounded here. An out-of-range CVSS is a data-quality signal,
    # not a reason to reject the whole file — a model-level ge/le bound would raise
    # on load and drop all 114 findings, violating "all 114 are scored". Range
    # checking is therefore deferred to a data_flag in phase 2 (join), where a bad
    # value is surfaced without dropping the finding.
    cvss: float
    exploit_available: bool
    patch_available: bool
    days_open: int
    asset_exposure: str
    auth_required: bool
    status: str
    affected_component: str


class IntelRecord(BaseModel):
    model_config = _MODEL_CONFIG

    intel_id: str
    threat_actor: str
    campaign_name: str
    target_sector: str
    target_region: str
    matched_cve_or_control: str
    exploit_maturity: str
    active_last_seen: date
    ransomware_association: bool
    confidence: Literal["High", "Medium", "Low"]
    summary: str


class BusinessService(BaseModel):
    model_config = _MODEL_CONFIG

    business_service: str
    business_owner: str
    business_impact: str
    customer_facing: bool
    compliance_scope: str  # e.g. "PCI DSS", "GDPR, UAE PDPL", or the literal "None"
    revenue_impact: str
    rto_hours: int
    depends_on: str | None  # 13 rows are blank — a service with no dependencies
    risk_appetite: str
    # Derived in join.py from the depends_on graph — how many services fail,
    # directly or transitively, if this one does. Not a CSV column; defaults 0.
    transitive_dependents: int = 0


class RemediationGuidance(BaseModel):
    model_config = _MODEL_CONFIG

    finding_type: str
    recommended_action: str
    priority_hint: str
    validation_evidence: str


class ControlRecord(BaseModel):
    """One NIST SP 800-53 control or control enhancement (§5). This is the ONLY
    kind of record that is ever embedded into the vector store."""

    model_config = _MODEL_CONFIG

    control_id: str  # e.g. "SI-2" or "AC-2(1)"
    family: str  # the alpha prefix, e.g. "SI"
    title: str
    statement: str  # the control text — this is what gets embedded
    discussion: str  # long, generic; stored as metadata, NOT embedded
    related_controls: list[str]


class KevEntry(BaseModel):
    """A CISA KEV catalog record. Fetched and joined in phase 7; defined here so
    ``EnrichedFinding`` is fully typed from the start."""

    model_config = _MODEL_CONFIG

    cve_id: str
    vulnerability_name: str
    date_added: date
    known_ransomware_campaign_use: str
    short_description: str


class ScoreBreakdown(BaseModel):
    model_config = _MODEL_CONFIG

    exposure: float
    exploitability: float
    adversary: float
    business: float
    control_gap: float
    blast_radius: float  # transitive-dependent fan-out + (phase-7) campaign objective
    total: float
    reasons: list[str]  # one human-readable string per contributing factor


class EnrichedFinding(BaseModel):
    model_config = _MODEL_CONFIG

    vulnerability: Vulnerability
    asset: Asset
    service: BusinessService
    intel: list[IntelRecord]  # empty list is a valid, common state
    # Per-record relevance weight in [0,1], keyed by intel_id (phase 2). Kept
    # deliberately SEPARATE from the match signal (which is ``bool(intel)``): a
    # weak/low-relevance record is still a match and still counts toward the 24.
    intel_relevance: dict[str, float] = {}
    kev: KevEntry | None = None
    kev_status: Literal["listed", "not_listed", "unknown"] = "unknown"
    control_gaps: list[str] = []
    data_flags: list[str] = []  # staleness, no owner, exposure disagreement
    # Set in phase 7 from report_parser's Campaign records; scored dormant until then.
    campaign_objective: str | None = None
    score: ScoreBreakdown | None = None
