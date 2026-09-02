"""Weights, thresholds, and fixed reference points for deterministic scoring.

The weights live here as a plain nested dict so ``eval.py`` can sweep them in
phase 6 (change one, re-measure). They are v0 — the report's stated factor
ordering, NOT tuned toward any desired answer.

Provenance: the five weight groups and their ordering come from the MDR report's
"Threat Intelligence Analyst Notes" ranking rubric in
``data/synthetic_threat_report.md``. That section is the scoring rubric, not data,
so it is encoded here rather than parsed (phase 7 adds the exact line citation).
"""

from __future__ import annotations

from datetime import date

# Reference "now" for recency scoring. Pinned to the freshest active_last_seen in
# the intel feed (2026-04-24) so score() is deterministic and reproducible — never
# wall-clock, which would make scores drift day to day and break purity.
REFERENCE_DATE = date(2026, 4, 24)

STALE_LAST_SEEN_DAYS = 30  # asset staleness: sets a flag, adds ZERO points (§4)
RECENT_INTEL_DAYS = 30  # adversary recency window
DAYS_OPEN_THRESHOLD = 30  # control-gap: vuln open longer than this

# "region or sector fit" for the adversary +2 term. A binary threshold, distinct
# from intel_match.relevance_weight's graded [0,1] blend (which is auxiliary).
HOME_REGION = "Middle East"
FIT_SECTORS = frozenset(
    {"Financial Services", "Fintech", "Finance", "Fintech and API-First", "Healthcare and Finance"}
)
# compliance_scope is multi-valued; +4 if either token appears (approved reading).
PCI_GDPR_TOKENS = frozenset({"PCI DSS", "GDPR"})

# Group maxima (documented; the additive terms are designed to sum to these):
# exposure 25, exploitability 22, adversary 25, business 20, control_gap 10.
WEIGHTS: dict[str, dict[str, float]] = {
    "exposure": {
        "internet_exposed": 18.0,
        "production": 7.0,
    },
    "exploitability": {
        "cvss_scale": 8.0,  # multiplier on cvss/10 -> 0..8
        "exploit_available": 8.0,
        "no_auth": 4.0,
        "kev_listed": 2.0,
    },
    "adversary": {
        "intel_match": 8.0,
        "ransomware": 8.0,
        "region_or_sector_fit": 2.0,
        "recent_activity": 2.0,
        # exploit-maturity points come from MATURITY_POINTS below (max over records).
    },
    "business": {
        "customer_facing": 4.0,
        "compliance_pci_gdpr": 4.0,
        "revenue_high_or_critical": 4.0,  # approved: High OR Critical (Critical >= High)
        # asset-criticality points come from CRITICALITY_POINTS below.
    },
    "control_gap": {
        "no_edr": 5.0,
        "no_vendor_patch": 3.0,
        "days_open": 2.0,
    },
    # TOTAL lookup maps — MUST cover the full enum domain the scorer reads, so an
    # unhandled value crashes loudly (KeyError) rather than silently scoring 0.
    # These are ordinal signals; the specific point values are phase-6 tuning
    # candidates. Maturity levels enumerate all six enum values (an earlier draft
    # listed only two, which silently zeroed Active Exploitation — the CitrixBleed
    # miss); part of the same WEIGHTS dict so eval.py sweeps them too.
    "maturity": {
        "Active Exploitation": 5.0,  # attacks happening now — at least equal to weaponized
        "Weaponized": 5.0,  # reliable exploit exists
        "Commodity Exploit": 3.0,  # widely available, lower skill floor
        "Proof of Concept": 2.0,
        "Social Engineering": 2.0,  # real, but not a technical exploit path
        "Not Applicable": 0.0,
    },
    "criticality": {
        "Critical": 8.0,
        "High": 5.0,
        "Medium": 2.0,
        "Low": 0.0,
    },
}
