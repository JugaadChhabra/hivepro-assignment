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
from pathlib import Path

# --- paths / cache (all gitignored; rebuilt on demand) ---
CACHE_DIR = Path(__file__).resolve().parents[2] / "cache"
NIST_CACHE_PATH = CACHE_DIR / "nist_sp800-53r5.json"
CHROMA_DIR = CACHE_DIR / "chroma"
CHROMA_COLLECTION = "nist_800_53"

# --- NIST SP 800-53 catalog (§3, §5) ---
NIST_CATALOG_URL = (
    "https://csrc.nist.gov/CSRC/media/Projects/risk-management/"
    "800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv"
)
# The catalog_load CSV does not carry a version field; this is the published
# revision it corresponds to. Phase 7 tightens the live staleness handling.
NIST_CATALOG_VERSION = "SP 800-53 Rev 5"

# --- LLM (§6) — writes the explanation sentence only, never a rank/score/control ---
GROQ_MODEL = "llama-3.3-70b-versatile"
GROQ_TEMPERATURE = 0.0
GROQ_TIMEOUT_S = 20.0  # per-call; an unreachable endpoint must RAISE, not hang
LLM_STAGE_DEADLINE_S = 30.0  # outer bound on the whole 5-call stage; stragglers -> template
# An enhancement is only shown if it matched at least this well; a weak match
# surfaces NO enhancement rather than the least-bad of a dozen (SC-7 flooding).
ENHANCEMENT_MAX_DISTANCE = 0.75
MAX_ENHANCEMENTS_SHOWN = 2

# --- RAG (§5) ---
EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"  # local, CPU, 384-dim, no API key
RETRIEVAL_TOP_K = 3
# Over-fetch before collapsing enhancements (e.g. SI-2(5)) to their base control
# (SI-2), so the top-k are k DISTINCT base controls, not one control's enhancements.
RETRIEVAL_OVERFETCH = 40
# Cosine distance (Chroma space) above which the family pre-filter is abandoned and
# the query retried unfiltered. Provisional — retrieval quality is measured in phase 6.
RETRIEVAL_DISTANCE_THRESHOLD = 1.0

# Reference "now" for recency scoring. Pinned to the freshest active_last_seen in
# the intel feed (2026-04-24) so score() is deterministic and reproducible — never
# wall-clock, which would make scores drift day to day and break purity.
REFERENCE_DATE = date(2026, 4, 24)

# Regression gate (§7): eval.py fails CI if non-contested pairwise drops below this.
# Current measured value (after blast radius). The two unsatisfied non-contested
# pairs (P03 exposure-vs-internal-ransomware, P09 recovery_of_last_resort) are
# documented consequence-gaps the current signals do not close — NOT overfit away.
EVAL_PAIRWISE_FLOOR = 0.6

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
    # Blast radius (§7) — its OWN group so the other group maxima stay stable and
    # the tuning table reads before/after cleanly. Discovered via the golden set:
    # the scorer modelled likelihood well and consequence barely.
    "blast_radius": {
        "dependents_high": 6.0,  # transitive_dependents >= 3
        "dependents_low": 3.0,  # transitive_dependents in 1..2
        "objective_theft": 6.0,  # objective credential_theft / ip_theft (dormant → phase 7)
        "objective_fraud": 4.0,  # objective payment_fraud (dormant → phase 7)
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
