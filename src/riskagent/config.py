"""Weights, thresholds, and fixed reference points for deterministic scoring.

The weights live here as a plain nested dict so ``eval.py`` can sweep them in
phase 6 (change one, re-measure). They are v0 — the report's stated factor
ordering, NOT tuned toward any desired answer.

Provenance: the five weight groups and their ordering come from the MDR report's
"Threat Intelligence Analyst Notes" ranking rubric in
``data/synthetic_threat_report.md`` (the "## Threat Intelligence Analyst Notes"
section, the five numbered factors on lines 79-83). That section is the scoring
rubric, not data, so it is encoded here rather than parsed:

  1. Internet exposure          -> exposure.internet_exposed         (line 79)
  2. Active exploitation         -> exploitability + maturity/KEV     (line 80)
  3. Ransomware association      -> adversary.ransomware              (line 81)
  4. Business criticality/scope  -> business (criticality, compliance) (line 82)
  5. Missing compensating controls -> control_gap (no_edr, ...)       (line 83)
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

# --- paths / cache (all gitignored; rebuilt on demand) ---
DATA_DIR = Path(__file__).resolve().parents[2] / "data"
REPORT_PATH = DATA_DIR / "synthetic_threat_report.md"  # MDR advisory (§3 report_parser)
CACHE_DIR = Path(__file__).resolve().parents[2] / "cache"
KEV_CACHE_PATH = CACHE_DIR / "kev.json"  # CISA KEV catalog cache (§3 kev.py)
TRACE_PATH = CACHE_DIR / "traces.jsonl"  # one JSONL record per pipeline run (§6 trace.py)
NIST_CACHE_PATH = CACHE_DIR / "nist_sp800-53r5.json"
CHROMA_DIR = CACHE_DIR / "chroma"
CHROMA_COLLECTION = "nist_800_53"

# --- CISA KEV catalog (§3, §7) — note the default branch is "develop", a main URL 404s ---
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/"
    "known_exploited_vulnerabilities.json"
)

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
# Current measured value: 0.800 (4/5 non-contested) after the phase-6b changes
# (rto_hours, recovery-infrastructure weighting). The one remaining unsatisfied
# non-contested pair, P03 (exposure vs internal-only active-ransomware), is a
# documented gap: closing it needs an "internal-only discounts a live campaign"
# signal that the phase-6b brief explicitly declined to add. NOT overfit away.
EVAL_PAIRWISE_FLOOR = 0.8

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

# Cloud object storage carrying a public access policy (phase 7, exposure_model_mismatch).
# Network-perimeter exposure is the wrong model for object storage: a public object
# policy is readable via the provider's own URL regardless of network path, so a
# perimeter scanner marks the asset internal-only for want of a route. When BOTH token
# sets hit (object storage AND a public/permissive policy) on an asset inventoried as
# internal-only, we raise exposure_model_mismatch and score exposure as reachable —
# WITHOUT mutating internet_exposed (both facts survive; third exposure source, same
# discipline as exposure_source_conflict). NARROW BY DESIGN: matches object storage with
# a public policy, not any misconfig / firewall / exposed admin interface. Fires on
# exactly one finding in this dataset (V-2071); asserted in tests.
OBJECT_STORAGE_TOKENS = frozenset({"bucket", "object storage", "blob storage"})
PUBLIC_POLICY_TOKENS = frozenset({"public", "overly permissive", "overly-permissive"})

# Recovery-of-last-resort services (phase 6b, constraints P04 + P09). blast_radius
# models FORWARD cascade via transitive_dependents; Backup and Recovery has ZERO
# dependents, so that signal scores it DOWN despite it being the fallback for every
# other incident (lose it and recoverable ransomware becomes catastrophic).
# DELIBERATE HARDCODE, made visible to the reviewer on purpose: the data carries no
# field to derive this from — the environment enum has a "DR" value but NO asset row
# uses it, and there is no is_recovery boolean. The only in-data evidence is the free
# text of business_impact ("Disaster recovery capability lost; data restoration
# impossible if primary fails"), which fuzzy text-matching would be less auditable
# than this explicit set. One entry today; add here if the data grows a DR service.
RECOVERY_SERVICES = frozenset({"Backup and Recovery"})

# Group maxima (documented; the additive terms are designed to sum to these):
# exposure 25, exploitability 22, adversary 25, business 25, control_gap 10.
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
        # rto_hours (phase 6b, constraint P11): the business stating in numbers how
        # much downtime it tolerates — stronger, harder evidence than the revenue
        # enum. Tiered, not linear: the gap between a 1h and a 12h RTO is the signal,
        # not the raw hours. Kept ALONGSIDE revenue_impact (distinct axes: revenue is
        # money-lost, rto is downtime-tolerated), so business group max is now 25.
        "rto_le_1h": 5.0,
        "rto_le_4h": 3.0,
        "rto_le_12h": 1.0,  # > 12h contributes 0
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
        # recovery-of-last-resort (phase 6b, P04/P09): equals dependents_high by
        # design — a recovery service is scored as top-tier fan-out regardless of its
        # (zero) forward dependents. See RECOVERY_SERVICES above.
        "recovery_infrastructure": 6.0,
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
