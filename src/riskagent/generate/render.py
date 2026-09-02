"""Render the brief to HTML and Markdown (§6). Deterministic — no model calls.

Jinja only. The per-risk entry format matches §6: assets/service, an evidence
line that spells out exploit prerequisites (auth_required, exploit_available),
the matched threat campaign or "no active campaign matched", the cited control
with any matched enhancement ("particularly SI-2(5)"), the grounded explanation,
and data flags. A provenance footer and a KEV-staleness banner (phase 7) come
from the brief's provenance.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from riskagent.generate.assemble import RiskBrief

_TEMPLATES_DIR = Path(__file__).resolve().parents[3] / "templates"

# ── "Why it's a risk" grouping (display only) ────────────────────────────────
# The scorer emits one flat, point-weighted string per contributing factor (the
# audit trail). That is the wrong shape to *show* a reader: 18 atoms with "+N"
# suffixes read like a debug log. Here we bucket those same strings into four
# plain-English drivers and drop the arithmetic — no scoring logic is duplicated,
# reasons stay the single source of truth. Buckets follow the scorer's own
# dimension order (exposure / exploitability+adversary / business+blast / gap).
_BUCKETS = ("Exposure", "Threat activity", "Business impact", "Weak controls")

# substring -> bucket. First match wins; order matters (e.g. "no EDR" before the
# generic weak-control fallthrough). Anything unmatched is dropped, not shown.
_ROUTE: tuple[tuple[str, str], ...] = (
    ("internet-exposed", "Exposure"),
    ("object-storage policy", "Exposure"),
    ("production environment", "Exposure"),
    ("CVSS", "Threat activity"),
    ("public exploit", "Threat activity"),
    ("no authentication", "Threat activity"),
    ("CISA KEV", "Threat activity"),
    ("threat intel", "Threat activity"),
    ("ransomware", "Threat activity"),
    ("exploit maturity", "Threat activity"),
    ("region/sector", "Threat activity"),
    ("intel active", "Threat activity"),
    ("no EDR", "Weak controls"),
    ("no vendor patch", "Weak controls"),
    ("open ", "Weak controls"),
    ("criticality asset", "Business impact"),
    ("customer-facing", "Business impact"),
    ("compliance scope", "Business impact"),
    ("revenue impact", "Business impact"),
    ("RTO", "Business impact"),
    ("depend on this", "Business impact"),
    ("recovery-of-last-resort", "Business impact"),
    ("campaign objective", "Business impact"),
)

_OBJECTIVE_PHRASE = {
    "credential_theft": "credential-theft campaign",
    "ip_theft": "IP-theft campaign",
    "payment_fraud": "payment-fraud campaign",
}


def _phrase(reason: str) -> str:
    """Strip the '(+N)' arithmetic and rewrite the ugliest atoms into human phrases."""
    text = reason.split(" (+")[0].strip()
    if "object-storage policy" in text:
        return "internet-reachable (public storage policy)"
    if text == "internet-exposed":
        return "internet-facing"
    if text == "listed in CISA KEV":
        return "on CISA KEV list"
    if text == "exploit maturity Active Exploitation":
        return "actively exploited"
    if text == "matched threat intel":
        return "matched threat intel"
    if text == "region/sector fit":
        return "targets our region/sector"
    if text.startswith("intel active within"):
        return "recent adversary activity"
    if text == "ransomware-associated campaign":
        return "ransomware campaign"
    if text == "PCI/GDPR compliance scope":
        return "PCI/GDPR scope"
    if text.startswith("RTO "):
        return f"{text[4:]} recovery target"
    if text.endswith("criticality asset"):  # "High-criticality asset" -> lower lead
        return text[0].lower() + text[1:]
    if "depend on this" in text:  # "4 services depend on this" / "1 service(s) ..."
        n = int(text.split()[0])
        return f"{n} dependent service" + ("s" if n != 1 else "")
    if text.startswith("campaign objective "):
        return _OBJECTIVE_PHRASE.get(text[len("campaign objective ") :], text)
    return text


def _route(reason: str) -> str | None:
    if "flag only" in reason:  # staleness note contributes 0 — not a risk driver
        return None
    for needle, bucket in _ROUTE:
        if needle in reason:
            return bucket
    return None


def why_groups(reasons: list[str]) -> list[dict[str, object]]:
    """Bucket the scorer's flat reasons into plain-English drivers for display."""
    grouped: dict[str, list[str]] = {b: [] for b in _BUCKETS}
    for reason in reasons:
        bucket = _route(reason)
        if bucket is not None:
            grouped[bucket].append(_phrase(reason))
    return [{"label": b, "items": grouped[b]} for b in _BUCKETS if grouped[b]]


_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)
_ENV.globals["why_groups"] = why_groups


def render_html(brief: RiskBrief) -> str:
    return _ENV.get_template("report.html").render(brief=brief)


def render_markdown(brief: RiskBrief) -> str:
    return _ENV.get_template("report.md").render(brief=brief)
