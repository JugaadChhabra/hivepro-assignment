"""Parse the MDR advisory's five campaign blocks into typed ``Campaign`` records (§3).

Sections 1-5 of the report are structured records in prose clothing:
``### N. Actor — "Campaign"`` followed by labelled lines and a prose paragraph.
We regex them into ``Campaign`` records.

``objective`` is the consequence signal that activates the dormant blast-radius
term wired in phase 6. It is derived from the block's PROSE via ordered keyword
rules, NEVER from the actor name — the classifier is handed the block with its
header line (which carries the actor) stripped, so renaming an actor cannot move
the objective. The rule order matters and encodes real precedence:

  payment_fraud       > ip_theft > ransomware(primary) > credential_theft
  (intercept payment)   (source     (**Ransomware:**      (build secrets,
                         code /       Yes, and not          private keys,
                         supply       already claimed        credentials)
                         chain)       above)

This ordering is what makes RedMantis resolve to ip_theft despite carrying
ransomware (its prose leads with source-code/supply-chain theft, ransomware is
secondary), and IronVeil to ransomware_deployment despite the word "credentials"
appearing (it has no source-code/supply-chain signal and IS primary ransomware).

The "Threat Intelligence Analyst Notes" section is NOT parsed — it is the scoring
rubric, encoded as weights in ``config.py`` with a source citation there.
"""

from __future__ import annotations

import re
from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

Objective = Literal[
    "ransomware_deployment",
    "credential_theft",
    "ip_theft",
    "payment_fraud",
    "espionage",
    "unknown",
]

_OBJECTIVES: frozenset[str] = frozenset(get_args(Objective))

# One campaign block: "### 1. CrimsonJackal — "Gateway Breaker"" ... up to the next
# "### " heading or the "## Threat Intelligence Analyst Notes" section.
_BLOCK_RE = re.compile(
    r'^###\s+\d+\.\s+(?P<actor>.+?)\s+[—-]\s+"(?P<campaign>.+?)"\s*$(?P<body>.*?)'
    r"(?=^###\s+\d+\.|^##\s+Threat Intelligence Analyst Notes|\Z)",
    re.MULTILINE | re.DOTALL,
)
_FIELD_RE = re.compile(r"^\*\*(?P<key>[^:*]+):\*\*\s*(?P<val>.+?)\s*$", re.MULTILINE)
# an id token in the exploit chain: CVE-2024-21762, CVE-SYN-2026-0004, CICD-SYN-001, ...
_ID_RE = re.compile(r"\b[A-Z0-9]+(?:-[A-Z0-9]+)*-\d+\b")


class Campaign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str
    campaign_name: str
    target_profile: str
    cve_chain: list[str]
    ransomware: bool
    confidence: str
    iocs: str
    objective: Objective


def _classify_objective(prose: str, *, ransomware: bool) -> Objective:
    """Objective from block PROSE (header/actor already stripped) + the parsed
    ransomware bool. Ordered, most-specific-consequence first."""
    t = prose.lower()
    if "payment" in t or "financial fraud" in t or "fraudulent" in t:
        return "payment_fraud"
    if "source code" in t or "supply chain" in t:
        return "ip_theft"
    if ransomware:  # primary ransomware — reached only when no theft signal preceded it
        return "ransomware_deployment"
    if any(k in t for k in ("credential", "build secret", "private key")):
        return "credential_theft"
    return "unknown"


def _parse_block(actor: str, campaign: str, body: str) -> Campaign:
    fields = {
        m.group("key").strip().lower(): m.group("val").strip() for m in _FIELD_RE.finditer(body)
    }
    # explicit presence check: a missing Ransomware line must NOT silently become False
    # (that would flip the objective classifier and the cross-check). Fail loudly on drift.
    if "ransomware" not in fields:
        raise ValueError(f"campaign {actor!r} has no **Ransomware:** line")
    ransomware = fields["ransomware"].lower().startswith("yes")
    chain_line = fields.get("exploit chain", "")
    cve_chain = _ID_RE.findall(chain_line)
    # confidence field is "High — confirmed victim..."; keep the leading grade only
    confidence = re.split(r"\s[—-]\s", fields.get("confidence", ""), maxsplit=1)[0].strip()
    # prose = body with the labelled lines removed, so classification sees narrative only
    prose = _FIELD_RE.sub("", body)
    return Campaign(
        actor=actor,
        campaign_name=campaign,
        target_profile=fields.get("target profile", ""),
        cve_chain=cve_chain,
        ransomware=ransomware,
        confidence=confidence,
        iocs=fields.get("iocs", ""),
        objective=_classify_objective(prose, ransomware=ransomware),
    )


def parse_report(text: str, *, expected: int = 5) -> list[Campaign]:
    """Parse all campaign blocks. Asserts exactly ``expected`` (5) — a count change
    means the report format drifted and everything downstream is suspect."""
    campaigns = [
        _parse_block(m.group("actor").strip(), m.group("campaign").strip(), m.group("body"))
        for m in _BLOCK_RE.finditer(text)
    ]
    if len(campaigns) != expected:
        raise ValueError(f"expected {expected} campaigns, parsed {len(campaigns)}")
    for c in campaigns:
        if not c.cve_chain:
            raise ValueError(f"campaign {c.actor!r} parsed no cve_chain")
        assert c.objective in _OBJECTIVES  # Literal guarantees this; belt-and-suspenders
    return campaigns
