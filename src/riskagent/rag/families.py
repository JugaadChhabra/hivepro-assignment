"""Map a finding to NIST control families, narrowing the semantic search (§5).

This is where the structured half constrains the semantic half. ``finding_type``
is derived by EXPLICIT keyword rules over ``affected_component``,
``vulnerability_name``, and ``control_gaps`` — the case-folded substring matching
here is deliberate classification, NOT the fuzzy intel matching the invariant
forbids (that invariant governs only ``matched_cve_or_control``).

FAMILY_HINTS covers all 22 finding types used by the golden set's retrieval
labels. The eight the reviewer marked ``family_hint_gap`` (AU, SC-for-encryption,
SI/SA-for-input-validation, and so on) are included with the families they
specified. The classifier emits only the subset its keyword rules can detect;
the rest are reachable by passing ``finding_type`` explicitly (as phase-6's
recall@3 harness does). ``retrieve`` raises on any type not listed here except
the explicit ``"unknown"`` fallback sentinel — so a classifier emitting an
unmapped type is a loud error, never a silent unfiltered search.
"""

from __future__ import annotations

from riskagent.models import EnrichedFinding

FAMILY_HINTS: dict[str, list[str]] = {
    "unpatched_software": ["SI", "RA"],
    "end_of_life_software": ["SA", "SI"],
    "exposed_admin_interface": ["AC", "SC", "CM"],
    "missing_edr": ["SI", "IR"],
    "excessive_privilege": ["AC"],
    "audit_logging_disabled": ["AU"],
    "missing_encryption_at_rest": ["SC"],
    "orphaned_asset": ["CM", "PM"],
    "backup_deficiency": ["CP"],
    "dr_not_tested": ["CP"],
    "authentication_bypass": ["IA", "AC"],
    "credential_reuse": ["IA", "AC"],
    "secrets_exposed": ["IA", "SC", "AU"],
    "public_storage_policy": ["AC", "SC"],
    "firewall_misconfiguration": ["SC", "AC", "CM"],
    "input_validation": ["SI", "SA"],
    "insecure_direct_object_reference": ["AC", "SI"],
    "session_management": ["AC", "IA"],
    "missing_rate_limiting": ["SC", "SI"],
    "certificate_expiry": ["SC"],
    "data_masking_absent": ["SI", "AC", "SC"],
    "container_misconfiguration": ["AC", "CM", "SC"],
}

# Canonical query phrase per finding_type — an honest description of the finding
# (never a NIST control's title), so the finding-type signal carries real weight
# in the embedding rather than being drowned by generic exposure/exploit tokens.
FINDING_TYPE_QUERY: dict[str, str] = {
    "unpatched_software": (
        "unpatched software with a known security flaw and no vendor patch applied"
    ),
    "end_of_life_software": (
        "end of life operating system past vendor end of support, "
        "no security patches will be issued"
    ),
    "exposed_admin_interface": (
        "administrative management interface exposed to an untrusted network"
    ),
    "missing_edr": (
        "host with no endpoint detection or anti-malware protection agent installed"
    ),
    "authentication_bypass": (
        "authentication can be bypassed, requests processed without a valid identity"
    ),
    "excessive_privilege": "account holds permissions far beyond what its function requires",
    "orphaned_asset": "production asset with no assigned owning team, absent from the inventory",
    "backup_deficiency": "backups are not protected, recovery copies could be lost or encrypted",
}

# Ordered most-specific first: the first matching rule wins, so end-of-life beats
# generic unpatched (an EOL box is also unpatched, but the EOL framing is stronger).
_END_OF_LIFE = (
    "end-of-life", "end of life", "eol", "unsupported", "obsolete",
    "legacy", "2008", "2012", "windows 7", "centos 6",
)
_ADMIN_IFACE = (
    "admin", "management interface", "management api", "console",
    "dashboard", "control panel", "management plane",
)
_AUTH_BYPASS = (
    "authentication bypass", "auth bypass", "weak auth", "default credential",
    "default password", "mfa", "session token", "credential",
)
_EXCESSIVE_PRIV = (
    "privilege escalation", "excessive privilege", "excessive permission",
    "over-privileged", "sudo", "rbac misconfig", "iam role",
)
_BACKUP = ("backup", "snapshot", "recovery point", "restore")
_UNPATCHED = (
    "unpatched", "remote code execution", " rce", "buffer overflow",
    "deserialization", "injection", "firmware", "heap", "cve-",
)


def _any(text: str, needles: tuple[str, ...]) -> bool:
    return any(n in text for n in needles)


def classify_finding_type(finding: EnrichedFinding) -> str:
    """Return one of FAMILY_HINTS' keys, or 'unknown' (which triggers fallback)."""
    vuln = finding.vulnerability
    text = f"{vuln.vulnerability_name} {vuln.affected_component}".lower()
    gaps = set(finding.control_gaps)

    if _any(text, _END_OF_LIFE):
        return "end_of_life_software"
    if _any(text, _ADMIN_IFACE):
        return "exposed_admin_interface"
    if _any(text, _AUTH_BYPASS):
        return "authentication_bypass"
    if _any(text, _EXCESSIVE_PRIV):
        return "excessive_privilege"
    if _any(text, _BACKUP):
        return "backup_deficiency"
    if _any(text, _UNPATCHED) or "no_vendor_patch" in gaps:
        return "unpatched_software"
    if "no_owner" in gaps or "stale_asset_record" in gaps:
        return "orphaned_asset"
    if "no_edr" in gaps:
        return "missing_edr"
    return "unknown"
