# TawasolPay — Top 5 Cyber Risks

Ranked deterministically over all findings; the sentence explaining each rank is grounded LLM prose.
{% if brief.provenance.kev_staleness_warning %}

> ⚠ KEV feed is more than 7 days stale — actively-exploited status may be out of date.
{% endif %}
{% for e in brief.entries %}

## #{{ e.rank }} — {{ e.vulnerability_name }}

- **Assets:** {{ e.affected_assets | join(', ') }} · **Service:** {{ e.service_name }} ({{ e.service_owner }}, RTO {{ e.rto_hours }}h)
{% if e.multi_env_note %}
- _{{ e.multi_env_note }}._
{% endif %}
- **Evidence:** {{ e.cve }} · CVSS {{ '%g' | format(e.cvss) }} · {{ 'internet-facing' if e.internet_exposed else 'internal' }} · {{ 'exploit available' if e.exploit_available else 'no public exploit' }} · {{ 'no auth required' if not e.auth_required else 'auth required' }} · {{ e.days_open }} days open · EDR {{ 'absent' if not e.edr_installed else 'present' }}
- **Threat:** {{ e.threat_summary }}
- **Control:** {{ e.control_id }} {{ e.control_title }}{% if e.enhancements %}, particularly {{ e.enhancements | map(attribute='control_id') | join(', ') }}{% endif %} — {{ e.control_summary }}
{% for g in e.gap_controls %}
- **Also applies:** {{ g.control_id }} {{ g.title }} — {{ g.reason }}
{% endfor %}
- **Why this ranks #{{ e.rank }}:** {{ e.why_ranked }}{% if e.explanation_source == 'template' %} _(template)_{% endif %}
{% if e.data_flags %}
- **Flags:** {{ e.data_flags | join(', ') }}
{% endif %}
{% endfor %}

---
NIST catalog {{ brief.provenance.nist_catalog_version }} · index built {{ brief.provenance.index_built_at }} · NIST fetched {{ brief.provenance.nist_fetched_at }}{% if brief.provenance.kev_fetched_at %} · KEV fetched {{ brief.provenance.kev_fetched_at }}{% endif %} · generated {{ brief.provenance.generated_at }}
