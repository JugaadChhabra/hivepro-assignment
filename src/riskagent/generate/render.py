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
_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(brief: RiskBrief) -> str:
    return _ENV.get_template("report.html").render(brief=brief)


def render_markdown(brief: RiskBrief) -> str:
    return _ENV.get_template("report.md").render(brief=brief)
