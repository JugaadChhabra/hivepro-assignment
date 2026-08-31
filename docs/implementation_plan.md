# TawasolPay Cyber Risk Assistant — Implementation Plan

Build target: a deployed service at a public URL that ingests the data pack, scores 114 findings deterministically, retrieves NIST SP 800-53 controls via RAG, and renders a top-5 risk brief with evidence.

Estimated effort: **12–15 hours** across 8 phases. Phases 1–5 produce a working system; 6–8 are what make it a strong submission.

---

## 0. Scope and non-goals

**In scope**
- Deterministic scoring over the full joined dataset, no truncation
- Exact-key threat intel matching with explicit noise handling
- NIST 800-53 retrieval via local embeddings
- LLM used only for the explanation sentence, over supplied evidence
- Golden-set evaluation of the ranking
- FastAPI service, public URL, public GitHub repo

**Explicitly out of scope (state this in the README)**
- Semantic matching of `threat_intelligence.summary` — designed, not shipped, see §11
- Auth, multi-tenancy, persistence, incremental re-ingest
- Any write path. Read-only, matching the JD's "agents start read-only" line

---

## 1. Repo layout

```
tawasolpay-risk/
├─ data/                          # the 6 provided files, committed
├─ cache/                         # kev.json, nist_sp800-53r5.csv, chroma/  (gitignored)
├─ src/riskagent/
│  ├─ models.py                   # pydantic contracts — the spine of the project
│  ├─ config.py                   # weights, model names, paths, thresholds
│  ├─ ingest/
│  │   ├─ csv_loader.py
│  │   ├─ report_parser.py
│  │   ├─ kev.py
│  │   └─ nist.py
│  ├─ pipeline/
│  │   ├─ join.py
│  │   ├─ intel_match.py
│  │   ├─ control_gaps.py
│  │   └─ score.py
│  ├─ rag/
│  │   ├─ index.py
│  │   ├─ families.py
│  │   └─ retrieve.py
│  ├─ generate/
│  │   ├─ select.py
│  │   ├─ llm.py
│  │   ├─ guard.py
│  │   └─ render.py
│  ├─ trace.py
│  └─ app.py
├─ tests/
│  ├─ test_join.py
│  ├─ test_intel_match.py
│  ├─ test_score.py
│  ├─ test_guard.py
│  └─ golden/golden_set.yaml
├─ templates/report.html
├─ eval.py
├─ Dockerfile
├─ pyproject.toml                 # ruff + mypy strict + pytest config
└─ README.md
```

Tooling from commit one: `ruff`, `mypy --strict`, `pytest`, GitHub Actions running all three. The JD says conventions are enforced rather than suggested — a green CI badge answers that without a paragraph.

---

## 2. Data contracts (`models.py`)

Write these first. Every module downstream consumes and returns these types, so the pipeline is typed end to end and `mypy --strict` catches wiring errors before runtime.

```python
class Asset(BaseModel):
    asset_id: str
    asset_name: str
    asset_type: str
    environment: Literal["Production", "Staging", "Development", "DR"]
    owner_team: str | None          # one row is blank — model it, don't crash on it
    business_service: str
    internet_exposed: bool
    criticality: Literal["Critical", "High", "Medium", "Low"]
    data_classification: str
    edr_installed: bool
    last_seen_days: int
    location: str
    vendor_product: str

class Vulnerability(BaseModel):
    vuln_id: str
    asset_id: str
    vulnerability_name: str
    cve: str                        # NOT always a real CVE — see §4
    severity: str
    cvss: float
    exploit_available: bool
    patch_available: bool
    days_open: int
    asset_exposure: str
    auth_required: bool
    status: str
    affected_component: str

class IntelRecord(BaseModel):
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

class ScoreBreakdown(BaseModel):
    exposure: float
    exploitability: float
    adversary: float
    business: float
    control_gap: float
    total: float
    reasons: list[str]              # one human string per contributing factor

class EnrichedFinding(BaseModel):
    vulnerability: Vulnerability
    asset: Asset
    service: BusinessService
    intel: list[IntelRecord]        # empty list is a valid, common state
    kev: KevEntry | None
    kev_status: Literal["listed", "not_listed", "unknown"]
    control_gaps: list[str]
    data_flags: list[str]           # staleness, no owner, exposure disagreement
    score: ScoreBreakdown | None
```

**Two contract decisions worth defending in the README:**

`kev_status` is three-valued, not boolean. Roughly 20 of 79 distinct IDs in `vulnerabilities.csv` are real CVEs; the rest are synthetic (`CVE-SYN-*`, `CTRL-SYN-*`, `K8S-SYN-*`, `CICD-SYN-*`, `CLOUD-SYN-*`). A boolean would silently record 59 IDs as "not actively exploited" when the truth is "not checkable." This is the exact failure mode the assignment names in supporting question 2.

`intel: list[...]` not `intel: IntelRecord | None`. A CVE can carry multiple intel records, and a scorer that takes the first one loses the ransomware signal when it arrives second.

---

## 3. Ingest

### `csv_loader.py`
Parse all five CSVs into the pydantic models. Coerce `Yes`/`No` to bool, dates to `date`, empty strings to `None`. Fail loudly on schema drift rather than defaulting.

Assertions: 60 assets, 114 vulnerabilities, 40 intel, 20 services, 30 guidance rows. Not busywork — if a row count moves, something upstream changed and everything below is suspect.

### `report_parser.py`
The MDR report is two documents in one file.

Sections 1–5 are structured records in prose clothing. Regex each `### N. Actor — "Campaign"` block into:

```python
class Campaign(BaseModel):
    actor: str
    campaign_name: str
    target_profile: str
    cve_chain: list[str]
    ransomware: bool
    confidence: str
    iocs: str
```

The "Threat Intelligence Analyst Notes" section is not data — it is the scoring rubric. Its five ranked factors become the weight groups in `config.py`. Encode it as a constant with a comment pointing back at the source line; do not parse it.

**Cross-check, don't merge.** Both the report and `threat_intelligence.csv` claim CrimsonJackal exploits CVE-2024-21762. Assert agreement; on mismatch, append to `data_flags` and prefer the CSV. Disagreement between two intel sources is a finding, not a merge conflict.

### `kev.py`
Fetch the KEV catalog from `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json` (note: default branch is `develop`, not `main` — a `main` URL 404s). Cache to `cache/kev.json` **alongside a `kev_fetched_at` timestamp**. Join on `cveID`. Emit `kev_lookups`, `kev_hits`, `kev_coverage_pct` into the trace. Expected coverage is roughly 25%; if it reads 100% or 0%, the join is broken.

**Staleness must be visible, not just cached.** If the live fetch fails and the app falls back to the cached copy, check the cache's age. If it's older than 7 days, set `kev_staleness_warning: true` and surface it as a banner in the rendered report and in `/healthz`. A security tool that silently serves a week-old exploit feed without saying so is itself a finding. Cache fallback is fine; *silent* cache fallback is not.

### `nist.py`
Download the SP 800-53 Rev 5 control catalog CSV from `https://csrc.nist.gov/CSRC/media/Projects/risk-management/800-53%20Downloads/800-53r5/NIST_SP-800-53_rev5_catalog_load.csv`. Cache it with a `nist_fetched_at` timestamp. Parse into one record per control: `control_id`, `family` (the alpha prefix), `title`, `statement`, `discussion`, `related_controls`. Capture the catalog's version string (currently Rev 5.1) as `nist_catalog_version` and carry it through to the index metadata and the rendered footer — this document changes rarely, but the provenance should still be checkable rather than assumed.

---

## 4. Structured pipeline (green path)

### `join.py`
```python
def join(assets, vulns, services) -> list[JoinedFinding]
```
`vulnerabilities` LEFT JOIN `assets` on `asset_id`, then LEFT JOIN `business_services` on `business_service`.

Both joins are total in this dataset — verified, zero orphans on either side — so assert it. An orphan means a data problem, and silently dropping it would remove a finding from the ranking without anyone noticing.

Also reconcile the two exposure columns. `vulnerabilities.asset_exposure` and `assets.internet_exposed` both encode exposure. Where they disagree, append `"exposure_source_conflict"` to `data_flags` and take the asset inventory as authoritative. Do not silently pick one.

### `intel_match.py`
```python
def match(findings, intel) -> list[JoinedFinding]   # populates .intel
```
Build `dict[str, list[IntelRecord]]` keyed on `matched_cve_or_control`. Exact string equality against `finding.vulnerability.cve`. No normalisation, no fuzzy matching, no embeddings.

The dataset is constructed so 24 of 40 records match a CVE in the vuln list and 16 do not. The noise is deliberately plausible: real CVEs for products TawasolPay doesn't run (Palo Alto CVE-2024-3400, Ivanti CVE-2025-0282, MOVEit CVE-2023-34362) plus non-CVE keys (`PHISH-SYN-001`, `INSIDER-SYN-001`, `CRED-SYN-001`).

Two assertions, both regression tests:
```python
assert matched_intel_count == 24
assert unmatched_intel_count == 16
```

Relevance weighting on top of the match: `target_region` and `target_sector` fit (only 11 of 40 records are Middle East), `confidence`, and recency from `active_last_seen`. A Global/Healthcare record hitting your CVE is weaker evidence than a Middle East/Financial Services one.

### `control_gaps.py`
Derives the "missing compensating controls" signal, which is factor 5 in the report's rubric and does not exist as a single column:

- `edr_installed == False` → `"no_edr"` (26 of 60 assets)
- `auth_required == False` → `"unauthenticated_exploit_path"`
- `patch_available == False` → `"no_vendor_patch"`
- `last_seen_days > 30` → `"stale_asset_record"`
- `owner_team is None` → `"no_owner"`
- the 13 `CTRL-SYN-*` rows are control failures, not software flaws — tag them `"control_deficiency"` so remediation routing differs

### `score.py`
```python
def score(finding: EnrichedFinding) -> ScoreBreakdown
```
Pure function. No I/O, no model calls, no globals. Every branch appends a human-readable string to `reasons`, which is what the LLM later turns into prose.

Weights live in `config.py` as a dict so `eval.py` can sweep them.

| Group | Signal | Points |
|---|---|---|
| **Exposure** (max 25) | `internet_exposed` | +18 |
| | `environment == Production` | +7 |
| **Exploitability** (max 22) | `cvss / 10 * 8` | 0–8 |
| | `exploit_available` | +8 |
| | `auth_required == False` | +4 |
| | `kev_status == "listed"` | +2 |
| **Adversary** (max 25) | exact intel match present | +8 |
| | `ransomware_association` | +8 |
| | `exploit_maturity == "Weaponized"` | +5 (PoC +2) |
| | region or sector fit | +2 |
| | `active_last_seen` within 30 days | +2 |
| **Business** (max 20) | `criticality` | Critical +8, High +5, Medium +2 |
| | `customer_facing` | +4 |
| | `compliance_scope` ∈ {PCI DSS, GDPR} | +4 |
| | `revenue_impact == High` | +4 |
| **Control gap** (max 10) | `no_edr` | +5 |
| | `no_vendor_patch` | +3 |
| | `days_open > 30` | +2 |

Additive, so every contribution stays inspectable and the total is reconstructable by hand.

Three design points to defend:

1. **Ordering matches the report's rubric.** Exposure and exploitability outweigh raw CVSS by design. A CVSS 9.8 on an internal dev box scores ~15; a CVSS 8.1 on an internet-facing PCI-scoped payment gateway with a live ransomware campaign scores ~75. That is the assignment's worked example, satisfied by construction.
2. **Staleness dampens, it does not amplify.** `last_seen_days > 30` adds nothing to the score. It sets a flag that surfaces in the output. A finding on a machine that may be decommissioned should not climb the list.
3. **These weights are v0.** They come from the report's stated ordering, not from tuning toward a desired answer. Phase 6 tunes them against the golden set, and the README says so.

---

## 5. RAG (purple path)

### `index.py`
- Chunk **one control per chunk** — the document's own boundary, and it makes `control_id` the citation. Never fixed token windows: they'd sever SI-2's statement from its discussion and produce uncitable fragments.
- Embed with `sentence-transformers/all-MiniLM-L6-v2` — local, CPU, 384-dim, ~80MB, no API key, satisfies the free-tier constraint. Keep it behind an interface so swapping to `BAAI/bge-small-en-v1.5` is a config change.
- Chunk text: `f"{control_id} {title}\n{statement}"`. Discussion is stored as metadata and shown in output but not embedded — it's long, generic, and dilutes the vector.
- Metadata per chunk: `{"control_id", "family", "title"}`.
- Persist to `cache/chroma/`. **Bake the built index into the Docker image** so the deployed service has no cold-start embedding pass.
- Write `nist_catalog_version` and `index_built_at` into the Chroma collection metadata at build time, so "was this index built from the current catalog" is a one-line lookup rather than an assumption.

### `families.py`
Metadata pre-filter map. This is where the structured half narrows the search space for the semantic half.

```python
FAMILY_HINTS: dict[str, list[str]] = {
    "unpatched_software":    ["SI", "RA"],
    "end_of_life_software":  ["SA", "SI"],
    "exposed_admin_iface":   ["AC", "SC"],
    "missing_edr":           ["SI", "AU"],
    "weak_auth":             ["IA", "AC"],
    "excessive_privilege":   ["AC"],
    "orphaned_asset":        ["CM", "PM"],
    "backup_deficiency":     ["CP"],
}
```

`finding_type` is derived from `affected_component`, `vulnerability_name`, and `control_gaps` by explicit keyword rules — the same deterministic classification used for the fuzzy join against `remediation_guidance.csv`. Thirty guidance rows is small enough to hand-verify all thirty.

### `retrieve.py`
```python
def retrieve(finding: EnrichedFinding, k: int = 3) -> list[ControlChunk]
```
Query text is **templated from structured fields, never raw free text**:

> `"{finding_type}. {affected_component}. {'internet-facing' if exposed}. {'weaponised exploit available' if ...}. {control gaps}."`

Filter to `FAMILY_HINTS[finding_type]`, retrieve top-3. If the best hit's distance exceeds a threshold, retry unfiltered and flag `"family_filter_fallback"` — over-constraining is the one way this makes things worse, so it needs an escape hatch.

**Ship dense-only.** Measure recall@3 in Phase 6 against ~20 hand-labelled risk→control pairs. If below 0.8, add `rank_bm25` and fuse with reciprocal rank fusion (k=60). RRF uses rank positions rather than scores, so there's no scale-normalisation problem between cosine similarity and BM25. Five lines. Do not build it speculatively; the README should say it was measured, not guessed.

---

## 6. Generate + serve (cyan path)

### `select.py`
Sort by `score.total`, then **dedupe before truncating**. Without this, four of the top five are two CVEs counted twice: `vpn-edge-01/02` carry identical Fortinet findings and `load-balancer-prod-01/02` carry identical CitrixBleed findings.

Group on `(cve, vulnerability_name)`, collapse to one entry with `affected_assets: list[str]`, keep the highest score. Optional secondary cap of two findings per business service so the brief isn't entirely Remote Access.

### `llm.py`
Provider: Groq free tier, `llama-3.3-70b-versatile`. Temperature 0. Five calls, one per risk, run concurrently.

The prompt carries only:
- the enriched record as an explicit key–value evidence block
- `score.reasons` — the factor list the scorer already produced
- the retrieved control text, verbatim

Instructions: two sentences explaining the rank position; reference only facts present in the evidence block; if `intel` is empty, say no active campaign was matched rather than inferring one. Return JSON with `why_ranked`, `control_id`, `control_summary`.

The model decides nothing. Rank, evidence, and control are all already determined.

### `guard.py`
This is what turns "the LLM might hallucinate" into an actual control.

```python
def validate(output: LlmOutput, finding: EnrichedFinding,
             retrieved: list[ControlChunk]) -> GuardResult
```
- `output.control_id` must be in `{c.control_id for c in retrieved}`
- every CVE-shaped token in `why_ranked` must appear in the evidence block
- every numeric token must appear in the evidence block
- no threat-actor name may appear if `finding.intel` is empty

On failure: retry once with the violation appended to the prompt. On second failure: fall back to a template-generated sentence built from `score.reasons`, tagged `explanation_source: "template"` in the output and the trace. Never silently ship an ungrounded sentence.

### `render.py`
Jinja to HTML and Markdown. Fully deterministic, no model calls. Per risk:

> **#1 — Fortinet SSL-VPN Heap Buffer Overflow RCE**
> Assets: vpn-edge-01, vpn-edge-02 · Service: Remote Access (owner, RTO)
> Evidence: CVE-2024-21762 · CVSS 9.8 · internet-facing · exploit available · 42 days open · EDR absent
> Threat: CrimsonJackal "Gateway Breaker" — LockBit 3.0, high confidence, UAE targeting
> Control: SI-2 Flaw Remediation — *[retrieved summary]*
> Why this ranks #1: *[LLM sentence]*
> Flags: *[data_flags, if any]*

Not JSON, not a CVSS table. What a technical manager pastes into a Slack thread.

### `app.py`
FastAPI. Pipeline runs once at startup and caches, so page loads are instant.

| Route | Returns |
|---|---|
| `GET /` | rendered HTML brief, with a provenance footer (`kev_fetched_at`, `nist_catalog_version`, `index_built_at`) and a staleness banner if `kev_staleness_warning` is set |
| `GET /api/risks` | full JSON with score breakdowns |
| `GET /api/findings` | all 114 scored, for auditing the ranking |
| `GET /traces` | last N run traces |
| `GET /healthz` | `{status, kev_fetched_at, kev_coverage_pct, kev_staleness_warning, nist_catalog_version, index_built_at}` — not just liveness |

`/api/findings` matters: it lets a reviewer verify you scored everything and didn't retrieve-then-rank. `/healthz` returning real fetch timestamps rather than a bare `{"status": "ok"}` is what proves retrieval is live rather than hardcoded, and doubles as the target for the keep-alive ping in §8.

### `trace.py`
JSONL per run: input file hashes, per-risk score breakdown, retrieval hits with distances and whether the family filter fell back, prompt, raw completion, guard result, latency, token count. The JD names observability three times.

**Degradation path:** if Groq is unreachable, the system still renders a top-5 with retrieved NIST controls and template sentences. Only the prose degrades, because only the prose was ever the model's job. Say this in the README — it falls out of the architecture rather than being bolted on.

---

## 7. Evaluation

### `tests/golden/golden_set.yaml`
Roughly 90 minutes of hand work against the 114 joined records. Two artefacts:

**Pairwise constraints (~15).** Honest confidence about "A outranks B" is achievable where a full ordering isn't:
```yaml
- higher: {cve: CVE-2024-21762, asset: vpn-edge-01}
  lower:  {cve: CVE-2024-23897, asset: jenkins-staging-01}
  reason: internet-facing + active ransomware campaign vs internal non-prod
```
The assignment hands you one of these for free — the CVSS 10 internal dev server versus the CVSS 8 exposed payment gateway. Most candidates read that as prose. Encode it as an assertion.

**Golden top-5**, hand-ranked with a written justification each.

### `eval.py`
Prints three numbers:
- **pairwise satisfaction rate** — primary metric
- **precision@5** against the golden top-5
- **retrieval recall@3** against ~20 hand-labelled risk→control pairs

Skip NDCG. Overkill at this size and harder to explain to a reviewer.

Wire `eval.py` into CI as a regression gate. When KEV enrichment lands in Phase 5, you find out that afternoon whether it broke the ordering.

README caveat, stated plainly: one annotator, so this is calibrated judgement rather than consensus ground truth. That's more credible than overclaiming.

---

## 8. Build order

| Phase | Work | Hours | Done when |
|---|---|---|---|
| **1** | `models.py`, `csv_loader.py`, repo skeleton, CI green | 2 | All five CSVs load into typed models, row-count assertions pass |
| **2** | `join.py`, `intel_match.py`, `control_gaps.py` + tests | 2 | 24/16 intel assertion passes, zero join orphans |
| **3** | `score.py` + `test_score.py` with the 4 hand-built cases | 2 | Internal-CVSS-10 ranks below exposed-CVSS-8 |
| **4** | `nist.py`, `index.py`, `retrieve.py` | 2.5 | Query for a Fortinet finding returns SI-2 in top 3 |
| **5** | `select.py`, `llm.py`, `guard.py`, `render.py`, `app.py` | 2.5 | Local server renders a readable top-5 |
| **6** | Golden set + `eval.py`, tune weights | 2 | Metrics printed, weights justified by measurement |
| **7** | `report_parser.py`, `kev.py`, `trace.py` | 1.5 | Campaign cross-check runs, KEV coverage logged |
| **8** | Dockerfile, deploy to HF Spaces, keep-alive, README | 1.5 | Public URL live, three README answers written |

**Phases 1–5 produce a working system.** If time collapses, stop after 5 and write the README honestly. Phases 6–8 are what separate this from a working notebook — do not skip 6.

**Deploy to Hugging Face Spaces, Docker SDK, not Render.** Decided, not left open:

- Render's free web service spins down after 15 minutes of no traffic and takes 30–60s to wake. A reviewer opening the link days after submission gets a blank page and may assume it's broken.
- HF Spaces on free CPU pause after 48 hours of inactivity — far more forgiving — and a lightweight keep-alive (below) keeps it from ever sleeping during the review window.
- Render's free tier has an **ephemeral filesystem**: local changes are lost on every spin-down/restart. The baked-in Chroma index and cached KEV/NIST files would be wiped on every wake, forcing a rebuild-on-cold-start that the plan is specifically designed to avoid.
- HF free CPU gives 2 vCPU / 16GB RAM against Render's 512MB — comfortable headroom for `sentence-transformers` + torch + Chroma.

Concretely: Space SDK = `docker`, `app_port: 7860` in the Space README frontmatter, index built during `docker build` and shipped inside the image, `GROQ_API_KEY` set as a Space secret, never committed — the JD names careless credential handling as the one thing they don't tolerate.

Add `.github/workflows/keep-alive.yml`: a scheduled job hitting `GET /healthz` every 12 hours. This also means the keep-alive ping doubles as a freshness monitor — if `kev_staleness_warning` ever flips true, it's visible in the workflow logs, not just on the page.

---

## 9. README skeleton

**Supporting question 1 — the data split.** Structured: everything with a join key, a closed enum, or a meaningful magnitude. Every query against the CSVs is a filter, and embedding a CVSS score destroys the ordering that makes it useful. Embedded: the NIST catalog only — unbounded prose, no join key, and the gap between "Fortinet VPN unpatched, 42 days open" and SI-2's language is semantic, not lexical. Name the ambiguous cases (`remediation_guidance.csv`, `threat_intelligence.summary`) and say how you resolved them.

**Supporting question 2 — three failure modes.** Use ones grounded in this data, not generic ones:
1. ~75% of the CVE IDs are synthetic and absent from KEV, so KEV-derived "actively exploited" flags are false-negative for most of the estate. → three-valued `kev_status`, coverage percentage in the trace.
2. Fuzzy or normalised intel matching could attach a ransomware campaign to an unrelated finding and inflate its score. → exact-key join only, `assert matched == 24`.
3. Stale `last_seen_days` or missing owner means a top risk may sit on a decommissioned box. → staleness dampens rather than amplifies, and surfaces as a flag.

**Supporting question 3 — one thing to change.** Semantic intel matching as a second, clearly separated channel: exact matches → `intel_match: confirmed`, feeding the score; semantic matches → `intel_match: possible` with a similarity value, shown as "possibly related activity" at much lower weight. Never merged. This closes the gap where an intel record describes a technology you run without naming a CVE — while preserving the precision that exact matching buys.

Also include: architecture diagram, `make run` / `make eval` commands, the weights table with its provenance in the MDR analyst notes, current eval numbers, and a one-line note on data freshness — KEV is fetched live and cached with a visible staleness check, NIST is fetched live and its catalog version is stamped into the index, and both are checkable at `/healthz`.
