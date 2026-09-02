# TawasolPay Cyber Risk Assistant

Ranks TawasolPay's 114 open vulnerabilities into a defensible top-5 risk brief and
cites the NIST SP 800-53 control for each. Every number is traceable to its source;
the LLM writes the explanation sentence and nothing else — it never decides a rank,
a score, or which control applies.

**Live:** deployed as a Docker web service on Render. It serves the rendered brief
at `/`, with `/api/risks`, `/api/findings` (all 114, so you can verify nothing was
truncated before scoring), `/traces`, and `/healthz` (real provenance — catalog
version, fetch timestamps, and the LLM-vs-template split, not a bare `ok`).

## Architecture

Two data paths, kept deliberately separate — this split is the design, not decoration:

- **Structured** — anything with a join key, a closed enum, or a meaningful magnitude.
  Joined and filtered in code; scored by a deterministic, weighted rule set. *Never*
  embedded — embedding a CVSS score or an `internet_exposed` flag destroys the very
  ordering that makes it useful.
- **Semantic** — the NIST control catalog *only*: unbounded prose, no join key, where
  "Fortinet SSL-VPN unpatched, 42 days open" maps to SI-2's language by meaning, not
  by string match. This is the one thing in the vector store.

```
 data/*.csv  (assets, vulnerabilities, threat_intel, business_services,          data/synthetic_threat_report.md
             remediation_guidance)                                               (MDR advisory)
        │  STRUCTURED: join keys · closed enums · magnitudes                            │
        ▼                                                                               ▼
  join ─► intel_match ─► control_gaps ─► campaign objectives  ◄──────── report_parser (cross-check, no merge)
        │   (EXACT string equality on matched_cve_or_control — no fuzzy, no embeddings)
        ▼
  score ALL 114 findings  (deterministic; config.WEIGHTS)          CISA KEV  ──live fetch──►  kev_status
        │                                                          (listed / not_listed / unknown), rescore
        ▼
  select top-5  (dedupe identical vpn-edge / load-balancer pairs BEFORE the cut)
        │
        ├──────────────► retrieve NIST controls ◄── Chroma (NIST CONTROLS ONLY)
        │   SEMANTIC: vector LOOKUP against precomputed query vectors — no model at runtime
        ▼
  guard ─► Groq LLM writes PROSE ONLY ─► explanation_source: llm | template
        │   (rank, evidence, control already decided; a refusal degrades prose, not the ranking)
        ▼
  RiskBrief ─► HTML report  ·  /api/risks  ·  /api/findings (all 114)  ·  /healthz  ·  /traces

  ── BUILD TIME (docker build, model present) ─────────────────────────────────
  NIST catalog ──live fetch──► all-MiniLM-L6-v2 ──► Chroma index + per-finding
                                                    query-vector pack (shipped in image)
```

**Contamination invariant:** no CVSS score, no asset attribute, no vulnerability row
ever enters Chroma. `build()` accepts `ControlRecord` and nothing else
(`src/riskagent/rag/index.py`), and `peek()` exists to prove it.

## Supporting question 1 — the data split

**Structured** is everything with a join key, a closed enum, or a meaningful
magnitude: the asset inventory, the vulnerability rows, the intel feed, the service
map, the remediation guidance. Every query against these is a *filter* or a
*join* — `asset_id → asset`, `matched_cve_or_control → intel`,
`business_service → service`. Embedding any of it would be actively harmful: a CVSS
of 9.8 vs 4.3 is an ordering, and cosine distance over an embedded "9.8" throws that
ordering away. So the CSVs are loaded into typed Pydantic models and never touched by
the embedder.

**Embedded** is the NIST SP 800-53 catalog and nothing else. A control statement is
unbounded prose with no join key, and the link from a finding to its control is
semantic — "unpatched internet-facing service" *is* SI-2 / SC-7 even though those
strings never co-occur. That is exactly what an embedding model is for, and exactly
what a filter cannot do.

**The two ambiguous cases, and how I resolved them:**

- `remediation_guidance.csv` reads like prose but is keyed (by CVE / vuln type) and
  its values are actionable strings, not a semantic-search target. I treat it as
  **structured** — a lookup, not a corpus. Embedding it would have put non-NIST
  content in the vector store for no retrieval benefit.
- `threat_intelligence.summary` is free text and *tempting* to embed. I keep it
  **structured**: the intel-to-finding link is the exact `matched_cve_or_control`
  key, not a fuzzy summary match (see failure mode 2). The summary is shown as
  evidence and passed to the LLM as context, but it is never a retrieval key — that
  would reintroduce the fuzzy matching the dataset is built to punish.

## Supporting question 2 — three failure modes

Grounded in *this* data, each with the mitigation that exists in the code:

1. **KEV false-negatives on synthetic CVEs.** ~75% of the CVE-column values are
   synthetic (`CVE-SYN-*`, `K8S-SYN-*`, …) and absent from CISA KEV, so a naive
   "not in KEV ⇒ not exploited" would mislabel most of the estate as safe.
   → **Three-valued `kev_status`.** Only a *real* CVE confirmed absent from a
   successfully-fetched catalog is `not_listed`; a synthetic id is `unknown` (not
   checkable), never silently `false`. Coverage is reported, not assumed —
   **25.4% (29 of 114)** on this data, the expected band for ~20 real CVEs among
   mostly-synthetic ids. *`src/riskagent/ingest/kev.py` (`is_real_cve`, `apply_kev`).*
2. **Fuzzy intel matching inflating a score.** Normalising or fuzzy-matching
   `matched_cve_or_control` would attach a ransomware campaign to an unrelated
   finding and push it up the ranking — and the feed carries **16 deliberate noise
   records** engineered to catch exactly that.
   → **Exact string-equality join only** — no normalisation, no case-folding, no
   embeddings. Pinned by test: `assert matched_intel_count == 24` (and a lowercase
   `cve-2024-21762` decoy is asserted *not* to match).
   *`src/riskagent/pipeline/intel_match.py`; `tests/test_intel_match.py`.*
3. **A top risk sitting on a stale or unowned asset.** A high score on a box last
   seen 200 days ago, or with a blank `owner_team`, may point at a decommissioned
   host — and amplifying it would send responders somewhere that no longer exists.
   → **Staleness dampens, it never amplifies.** `stale_asset_record` / `no_owner`
   are raised as flags that contribute **+0 points** to the score and surface in the
   brief's `data_flags`, so the reviewer sees the caveat instead of the score hiding
   it. *`src/riskagent/pipeline/control_gaps.py` (tags); `src/riskagent/pipeline/score.py`
   (flag-only, zero points).*

## Supporting question 3 — one thing to change

**Add semantic intel matching as a second, clearly separated channel.** Today intel
attaches to a finding by exact `matched_cve_or_control` equality — which is precise
but blind to the intel record that describes *a technology you run* without naming a
CVE ("threat actor X targeting Citrix NetScaler in the Gulf financial sector").

The change is a **two-channel design, never merged**:

- **Confirmed** — exact-key matches, exactly as today. These feed the score.
- **Possible** — semantic matches (embed the intel summary, match against the
  finding's software/vendor/context) surfaced as *"possibly related activity"* with
  a similarity value, at **much lower weight**, in their own channel. They inform the
  analyst; they do not silently move the ranking.

The two are never averaged into one number, because that is precisely the fuzzy
matching the dataset is built to punish (16 noise records). **Precision was preferred
for v1** deliberately: an exact join that says "confirmed: 24, and here are 16
records I refused to match" is more defensible to a reviewer than a fuzzy matcher
that quietly inflates a score and cannot tell you why. The semantic channel is the
principled way to recover recall *without* spending that precision — a v2 addition
that stays honest by keeping the confirmed and possible signals visibly apart.

## Make commands

| Command | What it does |
|---|---|
| `make install` | `pip install -e ".[dev]"` |
| `make lint` | `ruff check .` + `mypy` (strict) |
| `make test` | fast gate — no network, no model download (`pytest -m "not network"`) |
| `make test-integration` | real NIST fetch + embeddings (`pytest -m network`) |
| `make run` | `uvicorn riskagent.app:app --host 0.0.0.0 --port 7860` |
| `make eval` | pairwise + precision@5, and the before/after blast-radius rates |
| `make eval-retrieval` | also computes retrieval recall@3 (network + model) |
| `make dump` | write all 114 scored findings to `scored_findings.csv` |

## Weights table

Deterministic, additive, and tunable in one place (`src/riskagent/config.py::WEIGHTS`)
so `eval.py` can sweep them. The five factor **groups and their ordering** come
directly from the MDR report's **"Threat Intelligence Analyst Notes"** ranking rubric
(`data/synthetic_threat_report.md`, the five numbered factors, lines 79–83) — that
section is the scoring rubric, so it is encoded, not parsed:

| # | Factor (report rubric) | Group | Max | Key terms |
|---|---|---|---|---|
| 1 | Internet exposure (line 79) | `exposure` | 25 | internet_exposed 18, production 7 |
| 2 | Active exploitation (line 80) | `exploitability` | 22 | cvss×8, exploit_available 8, no_auth 4, kev_listed 2 (+ maturity, max 5) |
| 3 | Ransomware association (line 81) | `adversary` | 25 | intel_match 8, ransomware 8, region/sector fit 2, recent 2 (+ maturity) |
| 4 | Business criticality / scope (line 82) | `business` | 25 | customer_facing 4, PCI/GDPR 4, revenue 4, RTO tiered 5/3/1 (+ criticality) |
| 5 | Missing compensating controls (line 83) | `control_gap` | 10 | no_edr 5, no_vendor_patch 3, days_open 2 |

**One group is *not* from the report rubric:** `blast_radius` (forward dependency
fan-out, recovery-of-last-resort, campaign objective) was **discovered through
evaluation** in phase 6/7 — the golden set showed the scorer modelled *likelihood*
well and *consequence* barely. It was added the disciplined way: propose from the
data, measure the before/after against the golden set, keep only if it earns its
place (see below). It lives in its own group so the report-derived maxima stay stable.

## Evaluation

Measured by `eval.py` against a golden set of pairwise judgements and a golden top-5,
recorded **before** the scorer's output was trusted. Current numbers:

| Metric | Value | Notes |
|---|---|---|
| **pairwise_satisfaction** (primary) | **0.800** (4/5 non-contested) | the CI regression floor (`EVAL_PAIRWISE_FLOOR`) |
| before blast-radius | 0.600 (3/5) | the "consequence was under-modelled" evidence |
| contested (reported, not gated) | 0.167 (6 pairs) | genuinely-arguable pairs, kept out of the headline |
| **precision@5** | **0.800** | 4 of 5 golden top-5 slots; the missing one is documented below |
| **retrieval_recall@3** | **0.955** | an acceptable control in the top-3 for ~96% of golden queries |

**Headline pairwise is a fraction, not a decimal** — the denominator (5 non-contested
pairs) is the honest sample size and belongs in view. The cross-phase arc is
**2/5 → 3/5 → 4/5** (phase-6 pre-blast-radius → post-blast-radius → phase-6b):

| Step | Change | Headline pairwise | Δ | What moved |
|------|--------|-------------------|---|------------|
| baseline | phase-6 as committed | **3/5** (0.600) | — | P03, P09 fail |
| Change 1 | `rto_hours` in Business group (P11) | **3/5** (0.600) | 0/5 | no flip; P11 +1.6→+5.6, tightens P03 −2.4→−0.4, P09 −4.0→−1.0 |
| Change 2 | recovery-infrastructure blast-radius term (P04/P09) | **4/5** (0.800) | **+1/5** | flips **P09** (−1.0→+5.0): DR site scored top-tier fan-out despite 0 dependents |
| Change 3 | staleness decision: keep §4, retire contested P10 | **4/5** (0.800) | 0/5 | resolves a §4-vs-golden contradiction; contested 7→6 pairs |

A 0/5 delta is not an inert change — on a 5-pair denominator a pair only registers
when it crosses zero margin; the margin column is where Change 1 shows its work.

**Why precision@5 is 0.800, not 1.000 — and why it dropped.** Through phase-6b,
precision@5 held at 5/5. In phase 7 the `exposure_model_mismatch` rule correctly
promoted the public backup bucket (V-2071 — reachable via the provider URL regardless
of network path) into the top-5, and it displaced Fortinet SSL-VPN RCE
(CVE-2024-21762), which the golden set ranks #2. That is **one golden slot traded on
purpose**: Fortinet is the estate-wide *initial-access pivot*, but the scorer models
business impact *per service*, so VPN-edge infrastructure (`customer_facing = No`, 0
dependents, no PCI/GDPR) is structurally under-weighted despite a VPN compromise being
the pivot to everything. The named remedy — an asset-role signal separating pivot
infrastructure from leaf services — is deliberately **not built**: adding it after
seeing the output would be tuning toward the benchmark. The number is pinned in
`tests/test_eval.py::test_precision_at_5_is_0_8_documented_pivot_gap` so any change
that moves it fires an alarm rather than silently editing the number.

**Remaining documented pairwise gap:** P03 (−0.4) — an internet-exposed finding with
no intel loses to an internal-only finding carrying an active-exploitation ransomware
campaign (+23 adversary). Closing it needs an "internal-only discounts a live
campaign" signal that the phase-6b scope explicitly declined to add. An honest 0.80
with one named gap, not an engineered 0.90.

**Caveat — one annotator, small denominator.** The golden set is a single
annotator's judgement, and the headline rests on **5 non-contested pairs**; each is
worth 0.2, so the metric is coarse and one re-judged pair swings it a full step.
Contested pairs were **not** promoted into the headline to widen the denominator —
doing so after seeing the scores would be selecting constraints to improve the
number, the exact failure the methodology exists to prevent.

## LLM smoke test — is the model actually contributing?

The page looks identical whether the LLM writes the prose or a template does, so the
system reports the split explicitly. `/healthz` returns `explanations_llm` and
`explanations_template` (of the 5 top risks), and `/api/risks` carries
`explanation_source: "llm" | "template"` per entry. **On the deployed service, with
the Groq key set, at least one entry reads `"llm"`** (measured: 4 of 5 grounded, 1
template). If all five come back `"template"`,
the Groq key or network is wrong and every explanation has silently degraded to a
scorer-reason template — the ranking is still correct (the LLM never touched it), but
the prose is not the model's. This split is surfaced on purpose so a reviewer sees the
system working as designed rather than quietly degraded.

## Data freshness

**KEV is fetched live at startup** and cached with a timestamp (`kev_fetched_at`) —
not a bundled static copy. A failed fetch falls back to the cached copy, and that
fallback is **not silent**: if the served KEV copy is more than 7 days old,
`kev_staleness_warning` flips true on `/healthz` and a banner renders in the brief.

**The NIST catalog is pinned at build time.** It is fetched live during `docker
build`, embedded into the Chroma index, and its version + SHA-256 are stamped into
the index and surfaced at `/healthz`. At runtime the deployed service reads the
*baked* catalog (so `nist_fetched_at` reflects the build), because the embedding
model is not present at runtime and a newer catalog could not be re-embedded — see
the deployment tradeoff below. This is a deliberate consequence of the model-free
runtime, not a freshness regression: the version and hash are always visible and a
redeploy re-fetches. (Locally, without the data pack, NIST is still fetched live at
startup and embedded on demand.)

Recency scoring uses a **fixed reference date** (`config.REFERENCE_DATE =
2026-04-24`, the freshest intel date) so scores are reproducible and don't drift as
the wall clock moves past this synthetic dataset.

**Ephemeral filesystem.** Render's disk is ephemeral, which is fine here: the Chroma
index and query pack live in the *image*, not in a runtime write. `cache/kev.json`
and `cache/traces.jsonl` are lost on every restart — acceptable by design, because
KEV re-fetches on startup and traces are per-run observability, not durable state.

## Intel-source contradiction detection

The report parser cross-checks the MDR advisory against `threat_intelligence.csv`
**without merging** — a disagreement between two intel sources is a finding, not a
value to average away. On real data WinterViper genuinely disagrees: the report says
"Ransomware: No", CSV `TI-3023` says Yes. The CSV wins (scoring already reads its
flag) and the disagreement is flagged `intel_ransomware_conflict` on the affected
finding (Kong, V-2024), visible in the brief rather than silently resolved.

## Observability

Every pipeline run appends one JSONL record to `/traces` (last N): the six input-file
SHA-256 hashes (a ranking is traceable to exact data bytes), the KEV join stats, the
NIST catalog version, and per top-5 risk the full score breakdown, the cited control,
and whether the explanation was grounded LLM prose or a template fallback.

## Running locally

```bash
make install
export GROQ_API_KEY=...   # optional; without it, explanations are templates
make test                 # fast gate
make eval                 # the numbers above
make run                  # http://localhost:7860
```

Or with Docker (mirrors the deployed image):

```bash
docker build -t tawasolpay-risk .
docker run -p 7860:7860 -e GROQ_API_KEY=$GROQ_API_KEY tawasolpay-risk
# Render sets $PORT; the image honours it and defaults to 7860 locally.
```

## Deployment (Render, Docker runtime)

Deployed as a Docker web service on Render's free tier (`render.yaml`).
`GROQ_API_KEY` is a Render **environment variable / secret**, injected at runtime —
never in the image, the repo, or the git history. A scheduled GitHub Action
(`.github/workflows/keep-alive.yml`) pings `/healthz` **every 10 minutes** to keep
the service warm and to fail loudly if `kev_staleness_warning` ever goes true.

**Why Render, not Hugging Face Spaces.** The original target was an HF Docker Space;
HF changed policy in 2026 to require a paid plan for Docker Spaces, so this moved to
Render's free tier. Two Render constraints drove real design, not just config:

**1. 512MB RAM — the model is removed from the runtime entirely.** `torch` +
`sentence-transformers` alone would blow the budget. But both the corpus (NIST
controls) and the query set are static and known at build time — at most 114
findings, each producing exactly one deterministic templated query. So `docker
build` embeds the catalog into Chroma **and** precomputes the query vector for every
finding (`src/riskagent/prewarm.py` → `src/riskagent/rag/pack.py`), and ships both in
the image. At runtime, retrieval is a vector **lookup** against those precomputed
vectors (`ChromaControlStore(embed_fn=...)`) — no `sentence-transformers`, no
`torch`, no model load. `sentence-transformers` is a build-time-only dependency (the
`build` extra in `pyproject.toml`), so the embedding pipeline is still real and
reproducible, not hardcoded output. **Measured RSS on the deployed image: ~101MB
under a 512MB cap (~20%).** Retrieval is byte-identical to the model path — the
precomputed vectors *are* the model's vectors, pinned by
`tests/test_rag_integration.py::test_precomputed_pack_retrieval_matches_model_exactly`
across all 114 findings, and recall@3 is unchanged at 0.955.

  *Honest tradeoff:* this makes the deployed system **batch-only over a fixed data
  pack**. A brand-new finding appearing at runtime would need a rebuild to get its
  query vector embedded. That is a deployment choice for a static-dataset assignment,
  not an architectural limit — the same code runs the live model locally (no pack).

**2. Spin-down.** Render free spins the service down after ~15 min idle (~1 min cold
start). The keep-alive workflow pings every 10 minutes to stay inside that window.
Note that GitHub's scheduled runners are best-effort and can be delayed past 15 min
under load, so an occasional cold start is still possible; an external pinger
(UptimeRobot free) is more reliable if it matters.
