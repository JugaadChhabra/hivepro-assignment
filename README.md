# TawasolPay Cyber Risk Assistant

Ranks TawasolPay's 114 open vulnerability findings into a top-5 risk brief and cites the NIST
SP 800-53 control for each. The ranking is deterministic: a weighted rule set decides order,
score, and control. The LLM only writes the one sentence that explains a rank — and a guard
rejects anything it can't find in the evidence, so if the model is unreachable the brief still
renders from templates.

**[Live brief](https://tawasolpay-risk.onrender.com/) · [API docs](https://tawasolpay-risk.onrender.com/docs) · [Repo](https://github.com/JugaadChhabra/hivepro-assignment)**

## How it works

The CSVs load into typed models and join on their keys. Threat intel attaches by **exact
string equality** on `matched_cve_or_control` — no fuzzy match. CISA KEV is fetched live and
sets a three-valued `kev_status`. All 114 findings are scored by `config.WEIGHTS`, deduped,
and the top 5 selected. Only then does the system retrieve NIST controls from a Chroma vector
store and call the LLM five times for prose. A grounding guard validates each sentence, retries
once on a violation, then falls to a template.

![Architecture](docs/architecture.png)

*All 114 findings are scored and their controls retrieved **before** the top-5 are cut and the
LLM is called. The diagram is not streaming — the model writes captions for a decision already
made.*

## Sample output

Risk #1, copied from a live run (the prose sentence is LLM-written and varies; rank, evidence,
and control are deterministic):

```markdown
## #1 — Citrix ADC Session Token Leak (CitrixBleed)

- **Assets:** load-balancer-prod-01, load-balancer-prod-02 · **Service:** Customer Login (Chief Digital Officer, RTO 1h)
- **Evidence:** CVE-2023-4966 · CVSS 9.4 · internet-facing · exploit available · no auth required · 180 days open · EDR absent
- **Threat:** IronVeil "CitrixBleed Exploitation" — ransomware, High confidence, Global
- **Control:** SI-4 Device Identification and Authentication, particularly IA-3(2), IA-3(1) — The system must monitor for attacks and unauthorized connections, analyze detected events, and adjust monitoring based on changes in risk.
- **Also applies:** SI-3 Malicious Code Protection — no EDR installed on this host
- **Why this ranks #1:** The internet-facing production load balancers are vulnerable to an unauthenticated exploit with CVSS 9.4 that IronVeil is actively exploiting in a ransomware campaign. Absent EDR and a 1-hour-RTO customer login service push the score to 106.52.
```

| # | CVE | Finding | Service | Score |
|---|-----|---------|---------|------:|
| 1 | CVE-2023-4966 | Citrix ADC Session Token Leak (CitrixBleed) | Customer Login | 106.52 |
| 2 | CVE-SYN-2026-0010 | Payment API Insecure Direct Object Reference | Payment Processing | 97.28 |
| 3 | CVE-SYN-2026-0011 | Kong Gateway Admin API Exposed | Partner API Gateway | 96.44 |
| 4 | CLOUD-SYN-001 | Storage Bucket Public Policy Misconfiguration | Backup and Recovery | 95.28 |
| 5 | CVE-SYN-2026-0001 | Remote Code Execution in Web Framework | Customer Login | 92.84 |

The assignment asks each risk to surface five things. In the brief: **asset** → `Assets:`;
**vulnerability** → heading + `Evidence:`; **matched intel** → `Threat:` (only intel matched by
exact key); **business service** → `Service:`; **plain-English explanation** → `Why this ranks`.

## Q1 — the data split

**Structured** is everything with a join key, a closed enum, or a magnitude: assets (60),
vulnerabilities (114), intel (40), services (20), remediation guidance (30). These are filtered
and joined in code, never embedded — embedding a CVSS of 9.8 destroys the ordering that makes
it useful.

**Embedded** is the NIST SP 800-53 catalog only — 1189 control statements, unbounded prose with
no join key, where a finding maps to a control by meaning (`SI-2`, `SC-7`) not string match.
That is the entire contents of the vector store.

Ambiguous cases:

- **`remediation_guidance.csv`** — prose-like but treated as **structured**: a lookup resolved
  with hand-verified keyword rules. 30 rows is small enough to check exhaustively by hand.
- **`threat_intelligence.summary`** — free text, kept **structured and displayed, not queried**.
  The intel-to-finding link is the exact `matched_cve_or_control` key; the summary is shown as
  evidence but is never a retrieval key.
- **The MDR report** — two documents in one file. Five campaign blocks are structured records in
  prose (parsed and cross-checked against the intel CSV); the "Analyst Notes" section is the
  scoring rubric, encoded as weights rather than parsed.

## Scoring

The weights are **ordinal, not empirical** — they encode a stated priority order, not measured
coefficients. They live in `config.py::WEIGHTS` so `eval.py` can sweep them. The five groups and
their order come from the MDR report's "Analyst Notes" rubric
(`data/synthetic_threat_report.md`, lines 79–83; mapping cited in the `config.py` docstring).

| Factor (rubric, lines 79–83) | Group | Max | Key terms |
|---|---|---:|---|
| Internet exposure | `exposure` | 25 | internet_exposed 18, production 7 |
| Active exploitation | `exploitability` | 22 | cvss×8, exploit_available 8, no_auth 4, kev_listed 2 (+ maturity ≤5) |
| Ransomware association | `adversary` | 25 | intel_match 8, ransomware 8, region/sector fit 2, recent 2 |
| Business criticality / scope | `business` | 25 | customer_facing 4, PCI/GDPR 4, revenue 4, RTO 5/3/1 (+ criticality) |
| Missing compensating controls | `control_gap` | 10 | no_edr 5, no_vendor_patch 3, days_open 2 |

Three signals came from **measurement, not the rubric**, each tied to a golden-set constraint:

- **`transitive_dependents`** — the golden set showed consequence was under-modelled, so forward
  dependency fan-out was added as its own `blast_radius` group (keeping the rubric maxima stable).
- **`recovery_infrastructure`** (constraints P04/P09) — Backup and Recovery has zero dependents,
  so fan-out scored it *down* despite it being the fallback for every other incident. A visible
  hardcode (`RECOVERY_SERVICES`) because no data field encodes "recovery of last resort".
- **`rto_hours`** (constraint P11) — downtime tolerance in numbers is harder evidence than the
  revenue enum. Tiered, kept alongside `revenue_impact` (money-lost vs downtime are distinct axes).

## Evaluation

The golden set (`tests/golden/golden_set.yaml`) was hand-built **before** scorer output was
seen. It records **pairwise constraints** ("A outranks B") rather than a full ordering, because
honest confidence is achievable pairwise where it isn't for a full ranking. Contamination is
tracked per pair as a `blind` field; contested pairs keep their counterargument and are reported
separately.

| Metric | Value | Notes |
|---|---|---|
| pairwise (primary) | **4/5** (0.800) | non-contested pairs; the CI regression floor |
| precision@5 | **0.800** (4/5) | `blind: false` — the top-5 was seen |
| retrieval recall@3 | **0.955** (21/22) | an acceptable control in the top-3 |
| contested | 0.167 (6 pairs) | reported, not gated |

The headline is a fraction, not a bare decimal — the denominator is five pairs. Reintroducing
the `rto` and `blast_radius` weights one at a time gives a measured **2/5 → 3/5 → 4/5**:

| Step | Pairwise | Δ | What moved |
|---|---:|---:|---|
| baseline (rto + blast zeroed) | 2/5 | — | P01, P04 pass |
| + rto_hours (P11) | 3/5 | +1/5 | flips P11; also narrows P03 −2.4→−0.4 and P09 −4.0→−1.0 without flipping them |
| + blast_radius (P09) | 4/5 | +1/5 | flips P09 (−1.0→+5.0): DR bucket scored top-tier despite 0 dependents |

The rto step is a good example of margin work: it moved P03 and P09 toward zero (real progress
on a five-pair denominator) while only flipping P11 in the fraction.

**What still fails:** P03 (margin −0.4). An internet-exposed finding with no intel loses to an
internal-only one carrying an active ransomware campaign. The scorer is additive and can't
express "discount a live campaign against an unreachable asset". Pinned by `EVAL_PAIRWISE_FLOOR`.

**Caveats:** single annotator; five-pair denominator (each pair worth 0.2); precision@5 is
`blind: false`. Contested pairs were not promoted into the headline to widen the denominator —
that would be selecting constraints after seeing scores.

## Design decisions

- **Deterministic scoring, not LLM ranking.** The scorer already reads every signal the LLM
  would; ranking with the model adds non-determinism and breaks traceability for no gain.
- **Exact-key intel matching.** 16 deliberate noise records exist to catch a fuzzy matcher; only
  24 of 40 records match. Asserted as a regression test (`matched_intel_count == 24`).
- **Two channels, never merged** — used three times: exact vs semantic intel; retrieved chunks
  vs rule-derived `gap_controls`; inventory exposure vs `exposure_model_mismatch`.
- **Collapse-to-base retrieval.** Over-fetch 40, collapse enhancements (SI-2(5) → SI-2) to 3
  distinct base controls, carry the enhancement IDs alongside.
- **Dedupe before truncating.** Without it, CitrixBleed occupies two of five slots (two load
  balancers) and pushes a distinct finding out.
- **The guard is a real control.** CVE tokens and numbers must appear verbatim in the evidence,
  cited control IDs must be in the retrieved set, adversary claims are rejected when no intel
  matched. Retry once, then template.
- **Embedding at build time only.** `sentence-transformers`/`torch` are build-only extras; the
  deployed service loads a precomputed query-vector pack and no model.

## Considered and rejected

1. **LLM re-ranks the top-N** — no signal the scorer lacks; trades traceability for nothing.
2. **Fuzzy intel matching** — attaches unrelated campaigns; the 16 noise records punish it.
3. **Embedding intel summaries** — reintroduces fuzzy matching; kept as displayed evidence.
4. **Semantic intel as a second channel** — deferred, not rejected: valid only if kept visibly
   separate from confirmed matches. Out of scope for v1.
5. **Hybrid BM25 + RRF retrieval** — rejected on a measurement: recall@3 threshold set to 0.8
   *before* measuring; it came in at 0.955, so the complexity wasn't justified.

## Q2 — where it goes wrong

Three failure modes grounded in this dataset, each with the mitigation in code.

1. **KEV false-negatives.** 74/114 (64.9%) findings carry synthetic CVE ids absent from KEV;
   with 11 real-but-unlisted CVEs, **85/114 (74.6%) have no KEV listing**. A naive "not in KEV ⇒
   safe" mislabels most of the estate. → **Three-valued `kev_status`**: synthetic ids are
   `unknown`, never silently `not_listed`; coverage is reported (**25.4%, 29/114**) and a test
   asserts the band is neither 0 nor 100. *`ingest/kev.py`.*
2. **Wrong exposure model for object storage.** A public bucket policy is reachable via the
   provider URL regardless of network position, but the inventory marks it internal-only. →
   **`exposure_model_mismatch`** scores it as reachable without mutating `internet_exposed`;
   fires on exactly one finding (V-2071) and surfaces in the brief. *`pipeline/join.py`.*
3. **Single-label classification.** A host that is both unpatched and unmonitored gets one
   `finding_type` (16 findings classify as `missing_edr`), so retrieval would miss the monitoring
   control. → **Family union across `control_gaps`** plus the rule-derived `gap_controls` channel.
   *`rag/families.py`.*

The guard firing then the retry succeeding — the real `enforce()` loop, driven by a model
scripted to hallucinate once then correct:

```
[guard] attempt 1 REJECTED :: control_id 'SI-2(9)' not in retrieved set; number '7.5' not grounded in evidence
[guard] final explanation_source = llm  (control cited: SI-2)
```

## Data defects found

- **Four columns the first scorer ignored,** surfaced by hand-ranking: `depends_on`,
  `business_impact`, `rto_hours`, and cross-finding host context. The first three became weights.
- **The WinterViper contradiction.** `threat_intelligence.csv` (TI-3023) says ransomware = Yes;
  the MDR report says No. The CSV wins per a stated rule and the disagreement is flagged
  `intel_ransomware_conflict` on the finding (Kong, V-2024) rather than averaged away.
- **EDR denominators reconcile but differ:** 16 findings classify `missing_edr`; 26 assets lack
  EDR; the broader `no_edr` gap flag appears on 48 findings. All correct, worth stating.

## Q3 — one thing I would change

The missed golden slot (precision@5 = 0.800) is Fortinet SSL-VPN RCE (CVE-2024-21762), ranked #2
in the golden set. The scorer models business impact per-service, so the VPN edge
(`customer_facing = No`, 0 dependents, no PCI/GDPR) is under-weighted despite a VPN compromise
being the pivot into the whole estate. The remedy is an asset-role signal separating pivot
infrastructure from leaf services. I did not build it: it surfaced late, there is no clean
structured field for it, and adding it after seeing the output would be tuning toward the
benchmark.

## Verify it yourself

```bash
make eval                                          # pairwise 0.800 (4/5), precision@5 0.800
curl -s .../api/findings | jq length               # 114 — nothing truncated before scoring
curl -s .../healthz | jq                           # live fetch timestamps + LLM/template split
```
(base URL `https://tawasolpay-risk.onrender.com`)

## Run locally

```bash
git clone https://github.com/JugaadChhabra/hivepro-assignment.git && cd hivepro-assignment
make install
export GROQ_API_KEY=...     # optional; without it, explanations are templates
make eval                  # metrics above (no network)
make run                   # http://localhost:7860
make test                  # CI gate: 108 passed, no network, no model
```

`make test` (ruff, mypy, `pytest -m "not network"`, `eval.py`) is the CI gate; the network
suite (`pytest -m network`, `eval --retrieval`) runs as a separate job. `docker build` mirrors
the deployed image.

## Routes and layout

| Path | Description |
|---|---|
| `/` | HTML risk report (top-5) |
| `/docs` | FastAPI / OpenAPI docs |
| `/api/risks` | the `RiskBrief` — score breakdown, control, `explanation_source` per risk |
| `/api/findings` | all 114 scored findings |
| `/traces` | last N run traces (input SHA-256s, KEV stats, per-risk breakdown) |
| `/healthz` | catalog version + SHA, fetch timestamps, KEV coverage, LLM/template split |

```
src/riskagent/
  config.py    # WEIGHTS, thresholds, REFERENCE_DATE — the one tuning surface
  ingest/      # CSV loader, KEV fetch, NIST fetch, MDR report parser
  pipeline/    # join, intel_match, control_gaps, campaign, score (deterministic)
  rag/         # Chroma index, retrieval, family filter, build-time query pack
  generate/    # select, guard + LLM assemble, render, trace
  app.py       # FastAPI
data/  templates/  tests/ (incl. golden/)  eval.py
```

## Invariants and freshness

- **Invariants** (asserted in tests): the LLM never decides a rank, score, or control; all 114
  are scored before truncation; only NIST controls enter the vector store; intel matching is
  exact string equality.
- **Freshness:** KEV and NIST are fetched live and cached with timestamps (not bundled). A stale
  KEV copy (>7 days) flips `kev_staleness_warning` and shows a banner. NIST is embedded at build
  time (the runtime has no model to re-embed); version + SHA are shown at `/healthz`.
- **Reproducibility:** recency scores against a fixed `REFERENCE_DATE = 2026-04-24`, never the
  wall clock, so scores don't drift past this synthetic dataset.
- **Degradation:** if Groq is unreachable the brief still renders with retrieved controls and
  template sentences. `/healthz` currently reports 3 of 5 explanations as LLM, 2 as template.
