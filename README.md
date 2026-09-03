# TawasolPay Cyber Risk Assistant

Ranks TawasolPay's 114 open vulnerability findings into a top-5 risk brief and cites the NIST
SP 800-53 control for each. The ranking is deterministic: a weighted rule set decides order,
score, and control. The LLM only writes the one sentence that explains a rank — and a guard
rejects anything it can't find in the evidence, so if the model is unreachable the brief still
renders from templates.

**[Live brief](https://risk-assistant.jugaadchhabra.dev/) · [API docs](https://risk-assistant.jugaadchhabra.dev/docs) · [Repo](https://github.com/JugaadChhabra/hivepro-assignment)**

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

- **Additive groups with per-group maxima — deliberately not tier gates.** Six groups, each
  capped (exposure 25, exploitability 22, adversary 25, business 25, control_gap 10,
  blast_radius 12), summed to a total. The caps carry weight: they stop one dimension being run
  up by stacking small factors, so an internal dev box can't out-total an exposed payment
  gateway. Every branch that fires appends a plain-English reason, so the score reconstructs
  line by line — and that reason list is the evidence the LLM is later handed. The model is
  never given the ranking, because it reads nothing the scorer hasn't already read.
- **A blast-radius group for consequence, not just likelihood.** The other five groups answer
  "how likely is this hit"; blast radius answers "how far it spreads." It reads the `depends_on`
  graph transitively (Identity Verification carries 5 dependent services and looks unremarkable
  on its own row), recovery-of-last-resort infrastructure, and the campaign's objective
  (credential/IP theft spreads; a contained outage does not). Kept a separate group so the
  rubric-derived maxima stay fixed and the before/after tuning reads cleanly — and it exists
  because the golden set flagged a class of pairs the scorer got wrong for exactly this reason.
- **Exact-key intel matching, checked against planted noise.** Intel attaches only on exact
  `matched_cve_or_control` equality — no normalising, no embedding. The feed carries 16 noise
  records built to trip a fuzzy matcher; a test pins the split at 24 matched / 16 unmatched and
  asserts a lowercased near-miss of a real CVE does not attach.
- **Reproducible by construction.** Recency scores against a fixed `REFERENCE_DATE`, never the
  wall clock, so a score doesn't drift as real time passes this synthetic dataset; every run
  appends a trace with the six input-file SHA-256s, so any ranking ties back to exact bytes.
- **The evaluation is part of the build.** A golden set of pairwise constraints, recorded before
  the scorer's output was seen, drives precision@5, recall@3, and blind-tracking, and a CI floor
  fails the build if a weight change breaks a non-contested pair.

## What I considered and rejected

1. **Hugging Face Spaces for hosting** — the first target (16 GB RAM, 48-hour idle pause).
   Dropped when HF moved Docker Spaces behind a paid plan in 2026. The forced move to Render's
   512 MB is what pushed the embedding model out of the runtime entirely: the catalog and every
   finding's query vector are computed at `docker build` and shipped in the image, so runtime
   retrieval is a lookup with no torch. Recorded as a reversal, not swapped silently.
2. **Making staleness additive** — golden pair P10 argued that unseen-and-unowned *is* the risk
   and should add points. Rejected on measurement: it moved headline pairwise by zero and
   couldn't satisfy P10 without inventing graded-age and no-owner sub-signals. P10 was retired to
   the golden set's `excluded` section with the reasoning kept.
3. **Folding blast radius into the Business group** — kept it separate so the five rubric-derived
   maxima stay fixed and the tuning table shows a clean before/after.
4. **Hybrid BM25 + RRF retrieval** — the recall@3 bar was set to 0.8 *before* measuring; it came
   in at 0.955, so the extra machinery wasn't warranted.
5. **An agent framework and LLM reranking** — the flow is a straight line with no tool-use
   decisions, and the scorer already holds every signal a reranker would weigh. Both were
   declined as non-determinism without new information.

## Where it goes wrong

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

The guard's honest limit: it rejects *ungrounded* entities (a CVE, number, actor, or control not
in the evidence), but not *misattribution* — a real matched actor paired with the wrong CVE would
pass, because both names are individually in the allow-list.

## Data defects found

- **Four columns the first scorer ignored,** surfaced by hand-ranking: `depends_on`,
  `business_impact`, `rto_hours`, and cross-finding host context. The first three became weights.
- **The WinterViper contradiction.** `threat_intelligence.csv` (TI-3023) says ransomware = Yes;
  the MDR report says No. The CSV wins per a stated rule and the disagreement is flagged
  `intel_ransomware_conflict` on the finding (Kong, V-2024) rather than averaged away.
- **EDR denominators reconcile but differ:** 16 findings classify `missing_edr`; 26 assets lack
  EDR; the broader `no_edr` gap flag appears on 48 findings. All correct, worth stating.

## What I would do with more time

**Accuracy.** The additive scorer can't express interactions, and it costs us in two *measured*
places: it can't discount a live campaign against an unreachable asset (pair P03, margin −0.4),
and it can't credit a low-value asset for being a pivot (the Fortinet VPN miss, precision@5 =
0.800 — the golden #2 dropped). The fix is a gating layer over the additive score: reachability
gating the adversary term, an asset-role signal marking pivot infrastructure. I left it out on
purpose — adding it after watching P03 fail would be tuning to a five-pair golden set, and the
honest prerequisite is a larger labelled set to calibrate against. That set would also let me set
the point-values empirically; today their ordering is principled (the report's rubric) but the
exact numbers are considered guesses.

**Presentation.** The rendered brief explains each rank in a sentence but hides the arithmetic —
the per-group breakdown only exists on `/api/risks`. I'd surface it in the brief itself as a short
contribution bar per group, so a reader sees *why* #1 outranks #2 at a glance, and render the
cited NIST control's actual statement inline instead of a one-line summary.

## Verify it yourself

```bash
make eval                                          # pairwise 0.800 (4/5), precision@5 0.800
curl -s .../api/findings | jq length               # 114 — nothing truncated before scoring
curl -s .../healthz | jq                           # live fetch timestamps + LLM/template split
```
(base URL `https://risk-assistant.jugaadchhabra.dev`)

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
