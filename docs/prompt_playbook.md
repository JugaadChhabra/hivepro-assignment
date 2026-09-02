# Prompt Playbook — TawasolPay Cyber Risk Assistant

Companion to `implementation_plan.md`. One session per phase, one reviewer pass per phase, no phase starts until the previous one is signed off.

---

## How to use this

1. Work in a fresh session per phase. Long sessions drift, and drift is what produces "it compiles but the numbers are wrong."
2. Paste the **Standing Context** block (below) at the top of every session. It's the invariant set.
3. Paste the phase prompt.
4. When the phase reports done, run the **Reviewer** on it. Do not skip this even when the code looks fine — the reviewer's job is to catch the failure modes you're too close to see.
5. Commit only after a `PASS` verdict. One commit per phase, message `phase-N: <what>`.

The spec lives at `docs/implementation_plan.md` (single copy — no root duplicate). Reference it by that path rather than re-pasting.

---

## Standing Context (paste at the start of every session)

```
PROJECT: TawasolPay Cyber Risk Assistant — take-home for an AI Associate role
at a cybersecurity company. The full spec is in docs/implementation_plan.md — read
it before writing code.

WHAT I AM BEING GRADED ON, in priority order:
1. The ranking is defensible and every number traceable to its source
2. The structured/semantic split is deliberate, not decorative
3. Evaluation exists and produces measurable numbers
4. It runs at a public URL

NON-NEGOTIABLE INVARIANTS — violating any of these is a failed submission:
- The LLM never decides a rank, a score, or which NIST control applies.
  It writes prose from evidence that has already been decided.
- All 114 findings are scored. Never retrieve-then-rank. Never truncate
  before scoring.
- No CVSS score, no asset attribute, no vulnerability row ever enters the
  vector store. Chroma holds NIST controls and nothing else.
- Threat intel matching is exact string equality on
  `matched_cve_or_control`. No fuzzy matching, no normalisation, no
  embeddings. The dataset contains 16 deliberate noise records designed to
  catch a fuzzy matcher.
- Missing data is `unknown`, never `false`. Roughly 75% of the CVE IDs are
  synthetic and absent from CISA KEV.
- External documents (KEV, NIST) are fetched fresh at startup and cached with
  a timestamp. Cache fallback on fetch failure is permitted. SILENT cache
  fallback is not — if the served copy is more than 7 days stale, that must
  be visible in /healthz and as a banner in the rendered report.

VERIFIED FACTS ABOUT THE DATA — if your code produces different numbers,
your code is wrong, not the data:
- 60 assets, 114 vulnerabilities (all status Open), 40 intel records,
  20 business services, 30 remediation guidance rows
- Every vuln.asset_id exists in assets.csv — zero orphans
- Every asset.business_service exists in business_services.csv — zero orphans
- Exactly 24 of 40 intel records match a CVE present in vulnerabilities.csv;
  16 do not and must not match
- 26 of 60 assets have edr_installed = No
- 62 of 114 vulnerabilities are internet-exposed
- ~20 of 79 distinct CVE-column values are real CVEs; the rest are synthetic
  (CVE-SYN-*, CTRL-SYN-*, K8S-SYN-*, CICD-SYN-*, CLOUD-SYN-*)
- vpn-edge-01/02 carry identical Fortinet findings and load-balancer-prod-01/02
  carry identical CitrixBleed findings — these must be deduped before the
  top-5 cut or four of five slots are two CVEs counted twice
- One asset has a blank owner_team

HOUSE RULES:
- Typed Python. `mypy --strict` and `ruff` must pass before you call a phase done.
- Tests are written in the same session as the code, not after.
- No new dependency without saying why in one line.
- If a spec decision looks wrong to you, say so before implementing it.
  Do not silently improve it.
- If you are unsure whether something is in scope for this phase, ask.
  Do not build ahead.
```

---

## Phase 0 — Bootstrap

```
Set up the repo skeleton per §1 of implementation_plan.md. Nothing else.

Create:
- pyproject.toml with ruff, mypy (strict), pytest configured
- the src/riskagent/ package tree with empty __init__.py files
- tests/ tree
- .github/workflows/ci.yml running ruff, mypy --strict, pytest
- .gitignore covering cache/, .env, __pycache__
- Makefile with: install, lint, test, run, eval
- README.md stub with the section headings from §9 only

Copy the six data files into data/ and commit them.

Do NOT write any application logic. When done, show me the tree and confirm
`make lint` and `make test` both pass on an empty test suite.
```

**Exit:** CI green on an empty project. Commit `phase-0: skeleton`.

---

## Phase 1 — Contracts and loading

```
Implement src/riskagent/models.py and src/riskagent/ingest/csv_loader.py per
§2 and §3 of implementation_plan.md.

models.py: the pydantic models exactly as specified. Pay attention to two
decisions and do not "simplify" either:
- kev_status is a three-valued Literal, not a bool
- EnrichedFinding.intel is a list, not Optional[IntelRecord]

csv_loader.py: parse all five CSVs into typed models. Coerce Yes/No to bool,
dates to date, empty strings to None. Raise on schema drift — do not default
missing columns.

TESTS (tests/test_loader.py):
- exact row counts: 60 / 114 / 40 / 20 / 30
- the blank owner_team row loads with owner_team is None, does not crash
- every bool field is actually bool, not the string "Yes"
- cvss values are floats within 0.0–10.0
- a deliberately malformed row raises rather than silently defaulting
- loading is idempotent: two loads produce equal objects

Report the row counts you actually got before I look at the code.
```

**Exit:** all six tests pass, `mypy --strict` clean. Run the reviewer.

---

## Phase 2 — Join, intel match, control gaps

```
Implement pipeline/join.py, pipeline/intel_match.py, pipeline/control_gaps.py
per §4 of implementation_plan.md.

join.py: LEFT JOIN vulns→assets on asset_id, then →services on
business_service. Assert zero orphans on both — verified true for this data,
so an orphan means something broke. Reconcile vulnerabilities.asset_exposure
against assets.internet_exposed; on disagreement append
"exposure_source_conflict" to data_flags and treat the asset inventory as
authoritative. Do not silently pick one.

intel_match.py: dict keyed on matched_cve_or_control, exact string equality.
One-to-many. Then compute a relevance weight from target_region /
target_sector fit, confidence, and active_last_seen recency — but keep the
weight SEPARATE from the match boolean.

control_gaps.py: derive the six gap tags listed in the plan.

TESTS (tests/test_join.py, tests/test_intel_match.py):
- join produces exactly 114 rows, zero orphans either side
- assert matched_intel_count == 24 and unmatched_intel_count == 16
- CVE-2024-3400 (Palo Alto) and CVE-2025-0282 (Ivanti) match NOTHING —
  these are the noise records, name them explicitly in the test
- PHISH-SYN-001 and INSIDER-SYN-001 match nothing
- a CVE with two intel records returns both, not the first
- exactly 26 findings-on-assets carry the "no_edr" tag
- a fabricated near-miss key (e.g. "cve-2024-21762" lowercase) does NOT match,
  proving the matcher is not normalising

That last test is the important one. Write it deliberately.
```

**Exit:** 24/16 assertion passes, the lowercase near-miss test passes. Reviewer.

---

## Phase 3 — The scorer

```
Implement pipeline/score.py and config.py per §4 of implementation_plan.md.
Use the weights table exactly as written. Do not tune anything in this phase.

score() must be a pure function: EnrichedFinding -> ScoreBreakdown. No I/O,
no globals, no model calls. Every branch that fires appends a human-readable
string to reasons[]. Weights live in config.py as a dict so eval.py can sweep
them later.

Staleness (last_seen_days > 30) adds ZERO points. It sets a flag only. Do not
let it contribute to the total.

TESTS (tests/test_score.py) — build these fixtures by hand, not from the CSVs:
1. The assignment's worked example: internal dev server, CVSS 10.0, no exploit,
   no intel MUST score below internet-facing payment gateway, CVSS 8.1,
   exploit available, ransomware intel. Assert the inequality directly.
2. Two findings identical except internet_exposed — exposed scores exactly
   18 higher.
3. Two findings identical except ransomware intel — assert the exact delta.
4. A finding with empty intel list scores adversary == 0 and does not crash.
5. score() is deterministic: same input twice, identical output including
   reasons order.
6. reasons[] is non-empty for every one of the 114 real findings.
7. A stale asset (last_seen_days = 90) scores the same as an identical fresh
   one, and carries the flag.

Then run the scorer over all 114 and print the top 10 with their breakdowns.
Show me that table.
```

**Exit:** all seven tests pass. Sanity-check the printed top 10 against expectation: Fortinet VPN, CitrixBleed on the load balancers, Kong admin API, payment API IDOR should all appear. Reviewer.

---

## Phase 4 — RAG

```
Implement ingest/nist.py, rag/index.py, rag/families.py, rag/retrieve.py per
§5 of implementation_plan.md.

nist.py: fetch the SP 800-53 Rev 5 control catalog, cache to disk with a
timestamp, fall back to cache when offline. Parse to one record per control.

index.py: ONE CONTROL PER CHUNK. Not token windows. Embed
"{control_id} {title}\n{statement}" with all-MiniLM-L6-v2. Discussion goes in
metadata, not the embedding. Metadata: control_id, family, title. Persist to
cache/chroma/. Put the model name in config.py, and put Chroma behind a
ControlStore Protocol so it can be swapped.

families.py: the FAMILY_HINTS map. finding_type derived by explicit keyword
rules from affected_component + vulnerability_name + control_gaps.

retrieve.py: query text TEMPLATED from structured fields, never raw text.
Filter by FAMILY_HINTS[finding_type], top-3. If best distance exceeds the
threshold, retry unfiltered and flag "family_filter_fallback".

Ship dense-only. Do NOT add BM25 or RRF yet — that decision is made in
phase 6 based on a measurement.

TESTS (tests/test_rag.py):
- index contains ~1100 chunks, one per control, none empty
- no chunk text contains a CVSS score or an asset_id (guard against
  contamination — assert on a sample of chunk texts)
- a Fortinet unpatched-firmware finding returns SI-2 in the top 3
- an end-of-life Windows finding returns SA-22 in the top 3
- the family filter actually narrows: same query filtered vs unfiltered
  returns different result sets
- the fallback path fires and flags when given a nonsense finding_type
- retrieval is deterministic across two calls

Print the top-3 controls for five different finding types so I can eyeball
whether the retrieval is sane.
```

**Exit:** SI-2 and SA-22 tests pass, contamination test passes. Reviewer.

---

## Phase 5 — Generate and serve

```
Implement generate/select.py, generate/llm.py, generate/guard.py,
generate/render.py, and app.py per §6 of implementation_plan.md.

select.py: sort by total, DEDUPE on (cve, vulnerability_name) collapsing to
affected_assets: list[str], THEN take 5. Dedupe before truncating, not after.

llm.py: Groq, llama-3.3-70b-versatile, temperature 0, five concurrent calls.
The prompt gets the evidence block, score.reasons, and retrieved control text
verbatim. Nothing else. Returns JSON: why_ranked, control_id, control_summary.

guard.py: validate control_id is in the retrieved set; every CVE-shaped token
and every number in why_ranked appears in the evidence block; no threat actor
name appears when intel is empty. On failure retry once with the violation
appended; on second failure fall back to a template sentence built from
score.reasons and tag explanation_source: "template".

render.py: Jinja, deterministic, no model calls. Use the entry format in §6.
Two additions carried forward from phase 4:
- SURFACE THE ENHANCEMENT ID. Retrieval collapses enhancements to their base
  control for the citation but carries the matched enhancement IDs+text on the
  result (RetrievalResult.chunks[i].enhancement_ids / .enhancements). Where an
  enhancement matched, render "CP-9 System Backup, particularly CP-9(1)" — the
  base is the citation, but the enhancement is often where the actionable
  sentence lives (backup immutability is in CP-9(1), not CP-9's base text).
- SHOW EXPLOIT PREREQUISITES. The evidence line MUST print auth_required and
  exploit_available explicitly. This came out of an excluded golden pair whose
  reasoning inverted because auth_required wasn't visible — a human reading the
  brief who can't tell whether an exploit needs credentials will mis-sequence
  remediation the same way. e.g. "exploit available · no auth required".

app.py: the five routes. Pipeline runs once at startup and caches.

TESTS (tests/test_select.py, tests/test_guard.py):
- select() collapses vpn-edge-01/02 into one entry with two affected_assets
- select() returns 5 entries with 5 distinct (cve, vulnerability_name) pairs
- guard rejects a fabricated control_id not in the retrieved set
- guard rejects a sentence containing a CVE absent from the evidence
- guard rejects a threat actor name when intel is empty
- guard's template fallback produces a non-empty sentence from reasons[]
- /api/findings returns all 114, proving nothing was truncated before scoring
- render shows auth_required and exploit_available on the evidence line, and the
  matched enhancement ID where one was retrieved

Mock the LLM in tests. No network calls in the test suite.
```

**Exit:** local server renders a readable brief; the dedupe test passes. Reviewer.

---

## Phase 6 — Evaluation (do not skip)

```
Build the evaluation harness per §7 of implementation_plan.md.

First, dump all 114 scored findings to a CSV I can open, sorted by score,
with the full breakdown columns. I am going to hand-rank from this.

Then, once I give you the golden data, implement:

tests/golden/golden_set.yaml — ~15 pairwise constraints plus a golden top-5.
Include the assignment's own worked example as a constraint.

eval.py — prints three numbers:
- pairwise satisfaction rate (primary)
- precision@5 against the golden top-5
- retrieval recall@3 against ~20 hand-labelled risk→control pairs

3. RETRIEVAL UNDER-SERVES UNMONITORED HOSTS (found in phase 4, fix here — NOT a
   phase-4 reopen). Single-label classification silently drops a remediation
   dimension: 10 findings have an EDR gap but classify as unpatched_software
   (correct — a patch exists, so patching is primary). The consequence is that a
   finding on an unmonitored host retrieves SI-2 and never surfaces SI-3, so the
   brief says "patch" and never mentions nothing would have noticed an intrusion.
   Scoring is unaffected (phase-2 control_gaps tracks no_edr independently and
   feeds the scorer); it is retrieval, and therefore the output, that under-serves.
   Fix: union the family filter across the primary finding_type AND the control
   gaps, using phase-2 work that currently only feeds the scorer:

       families = set(FAMILY_HINTS[finding_type])
       for gap in finding.control_gaps:
           families |= set(GAP_FAMILY_HINTS.get(gap, ()))   # e.g. no_edr -> ["SI","AU"]

   So unpatched_software + no_edr searches SI, RA, AU and SI-3 becomes reachable
   in the top 3 alongside SI-2. Verify BOTH: (a) a finding with both signals
   returns SI-2 AND SI-3 in the top 3, and (b) widening does not degrade the clean
   cases — re-run recall@3 on R01–R22 before and after and report both numbers.

Wire eval.py into CI as a regression gate.

THEN, and only then, tune weights. Rules for tuning:
- change ONE weight at a time and report the metric delta
- if a change improves the metric but you cannot explain why in one sentence,
  revert it
- do not tune toward the golden top-5 specifically — that overfits to 5 rows
- record every change and its delta in a table for the README

Finally: measure retrieval recall@3. If it is below 0.8, add rank_bm25 and
fuse with reciprocal rank fusion at k=60, then re-measure and report both
numbers. If it is above 0.8, do not add it, and say in the README that the
decision was measured rather than assumed.

BLAST RADIUS — a new scorer group, added in this phase, NOT tuning.

Hand-ranking surfaced a consistent class of pair the scorer gets wrong: it
models likelihood well and consequence barely. Two signals fix it. Add them
AFTER the golden set exists and BEFORE weight tuning, and report the metric
delta for each separately so their contribution is measurable.

1. transitive_dependents — business_services.csv has a depends_on column we
   are currently not using at all. Parse it into edges in join.py, compute the
   transitive dependent count per service (how many services fail, directly or
   indirectly, if this one does). Split on comma, strip, empty = none.
   TRAVERSE WITH A VISITED SET — the data is acyclic today, but a cycle must
   not be discovered as a production hang.
   Expected: Identity Verification 5, Customer Login 4, Payment Processing 1,
   Software Delivery 1, Testing Platform 0. Assert these — if your numbers
   differ, the traversal is wrong.
   Score: >=3 dependents +6, 1-2 +3, 0 +0.

2. campaign objective — wire the term but leave it DORMANT this phase. It
   depends on report_parser.py, which is phase 7. Same pattern as the KEV
   term: the branch exists, contributes 0, and comes alive in phase 7.
   Score when live: credential_theft or ip_theft +6, payment_fraud +4.

Keep this as its own scoring group. Do not fold it into Business — the
existing group maxima must stay stable so the tuning table shows before/after
cleanly.

TESTS:
- transitive_dependents matches the five expected values above
- a synthetic cyclic depends_on graph terminates and does not hang
- a service with empty depends_on scores 0 on this group
- the objective term contributes exactly 0 for all 114 findings this phase
- pairwise satisfaction rate BEFORE and AFTER adding blast radius, reported
  separately — this is the evidence that the signal was discovered through
  evaluation rather than assumed
```

**Exit:** three metrics printed, a weight-change table, a measured decision on hybrid retrieval. Reviewer.

---

## Phase 7 — Report parser, KEV, tracing

```
FIRST, before the parser/KEV/trace work: resolve the exposure_model_mismatch.
This was sixth of seven on the phase-6 queue and did not make the 6b cut (my
sequencing error); it is promoted to the front of phase 7 because it is the one
outstanding item that can change the golden top-5, and phase 8 writes the README
around that top-5.

The defect: backup-storage-prod (CLOUD-SYN-001, V-2071) is marked
internet_exposed = No while carrying a PUBLIC object-storage policy. Network-
perimeter exposure is the wrong model for cloud object storage — a public object
policy is readable via the provider's own URL regardless of network path, so a
perimeter scanner marks it unexposed for want of a route.

PINNED RULE (do NOT reopen this decision):
  IF affected_component OR vulnerability_name indicates cloud object storage
  with a public / overly-permissive access policy, THEN
    (a) append exposure_model_mismatch to data_flags, AND
    (b) score the exposure term AS IF internet-reachable.
  Do NOT mutate internet_exposed. Both facts survive — the CSV's internal-only
  bit and the reachability disagreement — and nothing is silently overwritten.
  This is the same two-channel discipline as exact-vs-semantic intel and
  retrieval-vs-rule gap_controls: a third source of exposure evidence recorded
  alongside the CSV, not resolved into it. §4 already flags exposure
  disagreements rather than resolving them; this extends that, it does not
  break it.

Constraints on the implementation:
- NARROW. Public-access policy on object storage ONLY. Not "any misconfig",
  not firewall rules (SC-7 territory, already handled), not exposed admin
  interfaces. Assert the fired count in a test; expected 1-2 findings. If it
  fires on more than that the predicate is too loose — tighten it, do not ship.
  DATA CHECK (this dataset): a storage-AND-public predicate over
  vulnerability_name + affected_component fires on exactly ONE finding, V-2071
  ("Storage Bucket Public Policy Misconfiguration" / "Object Storage Policy"),
  and correctly excludes V-2031 ("Missing Encryption at Rest" / "Storage
  Encryption") — no public policy, so not reachability. Assert == 1 here.
- RENDERED, not just traced. The flag must appear in the report output, e.g.:
  "inventory records this asset as internal-only, but a public object policy
  may make it reachable via the provider URL — verify before deprioritising."
- precision@5 BEFORE and AFTER, reported. The golden set's reversal_trigger
  already states the expected outcome: V-2071 enters the top-5 at ~rank 2 (live
  exfiltration, no EDR) and V-2009 (current rank 5) drops out. If the top-5 set
  shifts and precision@5 STAYS 5/5 (1.000), the conditional worked — then update
  golden_set.yaml's top_five AND near_misses to match the new set. If
  precision@5 DROPS, STOP and report: something disagrees with the trigger and
  must be resolved before phase 8, not papered over. Record the before/after
  delta the same way the phase-6 blast-radius work did.

THEN the parser/KEV/trace work:

Implement ingest/report_parser.py, ingest/kev.py, and trace.py per §3 and §6.

report_parser.py: regex the five campaign blocks into Campaign records. Then
CROSS-CHECK against threat_intelligence.csv — both sources claim CrimsonJackal
exploits CVE-2024-21762. Assert agreement; on mismatch append to data_flags and
prefer the CSV. Do not merge.

KNOWN CONFLICT, already found — do not treat as a surprise: TI-3023 says
WinterViper ransomware_association = Yes, while §5 of the report says
"Ransomware: No — financial fraud and data theft focused". The CSV wins per
the rule above, the disagreement gets flagged, and this belongs in the README
as an example of the system detecting a contradiction between two intel
sources rather than silently averaging them. Assert this specific flag fires.

OBJECTIVE EXTRACTION — this is the consequence signal the scorer has been
missing, and it activates the dormant term wired in phase 6.

Each campaign block states its goal in prose. Map to the enum with explicit
keyword rules over the block text:
  CrimsonJackal  -> ransomware_deployment
  RedMantis      -> ip_theft          (source code theft, supply chain access)
  SilentForge    -> credential_theft  (build secrets, keys, API credentials)
  IronVeil       -> ransomware_deployment
  WinterViper    -> payment_fraud
Default to "unknown" rather than guessing. NEVER infer objective from the
actor name — infer it from the block text, so the rule generalises to a
campaign we have not seen.

The "Threat Intelligence Analyst Notes" section is NOT parsed. It is the
scoring rubric and is already encoded as weights in config.py. Add a comment
in config.py citing the source line.

kev.py: fetch from
https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
— note the default branch is "develop", not "main", a main URL 404s. Cache to
disk WITH a kev_fetched_at timestamp. Join on cveID. Emit kev_lookups,
kev_hits, kev_coverage_pct into the trace. A miss sets kev_status = "unknown",
never "not_listed" — only a confirmed absence from a successfully fetched
catalog sets "not_listed".

STALENESS, not just fallback: if the live fetch fails, fall back to the cached
copy, but check its age. If kev_fetched_at is more than 7 days old, set
kev_staleness_warning = true. This must reach /healthz and the rendered
report as a visible banner. A cache fallback that says nothing is a finding,
not a feature.

nist.py: same pattern — fetch, cache with nist_fetched_at, capture the
catalog's version string (currently Rev 5.1) as nist_catalog_version, carry
it into the Chroma index metadata built in phase 4 and into /healthz.

trace.py: JSONL per run with the fields listed in §6. Expose at /traces.

TESTS:
- parser extracts exactly 5 campaigns with correct CVE chains
- cross-check passes on real data; a mutated fixture triggers the flag
- kev_coverage_pct lands in the 20–35% band — assert the band, and assert it
  is neither 0 nor 100 (both indicate a broken join)
- a synthetic ID like CVE-SYN-2026-0011 yields kev_status "unknown"
- offline mode falls back to cache without raising
- all five campaigns map to a non-"unknown" objective, and the mapping is
  driven by block text not actor name — mutate an actor name in a fixture and
  assert the objective is unchanged
- the WinterViper ransomware conflict flag fires on real data
- the phase-6 objective term is now live: assert it contributes non-zero for
  at least one finding, and run eval.py before and after to isolate what the
  objective signal contributed to pairwise satisfaction
- a cache dated 10 days old, with the network mocked as unreachable, sets
  kev_staleness_warning = true and the banner actually renders in the HTML
  output — check the rendered string, not just the flag
- /healthz returns kev_fetched_at, kev_coverage_pct, kev_staleness_warning,
  nist_catalog_version, and index_built_at — not just a bare status string
- adding KEV enrichment does not change the golden-set pairwise score —
  run eval.py before and after and compare

That last one is the point of having built phase 6 first.
```

**Exit:** eval metrics unchanged or improved after enrichment. Reviewer.

---

## Phase 8 — Ship

**TARGET CHANGED: Hugging Face Spaces → Render.** HF made Docker Spaces a paid
feature in 2026, so the free path is Render's free tier. The original HF prompt is
preserved below (struck through) for traceability; the Render prompt is what was
executed. The change forced two real design moves — a model-free runtime for the
512MB cap, and a 10-minute keep-alive for the 15-min spin-down — recorded in
implementation_plan.md §8.

~~Original (HF Spaces):~~ *Dockerfile multi-stage, build the Chroma index during
`docker build`, expose 7860 (HF requirement), `GROQ_API_KEY` from a Space secret,
Space README frontmatter `sdk: docker` + `app_port: 7860`, keep-alive every 12h.*

```
Dockerfile + deploy to Render (Docker runtime) + keep-alive + README.

WHY RENDER, NOT HF SPACES: HF now requires a paid plan for Docker Spaces
(policy changed 2026). Render free tier it is. Two constraints need real
handling (below), recorded so the switch is traceable, not arbitrary.

Dockerfile: multi-stage. BUILD THE CHROMA INDEX DURING docker build so the
deployed service has no cold-start embedding pass. Port from $PORT env var,
not hardcoded. GROQ_API_KEY comes from a Render environment secret at runtime —
it must not appear in the image, the repo, or any commit in the history. Check
git log -p for accidental commits before pushing.

CONSTRAINT 1 — 512MB RAM. Remove the model from runtime entirely: the corpus
AND query set are static and known at build time (≤114 findings, one templated
query each). At build: embed the NIST catalog AND precompute every finding's
query vector; ship both in the image. At runtime: retrieval is a vector lookup
against precomputed vectors — no sentence-transformers, no torch. Keep the
model as a build-time-only dependency (the `build` extra). Must not change
recall@3: re-run eval and confirm 0.955 — same vectors, so a change means a
wiring bug. If memory still fails, report measured RSS before guessing.

CONSTRAINT 2 — spin-down after 15 min idle (~1 min cold start). keep-alive
every 10 minutes hitting /healthz; note GitHub cron can slip past 15 min so an
external pinger (UptimeRobot) is more reliable if it matters. Render's
ephemeral fs is fine — index lives in the image; cache/kev.json and
traces.jsonl are lost on restart (KEV refetches, traces are per-run) — say so.

Deploy (render.yaml or dashboard) and verify the public URL renders the brief
and that /healthz, /api/risks, /api/findings, /traces all respond, and that
/healthz returns real kev_fetched_at / nist_catalog_version, not placeholders.

LLM SMOKE TEST (do not skip — the brief looks fine even when the LLM does
nothing): after deploy, GET /api/risks and assert at least one entry has
explanation_source: "llm". If all five come back "template", the Groq key or
network is wrong and every explanation silently degraded to a scorer-reason
template while the page still renders. /healthz reports explanations_llm /
explanations_template — check there too, and note the split in the README.

README: fill in §9 of implementation_plan.md. Write the three supporting
answers in my voice, specific to this build, using real numbers from eval.py.

For supporting question 2, use the three data-grounded failure modes — not
generic ones. Each needs the concrete mitigation that exists in the code, with
a file reference.

For supporting question 3, the semantic-intel-matching gap: describe the
two-channel design (confirmed vs possible) and say why precision was preferred
for v1.

Also include: the architecture diagram, make commands, the weights table with
its provenance in the MDR analyst notes, current eval numbers, the
one-annotator caveat on the golden set, and a data-freshness note — KEV fetched
live and checkable at /healthz; NIST pinned at build (model-free runtime) with
version + sha at /healthz.
```

**Exit:** public URL live, README complete. Final reviewer pass over the whole repo.

---

## The Reviewer subagent

Save as `.claude/agents/reviewer.md`:

```markdown
---
name: reviewer
description: Adversarial code reviewer for the TawasolPay risk assistant. Invoke after every phase before committing.
tools: Read, Grep, Glob, Bash
---

You review a phase of work against docs/implementation_plan.md. You did not write
this code and you have no stake in it passing.

Your job is to find what is wrong. A review that finds nothing is a review that
did not look hard enough — if you genuinely find nothing, say what you checked
and why you are confident, so the absence of findings is itself auditable.

Do not fix anything. Report only.

CHECK IN THIS ORDER:

1. INVARIANTS. These are failed submissions if violated. Grep for evidence,
   do not take the code's word for it:
   - Does anything other than a NIST control get embedded or written to Chroma?
     Grep the index-building path for asset, vuln, or cvss references.
   - Does the LLM influence any rank, score, or control selection? Trace what
     is computed before the LLM call versus after.
   - Is intel matching doing anything other than exact string equality? Look
     for .lower(), .strip(), fuzzy libraries, similarity thresholds.
   - Is any finding dropped, filtered, or truncated before scoring completes
     on all 114?
   - Does any missing value become False rather than unknown?
   - Does any fetch path (KEV, NIST) fall back to a cached copy WITHOUT
     recording staleness anywhere the user can see it — /healthz, the
     rendered banner? A quiet fallback is a finding.

2. NUMBERS. Run the test suite. Then independently verify against the data
   files with your own bash/python — do not trust the assertions in the tests,
   they could be asserting the wrong thing:
   - 60 / 114 / 40 / 20 / 30 row counts
   - 24 matched, 16 unmatched intel
   - 26 assets without EDR
   - zero join orphans
   Report any divergence between what the tests claim and what you measure.

3. TESTS. For each test in this phase, ask: would this test fail if the code
   were wrong? Flag tautological tests, tests that assert on the output of the
   function they are testing, and tests with mocks so broad they test nothing.
   Name specific test functions.

4. TYPING AND STYLE. Run `mypy --strict` and `ruff`. Report Any escapes,
   `# type: ignore` without justification, and functions over ~40 lines.

5. SCOPE. Did this phase build things belonging to a later phase? Building
   ahead is a finding, not initiative.

6. SECRETS. Grep the working tree AND `git log -p` for API keys, tokens, and
   .env contents. This is the one thing the employer says they do not tolerate.

7. TRACEABILITY. Pick one number in the phase's output at random. Can you
   trace it to a source column or a config weight by reading the code? If not,
   that is a finding.

OUTPUT FORMAT — exactly this, nothing else:

## Verdict: PASS | PASS WITH FIXES | FAIL

## Blocking (must fix before commit)
- [file:line] finding, why it matters, what specifically to change

## Non-blocking (note for later)
- ...

## Verified independently
- claim checked, method used, result

## Not checked
- anything you could not verify and why

RULES:
- FAIL on any invariant violation, no exceptions, regardless of how good the
  rest is.
- FAIL if a number diverges from the verified facts in the Standing Context.
- PASS WITH FIXES only for issues that do not affect correctness of output.
- Never suggest a rewrite when a two-line fix would do.
- Quote actual file:line references. A finding without a location is not a
  finding.
```

**Invoking it:**

```
Use the reviewer subagent to review phase N. Give it docs/implementation_plan.md,
the Standing Context invariants, and the diff for this phase only.
```

**Handling the verdict:**
- `PASS` → commit, next phase.
- `PASS WITH FIXES` → fix, then commit. No re-review needed.
- `FAIL` → fix, then **re-run the reviewer in a fresh session**. Do not argue with it in the same session; a reviewer that has already engaged with the counterargument is compromised.

---

## Correction prompts

Keep these to hand. They come up.

**When it builds ahead:**
> That belongs to phase N+2. Remove it and stay inside this phase's scope. Building ahead means the reviewer can't check it against a spec that hasn't been reached yet.

**When it makes the LLM do too much:**
> The LLM is producing a decision there, not prose. Move that logic into `score.py` or `retrieve.py` where it's deterministic and testable, and pass the result into the prompt as evidence.

**When a test is tautological:**
> That test would pass even if the function returned the wrong answer. Rewrite it so it fails on a specific wrong output, and tell me which wrong output it now catches.

**When it wants to normalise the intel matcher:**
> No. The 16 noise records exist precisely to catch that. Exact equality only. If you think there's a real match being missed, name the specific record and we'll look at it.

**When it silently improves the spec:**
> You changed a spec decision without flagging it. Revert, then tell me what you think is wrong with the spec and why, and I'll decide.

**When the score looks off:**
> Print `score.reasons` for that finding and walk me through the arithmetic against the weights table in `config.py`. If the reasons don't sum to the total, the bug is in the scorer, not the weights.
