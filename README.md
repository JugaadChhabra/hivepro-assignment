# TawasolPay Cyber Risk Assistant

<!-- Stub. Section headings only (from §9 of implementation_plan.md); prose is
     written in phase 8 in the author's voice, with real numbers from eval.py. -->

## Supporting question 1 — the data split

<!-- structured vs embedded; name the ambiguous cases and how they were resolved -->

## Supporting question 2 — three failure modes

<!-- three data-grounded failure modes, each with its concrete mitigation + file ref -->

## Supporting question 3 — one thing to change

<!-- semantic intel matching as a separate confirmed/possible channel; why precision for v1 -->
<!-- TODO(phase-8): consider the STRONGER candidate surfaced in phase 3 — the scorer
     models business impact per-service, not blast radius, so initial-access pivot
     assets (vpn-edge / Remote Access, customer_facing No) are under-weighted even
     though a VPN compromise is the pivot to everything else. Decide which of the two
     is the supporting-Q3 answer once the golden set adjudicates the Fortinet ranking. -->

## Architecture

<!-- diagram -->

## Make commands

<!-- make install / lint / test / run / eval -->

## Weights table

<!-- weights with provenance in the MDR analyst notes -->

## Evaluation

<!-- current eval numbers; one-annotator caveat on the golden set -->

<!-- PHASE-6b MEASURED RECORD (data for phase-8 prose; one change, one eval run,
     one recorded delta — never batched). Headline = non-contested pairwise. -->

| Step | Change | Headline pairwise | Δ | What moved |
|------|--------|-------------------|---|------------|
| baseline | phase-6 as committed | 0.600 (3/5) | — | P03, P09 fail |
| Change 1 | `rto_hours` in Business group (P11) | 0.600 (3/5) | +0.000 | no flip; strengthens source pair P11 (+1.6→+5.6), tightens P03 (−2.4→−0.4) and P09 (−4.0→−1.0) |
| Change 2 | recovery-infrastructure blast-radius term (P04/P09) | 0.800 (4/5) | **+0.200** | flips **P09** (−1.0→+5.0): DR-failover site scored as top-tier fan-out despite 0 dependents |
| Change 3 | staleness decision: keep §4, retire P10 | 0.800 (4/5) | +0.000 | P10 was contested (not headline); resolves a §4-vs-golden contradiction, contested 7→6 pairs |

precision@5 held at **1.000** across all three steps (blind: false, secondary — not tuned toward). CI regression floor (`config.EVAL_PAIRWISE_FLOOR`) raised 0.6 → 0.8.

**Remaining documented gap:** P03 (−0.4) — an internet-exposed finding with no intel loses to an internal-only finding carrying an active-exploitation ransomware campaign (+23 adversary). Closing it needs an "internal-only discounts a live campaign" signal that the phase-6b scope explicitly declined to add. An honest 0.80 with one named gap, not an engineered 0.90.

<!-- TODO(phase-8): blind-tier methodology sentence — "Pairs involving findings
     already observed in scorer output are marked blind: false and reported separately,
     since prior exposure to the ranking compromises independence." Report blind and
     post-hoc pairwise rates separately; blind is the headline. -->

## Data freshness

<!-- KEV + NIST fetched live, staleness check, catalog version, all checkable at /healthz -->
<!-- TODO(phase-8): one line — recency is scored against a FIXED reference date
     (config.REFERENCE_DATE = 2026-04-24, the freshest intel date) for reproducibility,
     so scores don't drift as the wall clock moves past the synthetic dataset. -->
