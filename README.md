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
<!-- TODO(phase-8): blind-tier methodology sentence — "Pairs involving findings
     already observed in scorer output are marked blind: false and reported separately,
     since prior exposure to the ranking compromises independence." Report blind and
     post-hoc pairwise rates separately; blind is the headline. -->

## Data freshness

<!-- KEV + NIST fetched live, staleness check, catalog version, all checkable at /healthz -->
<!-- TODO(phase-8): one line — recency is scored against a FIXED reference date
     (config.REFERENCE_DATE = 2026-04-24, the freshest intel date) for reproducibility,
     so scores don't drift as the wall clock moves past the synthetic dataset. -->
