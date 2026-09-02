"""Build-time warm-up (§8 deploy) — run during ``docker build``, not at runtime.

Fetches the NIST catalog and the CISA KEV feed and builds the Chroma control index
so the deployed container starts with a warm index and no cold-start embedding pass.
Populating ``cache/`` here also gives the running service a fallback copy of each
external document if a startup live-fetch fails.

Explicitly NOT the LLM path: this never calls Groq, so ``GROQ_API_KEY`` is neither
needed nor present at build time — the secret stays out of the image entirely.
"""

from __future__ import annotations

import sys

from riskagent.ingest.kev import load_kev
from riskagent.ingest.nist import load_catalog
from riskagent.rag.index import ChromaControlStore


def main() -> int:
    catalog = load_catalog()  # live fetch; writes cache/nist_sp800-53r5.json
    store = ChromaControlStore()
    store.build(catalog.controls, catalog_sha256=catalog.catalog_sha256)
    kev = load_kev()  # live fetch; writes cache/kev.json as a startup fallback
    kev_note = f"{len(kev.by_cve)} entries ({kev.source})" if kev is not None else "unavailable"
    print(
        f"prewarm: chroma_rows={store.count()} "
        f"nist={catalog.catalog_version!r} sha={catalog.catalog_sha256[:12]} "
        f"kev={kev_note}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
