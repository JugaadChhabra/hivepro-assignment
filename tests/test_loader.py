"""Phase 1 loader tests (§3).

Every assertion is against a fact that would break if the loader silently
defaulted, coerced wrongly, or dropped a row.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from riskagent.ingest.csv_loader import (
    DataBundle,
    SchemaError,
    load_all,
    load_assets,
    load_vulnerabilities,
)

_ASSET_HEADER = (
    "asset_id,asset_name,asset_type,environment,owner_team,business_service,"
    "internet_exposed,criticality,data_classification,edr_installed,last_seen_days,"
    "location,vendor_product"
)
# A well-formed asset row, used as a template for malformed-row fixtures.
_GOOD_ASSET_ROW = (
    "A-9999,test-box,Web Server,Production,Blue Team,Customer Login,Yes,Critical,"
    "Customer PII,No,3,UAE,nginx 1.22 / Ubuntu 22.04"
)


@pytest.fixture(scope="module")
def bundle() -> DataBundle:
    return load_all()


def test_exact_row_counts(bundle: DataBundle) -> None:
    assert len(bundle.assets) == 60
    assert len(bundle.vulnerabilities) == 114
    assert len(bundle.intel) == 40
    assert len(bundle.services) == 20
    assert len(bundle.guidance) == 30


def test_blank_owner_team_becomes_none(bundle: DataBundle) -> None:
    blank = [a for a in bundle.assets if a.owner_team is None]
    assert [a.asset_id for a in blank] == ["A-1059"]  # exactly this row is blank
    # a populated owner_team is carried through verbatim (not None, not "")
    a1001 = next(a for a in bundle.assets if a.asset_id == "A-1001")
    assert a1001.owner_team == "Identity Team"


def test_bool_fields_are_real_bools(bundle: DataBundle) -> None:
    for a in bundle.assets:
        assert type(a.internet_exposed) is bool
        assert type(a.edr_installed) is bool
    for v in bundle.vulnerabilities:
        assert type(v.exploit_available) is bool
        assert type(v.patch_available) is bool
        assert type(v.auth_required) is bool
    for t in bundle.intel:
        assert type(t.ransomware_association) is bool
    for s in bundle.services:
        assert type(s.customer_facing) is bool


def test_cvss_is_float_in_range(bundle: DataBundle) -> None:
    for v in bundle.vulnerabilities:
        assert type(v.cvss) is float
        assert 0.0 <= v.cvss <= 10.0


def test_malformed_row_wrong_field_count_raises(tmp_path: Path) -> None:
    # 12 fields instead of 13 — a dropped column must raise, not shift/default.
    bad = tmp_path / "assets.csv"
    short_row = ",".join(_GOOD_ASSET_ROW.split(",")[:-1])
    bad.write_text(f"{_ASSET_HEADER}\n{short_row}\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_assets(bad)


def test_malformed_bad_enum_raises(tmp_path: Path) -> None:
    # 'Prod' is not a valid environment Literal — pydantic must reject it.
    bad = tmp_path / "assets.csv"
    row = _GOOD_ASSET_ROW.replace("Production", "Prod")
    bad.write_text(f"{_ASSET_HEADER}\n{row}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_assets(bad)


def test_malformed_bad_bool_raises(tmp_path: Path) -> None:
    # 'True' is not 'Yes'/'No' — the coercion must raise rather than default False.
    bad = tmp_path / "assets.csv"
    row = _GOOD_ASSET_ROW.replace(",Yes,", ",True,")
    bad.write_text(f"{_ASSET_HEADER}\n{row}\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_assets(bad)


def test_blank_required_string_raises(tmp_path: Path) -> None:
    # A blank in a required (non-optional) column is schema drift, not a default.
    # data_classification has no reason to be empty — it must fail loudly.
    bad = tmp_path / "assets.csv"
    row = _GOOD_ASSET_ROW.replace(",Customer PII,", ",,")
    bad.write_text(f"{_ASSET_HEADER}\n{row}\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_assets(bad)


def test_header_drift_raises(tmp_path: Path) -> None:
    # A renamed column is schema drift — do not default the missing one.
    bad = tmp_path / "vulnerabilities.csv"
    bad.write_text("vuln_id,asset_id\nV-1,A-1\n", encoding="utf-8")
    with pytest.raises(SchemaError):
        load_vulnerabilities(bad)


def test_load_is_idempotent() -> None:
    assert load_all() == load_all()
