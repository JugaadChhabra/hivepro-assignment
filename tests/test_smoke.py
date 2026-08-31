"""Smoke test so CI runs green on the empty skeleton.

Replaced/expanded by real tests starting in phase 1. Its only job here is to
prove the package imports and that the test toolchain is wired up.
"""

import importlib


def test_package_imports() -> None:
    assert importlib.import_module("riskagent") is not None
