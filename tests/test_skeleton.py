"""Placeholder so `pytest` has something to collect before v0.1's real
test suite lands. Each module currently raises NotImplementedError; this
test documents that fact so it fails loudly (not silently) if a module is
later imported successfully without anyone updating this file.
"""

from __future__ import annotations

import importlib

import pytest

_SKELETON_MODULES = [
    "custody.catalog",
    "custody.policy",
    "custody.approvals",
    "custody.audit",
    "custody.sandbox",
    "custody.tools",
    "custody.guard",
    "custody.routing",
]


@pytest.mark.parametrize("module_name", _SKELETON_MODULES)
def test_skeleton_module_not_yet_implemented(module_name: str) -> None:
    with pytest.raises(NotImplementedError):
        importlib.import_module(module_name)
