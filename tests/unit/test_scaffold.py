"""Step 0 smoke test: the workspace is installed and importable.

Exists so `pytest` has something to collect at step 0 (an empty run exits 5, not 0)
and so a broken editable install fails loudly rather than at the first real test.
"""

import importlib

import pytest

WORKSPACE_PACKAGES = ["rlapi", "rlas", "rlmcp"]


@pytest.mark.parametrize("name", WORKSPACE_PACKAGES)
def test_package_is_importable(name: str) -> None:
    module = importlib.import_module(name)
    assert module.__version__ == "0.0.0"


@pytest.mark.parametrize("name", WORKSPACE_PACKAGES)
def test_package_is_installed_from_source_tree(name: str) -> None:
    """Guard against a stale wheel shadowing the editable install."""
    module = importlib.import_module(name)
    assert module.__file__ is not None
    assert f"packages/{name}/src/{name}" in module.__file__
