# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Support package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "conftest_factory": "tests.support.conftest_factory",
    "ldif_data": "tests.support.ldif_data",
    "test_files": "tests.support.test_files",
    "validators": "tests.support.validators",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
