# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "test_apache_quirks": "tests.unit.quirks.servers.test_apache_quirks",
    "test_ds389_quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "test_edge_cases": "tests.unit.quirks.servers.test_edge_cases",
    "test_novell_quirks": "tests.unit.quirks.servers.test_novell_quirks",
    "test_oid_quirks": "tests.unit.quirks.servers.test_oid_quirks",
    "test_relaxed_quirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "test_schema_transformer": "tests.unit.quirks.servers.test_schema_transformer",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)
