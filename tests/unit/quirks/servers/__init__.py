# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Servers package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import tests.unit.quirks.servers.test_apache_quirks as _tests_unit_quirks_servers_test_apache_quirks

    test_apache_quirks = _tests_unit_quirks_servers_test_apache_quirks
    import tests.unit.quirks.servers.test_ds389_quirks as _tests_unit_quirks_servers_test_ds389_quirks

    test_ds389_quirks = _tests_unit_quirks_servers_test_ds389_quirks
    import tests.unit.quirks.servers.test_edge_cases as _tests_unit_quirks_servers_test_edge_cases

    test_edge_cases = _tests_unit_quirks_servers_test_edge_cases
    import tests.unit.quirks.servers.test_novell_quirks as _tests_unit_quirks_servers_test_novell_quirks

    test_novell_quirks = _tests_unit_quirks_servers_test_novell_quirks
    import tests.unit.quirks.servers.test_oid_quirks as _tests_unit_quirks_servers_test_oid_quirks

    test_oid_quirks = _tests_unit_quirks_servers_test_oid_quirks
    import tests.unit.quirks.servers.test_relaxed_quirks as _tests_unit_quirks_servers_test_relaxed_quirks

    test_relaxed_quirks = _tests_unit_quirks_servers_test_relaxed_quirks
    import tests.unit.quirks.servers.test_schema_transformer as _tests_unit_quirks_servers_test_schema_transformer

    test_schema_transformer = _tests_unit_quirks_servers_test_schema_transformer
    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = {
    "c": ("flext_core.constants", "FlextConstants"),
    "d": ("flext_core.decorators", "FlextDecorators"),
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "s": ("flext_core.service", "FlextService"),
    "t": ("flext_core.typings", "FlextTypes"),
    "test_apache_quirks": "tests.unit.quirks.servers.test_apache_quirks",
    "test_ds389_quirks": "tests.unit.quirks.servers.test_ds389_quirks",
    "test_edge_cases": "tests.unit.quirks.servers.test_edge_cases",
    "test_novell_quirks": "tests.unit.quirks.servers.test_novell_quirks",
    "test_oid_quirks": "tests.unit.quirks.servers.test_oid_quirks",
    "test_relaxed_quirks": "tests.unit.quirks.servers.test_relaxed_quirks",
    "test_schema_transformer": "tests.unit.quirks.servers.test_schema_transformer",
    "u": ("flext_core.utilities", "FlextUtilities"),
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "test_apache_quirks",
    "test_ds389_quirks",
    "test_edge_cases",
    "test_novell_quirks",
    "test_oid_quirks",
    "test_relaxed_quirks",
    "test_schema_transformer",
    "u",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)
