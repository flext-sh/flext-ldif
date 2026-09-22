"""Generated server exports resolve real parent-package imports."""

from __future__ import annotations

import importlib
import inspect

from flext_ldif import FlextLdifServersOidConstants, FlextLdifServersRfc


class TestsFlextLdifLazyServerExports:
    """Exercise the generated server namespace through its exported classes."""

    def test_oid_namespace_resolves_the_parent_rfc_export(self) -> None:
        """The generated parent-relative RFC export resolves to its public owner."""
        constants_module = inspect.getmodule(FlextLdifServersOidConstants)
        assert constants_module is not None
        package_name = constants_module.__package__
        assert package_name is not None
        server_namespace = importlib.import_module(package_name)
        assert (
            getattr(server_namespace, "fsr")
            is FlextLdifServersRfc
        )
