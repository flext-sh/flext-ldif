"""Generated server exports resolve real parent-package imports."""

from __future__ import annotations

import importlib
import inspect

from flext_ldif import FlextLdifServersOid, FlextLdifServersRfc


class TestsFlextLdifLazyServerExports:
    """Exercise the generated server namespace through its exported classes."""

    def test_server_namespace_resolves_oid_and_rfc_owners(self) -> None:
        """The public server package exports canonical classes, not private aliases."""
        oid_module = inspect.getmodule(FlextLdifServersOid)
        assert oid_module is not None
        package_name = oid_module.__package__
        assert package_name is not None
        server_namespace = importlib.import_module(package_name)
        assert server_namespace.FlextLdifServersOid is FlextLdifServersOid
        assert server_namespace.FlextLdifServersRfc is FlextLdifServersRfc
