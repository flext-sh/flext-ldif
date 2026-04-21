"""Public facade tests for LDIF server registry access."""

from __future__ import annotations

from flext_tests import tm

from flext_ldif import FlextLdif
from tests import c, u


class TestsTestFlextLdifApiServerRegistry:
    """Validate registry behavior through the public LDIF facade."""

    def test_list_registered_servers_includes_core_server_types(
        self,
        api: FlextLdif,
    ) -> None:
        """The facade should expose the real registered server catalog."""
        registered_servers = api.list_registered_servers()

        tm.that(c.Ldif.Tests.RFC in registered_servers, eq=True)
        tm.that(c.Ldif.Tests.OID in registered_servers, eq=True)
        tm.that(c.Ldif.Tests.OUD in registered_servers, eq=True)

    def test_quirk_resolution_returns_real_registered_server(
        self,
        api: FlextLdif,
    ) -> None:
        """The facade should resolve the real quirk registry entry by type."""
        quirk = u.Tests.assert_success(
            api.quirk(c.Ldif.Tests.OID),
            error_msg="OID quirk must resolve from the facade",
        )

        tm.that(quirk.server_type, eq=c.Ldif.Tests.OID)
        tm.that(api.schema_quirk(c.Ldif.Tests.OID), none=False)
        tm.that(api.acl(c.Ldif.Tests.OID), none=False)
        tm.that(api.entry(c.Ldif.Tests.OID), none=False)

    def test_get_all_quirks_and_constants_expose_public_registry_contract(
        self,
        api: FlextLdif,
    ) -> None:
        """The facade should expose the same registry metadata as the server API."""
        quirk_bundle = u.Tests.assert_success(
            api.get_all_quirks(c.Ldif.Tests.OUD),
            error_msg="OUD quirk bundle must resolve from the facade",
        )
        constants = u.Tests.assert_success(
            api.get_constants(c.Ldif.Tests.OUD),
            error_msg="OUD constants must resolve from the facade",
        )
        stats = api.get_registry_stats()

        tm.that("schema" in quirk_bundle, eq=True)
        tm.that("acl" in quirk_bundle, eq=True)
        tm.that("entry" in quirk_bundle, eq=True)
        tm.that(getattr(constants, "CATEGORIZATION_PRIORITY", None), none=False)
        tm.that("quirks_by_server" in stats, eq=True)
        tm.that("server_priorities" in stats, eq=True)
