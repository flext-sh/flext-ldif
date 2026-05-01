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

        tm.that(c.Tests.RFC in registered_servers, eq=True)
        tm.that(c.Tests.OID in registered_servers, eq=True)
        tm.that(c.Tests.OUD in registered_servers, eq=True)

    def test_quirk_resolution_returns_real_registered_server(
        self,
        api: FlextLdif,
    ) -> None:
        """The facade should resolve the real quirk registry entry by type."""
        quirk = u.Tests.assert_success(
            api.quirk(c.Tests.OID),
            error_msg="OID quirk must resolve from the facade",
        )

        tm.that(quirk.server_type, eq=c.Tests.OID)
        base_quirk = u.Tests.assert_success(
            api.resolve_base_quirk(c.Tests.OID),
            error_msg="OID base quirk must resolve from the facade",
        )
        tm.that(base_quirk.server_type, eq=c.Tests.OID)
        tm.that(api.schema_quirk(c.Tests.OID), none=False)
        tm.that(api.acl(c.Tests.OID), none=False)
        tm.that(api.entry(c.Tests.OID), none=False)

    def test_registry_resolution_exposes_public_registry_contract(
        self,
        api: FlextLdif,
    ) -> None:
        """The facade should expose the same registry metadata as the server API."""
        quirk_bundle = u.Tests.assert_success(
            api.resolve_quirk_bundle(c.Tests.OUD),
            error_msg="OUD quirk bundle must resolve from the facade",
        )
        constants = u.Tests.assert_success(
            api.resolve_server_constants(c.Tests.OUD),
            error_msg="OUD constants must resolve from the facade",
        )
        stats = api.summarize_registry()

        tm.that("schema" in quirk_bundle, eq=True)
        tm.that("acl" in quirk_bundle, eq=True)
        tm.that("entry" in quirk_bundle, eq=True)
        tm.that(getattr(constants, "CATEGORIZATION_PRIORITY", None), none=False)
        tm.that("quirks_by_server" in stats, eq=True)
        tm.that("server_priorities" in stats, eq=True)

    def test_invalid_server_type_returns_public_failures(
        self,
        api: FlextLdif,
    ) -> None:
        """Invalid server identifiers should fail gracefully via public APIs."""
        invalid_server = c.Tests.SERVER_INVALID_QUIRK_TYPE

        tm.that(api.acl(invalid_server), eq=None)
        tm.that(api.entry(invalid_server), eq=None)
        tm.that(api.schema_quirk(invalid_server), eq=None)
        tm.that(api.resolve_schema_quirk(invalid_server), eq=None)

        quirk_result = api.quirk(invalid_server)
        bundle_result = api.resolve_quirk_bundle(invalid_server)
        constants_result = api.resolve_server_constants(invalid_server)

        tm.that(quirk_result.failure, eq=True)
        tm.that(bundle_result.failure, eq=True)
        tm.that(constants_result.failure, eq=True)

    def test_valid_but_unregistered_server_type_fails_lookup(
        self,
        api: FlextLdif,
    ) -> None:
        """A valid normalized type without registered quirk should fail gracefully."""
        valid_unregistered_server = c.Tests.GENERIC

        quirk_result = api.quirk(valid_unregistered_server)
        base_result = api.resolve_base_quirk(valid_unregistered_server)
        bundle_result = api.resolve_quirk_bundle(valid_unregistered_server)
        constants_result = api.resolve_server_constants(valid_unregistered_server)

        tm.that(quirk_result.failure, eq=True)
        tm.that(base_result.failure, eq=True)
        tm.that(bundle_result.failure, eq=True)
        tm.that(constants_result.failure, eq=True)
