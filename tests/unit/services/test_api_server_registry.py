"""Public facade tests for LDIF server registry access."""

from __future__ import annotations

from flext_tests import tm

from tests import c, p, u


class TestsTestFlextLdifApiServerRegistry:
    """Validate registry behavior through the public LDIF facade."""

    def test_list_registered_servers_includes_core_server_types(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The facade should expose the real registered server catalog."""
        registered_servers = u.Tests.assert_success(
            api.list_registered_servers(),
            error_msg="registered servers must resolve from the facade",
        )

        tm.that(c.Tests.RFC in registered_servers, eq=True)
        tm.that(c.Tests.OID in registered_servers, eq=True)
        tm.that(c.Tests.OUD in registered_servers, eq=True)

    def test_server_resolution_returns_real_registered_server(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The facade should resolve the real server registry entry by type."""
        server = u.Tests.assert_success(
            api.resolve_base_server(c.Tests.OID),
            error_msg="OID server must resolve from the facade",
        )

        tm.that(server.server_type, eq=c.Tests.OID)
        base_server = u.Tests.assert_success(
            api.resolve_base_server(c.Tests.OID),
            error_msg="OID base server must resolve from the facade",
        )
        tm.that(base_server.server_type, eq=c.Tests.OID)
        tm.that(api.schema_server(c.Tests.OID).success, eq=True)
        tm.that(api.acl(c.Tests.OID).success, eq=True)
        tm.that(api.entry(c.Tests.OID).success, eq=True)

    def test_registry_resolution_exposes_public_registry_contract(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The facade should expose the same registry metadata as the server API."""
        server_bundle = u.Tests.assert_success(
            api.resolve_server_bundle(c.Tests.OUD),
            error_msg="OUD server bundle must resolve from the facade",
        )
        constants = u.Tests.assert_success(
            api.resolve_server_constants(c.Tests.OUD),
            error_msg="OUD constants must resolve from the facade",
        )
        stats = u.Tests.assert_success(
            api.summarize_registry(),
            error_msg="registry summary must resolve from the facade",
        )

        tm.that("schema" in server_bundle, eq=True)
        tm.that("acl" in server_bundle, eq=True)
        tm.that("entry" in server_bundle, eq=True)
        tm.that(getattr(constants, "CATEGORIZATION_PRIORITY", None), none=False)
        tm.that("servers_by_server" in stats, eq=True)
        tm.that("server_priorities" in stats, eq=True)

    def test_invalid_server_type_returns_public_failures(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """Invalid server identifiers should fail gracefully via public APIs."""
        invalid_server = c.Tests.SERVER_INVALID_SERVER_TYPE

        tm.that(api.acl(invalid_server).failure, eq=True)
        tm.that(api.entry(invalid_server).failure, eq=True)
        tm.that(api.schema_server(invalid_server).failure, eq=True)
        tm.that(api.resolve_schema_server(invalid_server).failure, eq=True)

        server_result = api.resolve_base_server(invalid_server)
        bundle_result = api.resolve_server_bundle(invalid_server)
        constants_result = api.resolve_server_constants(invalid_server)

        tm.that(server_result.failure, eq=True)
        tm.that(bundle_result.failure, eq=True)
        tm.that(constants_result.failure, eq=True)

    def test_valid_but_unregistered_server_type_fails_lookup(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A valid normalized type without registered server should fail gracefully."""
        valid_unregistered_server = c.Tests.GENERIC

        server_result = api.resolve_base_server(valid_unregistered_server)
        base_result = api.resolve_base_server(valid_unregistered_server)
        bundle_result = api.resolve_server_bundle(valid_unregistered_server)
        constants_result = api.resolve_server_constants(valid_unregistered_server)

        tm.that(server_result.failure, eq=True)
        tm.that(base_result.failure, eq=True)
        tm.that(bundle_result.failure, eq=True)
        tm.that(constants_result.failure, eq=True)
