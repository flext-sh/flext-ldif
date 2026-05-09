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
        tm.that(registered_servers, has=[c.Tests.RFC, c.Tests.OID, c.Tests.OUD])

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
        tm.ok(api.schema_server(c.Tests.OID))
        tm.ok(api.acl(c.Tests.OID))
        tm.ok(api.entry(c.Tests.OID))

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
        tm.that(server_bundle, has=["schema", "acl", "entry"])
        tm.that(getattr(constants, "CATEGORIZATION_PRIORITY", None), none=False)
        tm.that(stats, has=["servers_by_server", "server_priorities"])

    def test_invalid_server_type_returns_public_failures(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """Invalid server identifiers should fail gracefully via public APIs."""
        invalid = c.Tests.SERVER_INVALID_SERVER_TYPE
        tm.fail(api.acl(invalid))
        tm.fail(api.entry(invalid))
        tm.fail(api.schema_server(invalid))
        tm.fail(api.resolve_schema_server(invalid))
        tm.fail(api.resolve_base_server(invalid))
        tm.fail(api.resolve_server_bundle(invalid))
        tm.fail(api.resolve_server_constants(invalid))

    def test_valid_but_unregistered_server_type_fails_lookup(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A valid normalized type without registered server should fail gracefully."""
        unregistered = c.Tests.GENERIC
        tm.fail(api.resolve_base_server(unregistered))
        tm.fail(api.resolve_server_bundle(unregistered))
        tm.fail(api.resolve_server_constants(unregistered))
