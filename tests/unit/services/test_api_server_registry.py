"""Behavioral tests for the LDIF facade server-registry public contract."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from flext_tests import tm

from tests import c, u

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdifApiServerRegistry:
    """Validate registry behavior through the public LDIF facade only."""

    def test_list_registered_servers_includes_core_server_types(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The facade exposes the real registered server catalog."""
        registered_servers = u.Tests.assert_success(
            api.list_registered_servers(),
            error_msg="registered servers must resolve from the facade",
        )
        tm.that(registered_servers, has=[c.Tests.RFC, c.Tests.OID, c.Tests.OUD])

    def test_base_server_resolution_returns_requested_server_type(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """Resolving a registered type yields a server whose type round-trips."""
        server = u.Tests.assert_success(
            api.resolve_base_server(c.Tests.OID),
            error_msg="OID server must resolve from the facade",
        )
        tm.that(server.server_type, eq=c.Tests.OID)

    def test_component_lookups_succeed_for_registered_server_type(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """Schema, ACL, and entry component lookups succeed for a real type."""
        tm.ok(api.schema_server(c.Tests.OID))
        tm.ok(api.acl(c.Tests.OID))
        tm.ok(api.entry(c.Tests.OID))

    def test_server_bundle_exposes_component_contract(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The resolved bundle exposes schema/acl/entry component keys."""
        server_bundle = u.Tests.assert_success(
            api.resolve_server_bundle(c.Tests.OUD),
            error_msg="OUD server bundle must resolve from the facade",
        )
        tm.that(server_bundle, has=["schema", "acl", "entry"])

    def test_server_constants_expose_categorization_priority(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """Resolved server constants publish the categorization priority contract."""
        constants = u.Tests.assert_success(
            api.resolve_server_constants(c.Tests.OUD),
            error_msg="OUD constants must resolve from the facade",
        )
        tm.that(constants.CATEGORIZATION_PRIORITY, none=False)

    def test_registry_summary_exposes_statistics_contract(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """The registry summary publishes per-server and priority statistics."""
        stats = u.Tests.assert_success(
            api.summarize_registry(),
            error_msg="registry summary must resolve from the facade",
        )
        tm.that(stats, has=["servers_by_server", "server_priorities"])

    def test_invalid_server_type_fails_every_resolution_endpoint(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        """A syntactically invalid identifier fails gracefully on all endpoints."""
        invalid = c.Tests.SERVER_INVALID_SERVER_TYPE
        tm.fail(api.acl(invalid))
        tm.fail(api.entry(invalid))
        tm.fail(api.schema_server(invalid))
        tm.fail(api.resolve_schema_server(invalid))
        tm.fail(api.resolve_base_server(invalid))
        tm.fail(api.resolve_server_bundle(invalid))
        tm.fail(api.resolve_server_constants(invalid))

    @pytest.mark.parametrize(
        "resolver_name",
        [
            "resolve_base_server",
            "resolve_server_bundle",
            "resolve_server_constants",
        ],
    )
    def test_valid_but_unregistered_server_type_fails_lookup(
        self,
        api: p.Ldif.LdifClient,
        resolver_name: str,
    ) -> None:
        """A valid-but-unregistered type fails gracefully on each resolver."""
        resolver = getattr(api, resolver_name)
        tm.fail(resolver(c.Tests.GENERIC))
