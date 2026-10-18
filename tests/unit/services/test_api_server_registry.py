"""Behavioral tests for the LDIF facade server-registry public contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_ldif import FlextLdif, ldif
from flext_ldif.services import FlextLdifServer
from tests import c, m, tm, u

if TYPE_CHECKING:
    from tests import p


class TestsFlextLdifApiServerRegistry:
    """Validate registry behavior through the public LDIF facade only."""

    @staticmethod
    def test_list_registered_servers_includes_core_server_types(
        api: p.Ldif.LdifClient,
    ) -> None:
        """The facade exposes the real registered server catalog."""
        registered_servers = u.Tests.assert_success(
            api.list_registered_servers(),
            error_msg="registered servers must resolve from the facade",
        )
        tm.that(registered_servers, has=[c.Tests.RFC, c.Tests.OID, c.Tests.OUD])

    @staticmethod
    def test_base_server_resolution_returns_requested_server_type(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Resolving a registered type yields a server whose type round-trips."""
        server = u.Tests.assert_success(
            api.resolve_base_server(c.Tests.OID),
            error_msg="OID server must resolve from the facade",
        )
        tm.that(server.server_type, eq=c.Tests.OID)

    @staticmethod
    def test_component_lookups_succeed_for_registered_server_type(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Schema, ACL, and entry component lookups succeed for a real type."""
        tm.ok(api.schema_server(c.Tests.OID))
        tm.ok(api.acl(c.Tests.OID))
        tm.ok(api.entry(c.Tests.OID))

    @staticmethod
    def test_server_bundle_exposes_component_contract(
        api: p.Ldif.LdifClient,
    ) -> None:
        """The resolved bundle exposes schema/acl/entry component keys."""
        server_bundle = u.Tests.assert_success(
            api.resolve_server_bundle(c.Tests.OUD),
            error_msg="OUD server bundle must resolve from the facade",
        )
        tm.that(server_bundle, has=["schema", "acl", "entry"])

    @staticmethod
    def test_server_constants_expose_categorization_priority(
        api: p.Ldif.LdifClient,
    ) -> None:
        """Resolved server constants publish the categorization priority contract."""
        constants = u.Tests.assert_success(
            api.resolve_server_constants(c.Tests.OUD),
            error_msg="OUD constants must resolve from the facade",
        )
        tm.that(constants.CATEGORIZATION_PRIORITY, none=False)

    @staticmethod
    def test_registry_summary_exposes_statistics_contract(
        api: p.Ldif.LdifClient,
    ) -> None:
        """The registry summary publishes per-server and priority statistics."""
        stats = u.Tests.assert_success(
            api.summarize_registry(),
            error_msg="registry summary must resolve from the facade",
        )
        tm.that(stats, has=["servers_by_server", "server_priorities"])

    @staticmethod
    def test_invalid_server_type_fails_every_resolution_endpoint(
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

    @staticmethod
    @pytest.mark.parametrize(
        "resolver_name",
        ["resolve_base_server", "resolve_server_bundle", "resolve_server_constants"],
    )
    def test_valid_but_unregistered_server_type_fails_lookup(
        api: p.Ldif.LdifClient,
        resolver_name: str,
    ) -> None:
        """A valid-but-unregistered type fails gracefully on each resolver."""
        resolver = getattr(api, resolver_name)
        tm.fail(resolver(c.Tests.GENERIC))

    @staticmethod
    def test_independent_apis_and_callable_facades_isolate_removals() -> None:
        """Only explicit core-registry injection shares mutable dialect state."""
        first = FlextLdif()
        second = FlextLdif()
        callable_api = ldif()
        route = c.Ldif.ServerTypes.RFC.value
        tm.ok(first.unregister_server(route))
        tm.fail(first.resolve_base_server(route))
        tm.ok(second.resolve_base_server(route))
        tm.ok(callable_api.resolve_base_server(route))

    @staticmethod
    def test_explicit_registry_shares_identity_and_remove_reregister() -> None:
        """Sharing is intentional and removal frees the canonical core key."""
        first = FlextLdif()
        registry = first.registry
        second = FlextLdif(registry=registry)
        route = c.Ldif.ServerTypes.RFC.value
        original = first.resolve_base_server(route).unwrap()
        tm.that(second.resolve_base_server(route).unwrap() is original)
        tm.ok(first.register_server(original))
        tm.ok(first.unregister_server(route))
        tm.fail(second.resolve_base_server(route))
        tm.fail(FlextLdif(registry=registry).resolve_base_server(route))
        replacement = type(original)()
        tm.ok(first.register_server(replacement))
        tm.that(second.resolve_base_server(route).unwrap() is replacement)
        tm.fail(second.register_server(original))
        tm.that(first.resolve_base_server(route).unwrap() is replacement)

    @staticmethod
    def test_registered_dialect_is_original_core_payload() -> None:
        """The public facade and core registry return the same dialect object."""
        api = FlextLdif()
        registry = api.registry
        route = c.Ldif.ServerTypes.OID.value
        dialect = api.resolve_base_server(route).unwrap()
        stored = registry.fetch_plugin(c.Ldif.SERVERS, route).unwrap()
        tm.that(stored is dialect)

    @staticmethod
    def test_required_registry_port_is_validated_and_not_serialized() -> None:
        """Services cannot construct infrastructure or accept a loose payload."""
        with pytest.raises(ValueError):
            FlextLdifServer.model_validate({})
        with pytest.raises(ValueError):
            m.Ldif.RegistryPortOptions.model_validate({"registry": m.Ldif.Statistics()})
        registry = u.build_registry()
        ports = m.Ldif.RegistryPortOptions(registry=registry)
        tm.that(ports.registry is registry)
        tm.that("registry" not in ports.model_dump())
        tm.that("registry" not in ports.model_json_schema().get("properties", {}))
        with pytest.raises(ValueError):
            ports.__setattr__("registry", m.Ldif.Statistics())
        tm.that(ports.registry is registry)

    @staticmethod
    def test_incompatible_stored_payload_fails_lookup_without_fallback() -> None:
        """An invalid stored dialect never causes a fresh dialect to be built."""
        registry = u.build_registry()
        route = c.Ldif.ServerTypes.RFC.value
        payload = m.Ldif.Statistics()
        tm.ok(registry.register_plugin(c.Ldif.SERVERS, route, payload))
        service = FlextLdifServer(registry=registry)
        tm.fail(service.resolve_base_server(route))
        tm.fail(service.resolve_server_bundle(route))
        tm.fail(service.summarize_registry())
        tm.that(registry.fetch_plugin(c.Ldif.SERVERS, route).unwrap() is payload)

    @staticmethod
    def test_real_dialect_parse_write_roundtrip_and_removal_failure() -> None:
        """Registry composition retains the real RFC parse/write implementation."""
        api = FlextLdif()
        route = c.Ldif.ServerTypes.RFC.value
        source = "dn: cn=person,dc=example,dc=com\nobjectClass: person\ncn: person\nsn: example\n"
        parsed = api.parse_string(source, server_type=route).unwrap()
        written = api.write_to_string(
            u.Ldif.as_entries(parsed.entries),
            server_type=route,
        ).unwrap()
        reparsed = api.parse_string(written, server_type=route).unwrap()
        tm.that(len(reparsed.entries), eq=len(parsed.entries))
        tm.that(reparsed.entries[0].dn, eq=parsed.entries[0].dn)
        tm.ok(api.unregister_server(route))
        tm.fail(api.parse_string(source, server_type=route))
        tm.fail(
            api.write_to_string(u.Ldif.as_entries(parsed.entries), server_type=route)
        )

    @staticmethod
    def test_transformer_mro_and_pipeline_forwarding_use_the_facade_graph() -> None:
        """Constructor migration retains real transformation and entry input."""
        api = FlextLdif(
            source_server=c.Ldif.ServerTypes.RFC,
            target_server=c.Ldif.ServerTypes.RFC,
        )
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"objectClass": ["top"], "cn": ["identity"]},
        )
        converted = api.apply(entry).unwrap()
        tm.that(converted.dn, eq=entry.dn)
        tm.that(converted.attributes, eq=entry.attributes)
        pipeline = api.processing_pipeline(
            transform_config=None,
            entries_input=[entry],
            runtime_settings=api.settings,
        )
        tm.ok(pipeline.execute())
        migration = api.migration_pipeline(runtime_settings=api.settings)
        tm.fail(migration.execute(), has="input_dir")

    @staticmethod
    def test_oud_schema_write_uses_explicit_registry_not_other_apis() -> None:
        """Cross-dialect schema writes cannot consult a hidden process registry."""
        api = FlextLdif()
        independent = FlextLdif()
        source_route = c.Ldif.ServerTypes.OID.value
        target_route = c.Ldif.ServerTypes.OUD.value
        content = (
            "dn: cn=schema\nchangetype: modify\nadd: attributeTypes\n"
            "attributeTypes: ( 1.2.3.4 NAME 'exampleAttr' "
            "SYNTAX '1.3.6.1.4.1.1466.115.121.1.15' )\n-\n"
        )
        parsed = api.parse_string(content, server_type=source_route).unwrap()
        entries = u.Ldif.as_entries(parsed.entries)
        written = api.write_to_string(entries, server_type=target_route)
        tm.ok(written)
        tm.that("SYNTAX 1.3.6.1.4.1.1466.115.121.1.15" in written.value)
        tm.ok(api.unregister_server(source_route))
        tm.ok(independent.resolve_base_server(source_route))
        tm.fail(api.write_to_string(entries, server_type=target_route))
