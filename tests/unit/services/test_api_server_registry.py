"""Behavioral tests for the LDIF facade server-registry public contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import PurePath
from typing import TYPE_CHECKING

import pytest

from flext_ldif import FlextLdif, ldif, services
from flext_ldif.servers import FlextLdifServersRfc
from tests import c, m, tm, u

if TYPE_CHECKING:
    from pathlib import Path

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
        tm.that(
            constants is api.resolve_base_server(c.Tests.OUD).unwrap().server_constants
        )
        tm.that(type(constants), eq=type)

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
    @pytest.mark.parametrize("field_name", ["_runtime", "_operation_stats"])
    def test_private_runtime_state_is_not_constructor_input(field_name: str) -> None:
        """The facade preserves the base model's strict private-state ownership."""
        with pytest.raises(ValueError, match=field_name):
            FlextLdif.model_validate({field_name: None})

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
    def test_dialect_bootstrap_and_schema_keep_public_model_contracts() -> None:
        """Explicit bootstrap preserves DI and schema parsing returns native models."""
        api = FlextLdif()
        dialect = api.resolve_base_server(c.Ldif.ServerTypes.RFC.value).unwrap()
        rebuilt = FlextLdifServersRfc(
            runtime_settings=api.settings,
            settings_overrides={},
        )
        tm.that(rebuilt.settings is api.settings)
        attribute = dialect.schema_server.parse_server(
            "( 1.2.3.4 NAME 'exampleAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        ).unwrap()
        tm.that(isinstance(attribute, m.Ldif.SchemaAttribute))
        objectclass = dialect.schema_server.parse_server(
            "( 1.2.3.5 NAME 'exampleClass' SUP top STRUCTURAL MUST cn )"
        ).unwrap()
        tm.that(isinstance(objectclass, m.Ldif.SchemaObjectClass))

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
    @pytest.mark.parametrize("field_name", ["registry"])
    def test_required_registry_port_is_validated_and_not_serialized(
        field_name: str,
    ) -> None:
        """Services cannot construct infrastructure or accept a loose payload."""
        with pytest.raises(ValueError, match="registry"):
            services.FlextLdifServer.model_validate({})
        with pytest.raises(ValueError, match="registry"):
            m.Ldif.RegistryPortOptions.model_validate({field_name: m.Ldif.Statistics()})
        registry = u.build_registry()
        ports = m.Ldif.RegistryPortOptions(registry=registry)
        tm.that(ports.registry is registry)
        tm.that(field_name not in ports.model_dump())
        tm.that(field_name not in ports.model_json_schema().get("properties", {}))
        with pytest.raises(ValueError, match="registry"):
            setattr(ports, field_name, m.Ldif.Statistics())
        tm.that(ports.registry is registry)

    @staticmethod
    def test_incompatible_stored_payload_fails_lookup_without_fallback() -> None:
        """An invalid stored dialect never causes a fresh dialect to be built."""
        registry = u.build_registry()
        route = c.Ldif.ServerTypes.RFC.value
        payload = m.Ldif.Statistics()
        tm.ok(registry.register_plugin(c.Ldif.SERVERS, route, payload))
        service = services.FlextLdifServer(registry=registry)
        tm.fail(service.resolve_base_server(route))
        tm.fail(service.resolve_server_bundle(route))
        tm.fail(service.summarize_registry())
        tm.that(registry.fetch_plugin(c.Ldif.SERVERS, route).unwrap() is payload)

    @staticmethod
    def test_real_dialect_parse_write_roundtrip_and_removal_failure() -> None:
        """Registry composition retains the real RFC parse/write implementation."""
        api = FlextLdif()
        route = c.Ldif.ServerTypes.RFC.value
        source = (
            "dn: cn=person,dc=example,dc=com\n"
            "objectClass: person\ncn: person\nsn: example\n"
        )
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


class TestsFlextLdifRegistryWrites:
    """Validate registry-selected writers and their explicit runtime ports."""

    @staticmethod
    def test_structural_write_boundary_preserves_models_and_pathlike_io(
        tmp_path: Path,
    ) -> None:
        """The write ingress owns validation without copying valid payload models."""
        api = FlextLdif()
        route = c.Ldif.ServerTypes.RFC.value
        entry = u.Tests.create_real_entry(
            dn=c.Tests.ANALYSIS_DN_VALID,
            attributes={"objectClass": ["person"], "cn": ["entry"], "sn": ["entry"]},
        )
        options = m.Ldif.WriteFormatOptions()
        request = m.Ldif.WriteRequest.model_validate({
            "entries": [entry],
            "format_options": options,
        })
        tm.that(request.entries[0] is entry)
        tm.that(request.format_options is options)
        output = tmp_path / "structural.ldif"
        tm.ok(
            api.write_ldif_file(
                (entry,),
                PurePath(output),
                server_type=route,
                format_options=options,
            )
        )
        parsed = api.parse_ldif(PurePath(output), server_type=route).unwrap()
        tm.that(len(parsed.entries), eq=len(request.entries))
        tm.that(parsed.entries[0].dn, eq=entry.dn)

    @staticmethod
    @pytest.mark.parametrize("comment_acl", [False, True])
    def test_write_response_preserves_oid_entries_and_phase_options(
        tmp_path: Path,
        *,
        comment_acl: bool,
    ) -> None:
        """OID metadata and explicitly selected ACL handling survive file writes."""
        api = FlextLdif()
        acl = "access to entry by * (browse)"
        source_attribute = c.Ldif.Oid.ACL_ATTRIBUTE_NAME
        parsed = api.parse_string(
            "dn: cn=synthetic\nobjectClass: person\n"
            f"cn: synthetic\nsn: Sample\n{source_attribute}: {acl}\n\n",
            server_type=c.Ldif.ServerTypes.OID,
        ).unwrap()
        tm.that(len(parsed.entries), eq=1)
        tm.that(parsed.entries[0].attributes_dict[source_attribute], eq=[acl])
        output = tmp_path / "converted.ldif"
        written = api.write_ldif_file(
            parsed,
            output,
            server_type=c.Ldif.ServerTypes.OUD,
            format_options=m.Ldif.WriteFormatOptions(
                entry_category=c.Ldif.Categories.USERS,
                comment_acl_in_non_acl_phases=comment_acl,
                acl_attribute_names=frozenset({
                    source_attribute,
                    c.Ldif.Oud.ACL_ATTRIBUTE_NAME,
                }),
            ),
        ).unwrap()
        content = tm.not_none(output.read_text())
        tm.that(written.output_path, eq=str(output))
        tm.that(written.content, eq=content)
        tm.that(written.statistics.processed_entries, eq=len(parsed.entries))
        tm.that(content, has=acl)
        tm.that(
            any(
                line.startswith(f"{source_attribute}:") for line in content.splitlines()
            ),
            eq=not comment_acl,
        )
        reparsed = tm.ok(api.parse_ldif(output, server_type=c.Ldif.ServerTypes.OUD))
        tm.that(len(reparsed.entries), eq=len(parsed.entries))
        tm.that(reparsed.entries[0].dn_str, eq=parsed.entries[0].dn_str)
        tm.that(reparsed.entries[0].attributes_dict["sn"], eq=["Sample"])

    @staticmethod
    def test_failed_write_preserves_failure_and_creates_no_file(
        tmp_path: Path,
    ) -> None:
        """An invalid dialect fails both public writers before persisting output."""
        api = FlextLdif()
        parsed = api.parse_string(
            "dn: cn=synthetic\nobjectClass: person\ncn: synthetic\nsn: Sample\n\n",
            server_type=c.Ldif.ServerTypes.RFC,
        ).unwrap()
        tm.that(len(parsed.entries), eq=1)
        output = tmp_path / "invalid.ldif"
        tm.fail(api.write(parsed, server_type=c.Tests.SERVER_INVALID_SERVER_TYPE))
        tm.fail(
            api.write_ldif_file(
                parsed, output, server_type=c.Tests.SERVER_INVALID_SERVER_TYPE
            )
        )
        tm.fail(output.exists())

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
