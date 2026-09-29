"""OUD entry — Schema definition write normalization.

Per AGENTS.md §2.3 (MRO Composition) + §3.1 (200-LOC cap): one of the
domain-specific Mixins composed into ``FlextLdifServersOudHelpersMixin``.

RFC 4512 § 2.5.1 defines the ``SYNTAX`` property of a schema definition as an
unquoted ``noidlen``. Source dialects that quote the numeric OID (e.g. OID
schema dumps) serialize ``cn=schema`` modify values that OUD 14.1.2.1.0
rejects with ``invalidAttributeSyntax`` (21). Phase-aware OUD writes
therefore re-serialize ``attributetypes``/``objectclasses`` values through
the canonical source-parse → target-write cycle; same-server round trips
restore the original definition bytes unchanged.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import c, m, p, r, t, u


class FlextLdifServersOudSchemaWriteMixin:
    """OUD Schema write normalization for phase-aware OUD writes."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    _SCHEMA_DEFINITION_ATTRS: ClassVar[frozenset[str]] = frozenset({
        c.Ldif.ATTRIBUTE_TYPES.lower(),
        c.Ldif.OBJECT_CLASSES.lower(),
    })

    @classmethod
    def normalize_schema_definitions_for_write(
        cls, entry: m.Ldif.Entry
    ) -> p.Result[m.Ldif.Entry]:
        """Canonicalize schema definitions through the source→OUD write cycle.

        Non-schema entries and definitions already in OUD-canonical form pass
        through unchanged; values that fail to parse or serialize for OUD fail
        the write loudly.
        """
        if not cls._carries_schema_definitions(entry):
            return r[m.Ldif.Entry].ok(entry)
        servers_result = cls._resolve_write_schema_servers(entry)
        if servers_result.failure:
            return r[m.Ldif.Entry].from_failure(servers_result)
        source_schema, target_schema = servers_result.value
        attributes_result = cls._normalize_schema_attributes(
            entry, source_schema, target_schema
        )
        if attributes_result.failure:
            return r[m.Ldif.Entry].from_failure(attributes_result)
        return cls._normalize_schema_change_operations(
            attributes_result.value, source_schema, target_schema
        )

    @classmethod
    def _carries_schema_definitions(cls, entry: m.Ldif.Entry) -> bool:
        """Detect schema definition values in attributes or change operations."""
        attribute_names = (
            {name.lower() for name in entry.attributes.attributes}
            if entry.attributes is not None
            else set()
        )
        change_operation_names = {
            change_operation.attribute.lower()
            for change_operation in entry.change_operations
        }
        return bool(
            attribute_names & cls._SCHEMA_DEFINITION_ATTRS
            or change_operation_names & cls._SCHEMA_DEFINITION_ATTRS
        )

    @classmethod
    def _resolve_write_schema_servers(
        cls, entry: m.Ldif.Entry
    ) -> p.Result[t.Pair[p.Ldif.SchemaServer, p.Ldif.SchemaServer]]:
        """Resolve (source, target) schema servers for the entry provenance."""
        from flext_ldif.services.server import FlextLdifServer

        registry = FlextLdifServer.fetch_global_instance()
        target_result = registry.server(str(c.Ldif.ServerTypes.OUD.value))
        if target_result.failure:
            return r[t.Pair[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].fail_op(
                "resolve OUD target schema server", target_result.error
            )
        source_type: str = (
            entry.metadata.server_type
            if entry.metadata is not None
            else c.Ldif.ServerTypes.OUD.value
        )
        source_result = registry.server(source_type)
        if source_result.failure:
            return r[t.Pair[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].fail_op(
                f"resolve source schema server for OUD write from {source_type}",
                source_result.error,
            )
        return r[t.Pair[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].ok((
            source_result.value.schema_server,
            target_result.value.schema_server,
        ))

    @classmethod
    def _normalize_schema_attributes(
        cls,
        entry: m.Ldif.Entry,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
    ) -> p.Result[m.Ldif.Entry]:
        """Re-serialize schema definition attribute values for OUD."""
        if entry.attributes is None:
            return r[m.Ldif.Entry].ok(entry)
        normalized_values: dict[str, list[str]] = {}
        for attr_name, values in entry.attributes.attributes.items():
            if attr_name.lower() not in cls._SCHEMA_DEFINITION_ATTRS:
                continue
            new_values: list[str] = []
            for value in values:
                normalized_result = cls._normalize_definition_value(
                    value,
                    attr_name=attr_name,
                    source_schema=source_schema,
                    target_schema=target_schema,
                )
                if normalized_result.failure:
                    return r[m.Ldif.Entry].from_failure(normalized_result)
                new_values.append(normalized_result.value)
            if new_values != list(values):
                normalized_values[attr_name] = new_values
        if not normalized_values:
            return r[m.Ldif.Entry].ok(entry)
        merged_attributes: t.MutableStrSequenceMapping = dict(
            entry.attributes.attributes.items()
        )
        merged_attributes.update(normalized_values)
        pruned_metadata: dict[str, t.MutableAttributeMapping] = {
            attr_name: attribute_metadata
            for attr_name, attribute_metadata in (
                entry.attributes.attribute_metadata or {}
            ).items()
            if attr_name.lower() not in normalized_values
        }
        return r[m.Ldif.Entry].ok(
            entry.model_copy(
                update={
                    "attributes": m.Ldif.Attributes.model_validate({
                        "attributes": merged_attributes,
                        "attribute_metadata": pruned_metadata,
                        "metadata": entry.attributes.metadata,
                    })
                }
            )
        )

    @classmethod
    def _normalize_schema_change_operations(
        cls,
        entry: m.Ldif.Entry,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
    ) -> p.Result[m.Ldif.Entry]:
        """Re-serialize schema definition values inside modify blocks."""
        if not entry.change_operations:
            return r[m.Ldif.Entry].ok(entry)
        normalized_operations: t.MutableSequenceOf[m.Ldif.ChangeOperation] = []
        changed = False
        for change_operation in entry.change_operations:
            if change_operation.attribute.lower() not in cls._SCHEMA_DEFINITION_ATTRS:
                normalized_operations.append(change_operation)
                continue
            new_values: t.MutableSequenceOf[m.Ldif.ChangeOperationValue] = []
            for value_data in change_operation.values:
                normalized_result = cls._normalize_definition_value(
                    value_data.value,
                    attr_name=change_operation.attribute,
                    source_schema=source_schema,
                    target_schema=target_schema,
                )
                if normalized_result.failure:
                    return r[m.Ldif.Entry].from_failure(normalized_result)
                if normalized_result.value != value_data.value:
                    changed = True
                new_values.append(
                    value_data.model_copy(
                        update={
                            "value": normalized_result.value,
                            "value_origin": c.Ldif.ValueOrigin.PLAIN,
                            "raw_value": None,
                        }
                    )
                )
            normalized_operations.append(
                change_operation.model_copy(update={"values": new_values})
            )
        if not changed:
            return r[m.Ldif.Entry].ok(entry)
        return r[m.Ldif.Entry].ok(
            entry.model_copy(update={"change_operations": normalized_operations})
        )

    @classmethod
    def _normalize_definition_value(
        cls,
        value: str,
        *,
        attr_name: str,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
    ) -> p.Result[str]:
        """Canonicalize one schema definition through source-parse→OUD-write."""
        if attr_name.lower() == c.Ldif.ATTRIBUTE_TYPES.lower():
            parse_result = source_schema.parse_attribute(value)
            if parse_result.failure:
                return r[str].fail_op(
                    f"parse {attr_name} definition for OUD write", parse_result.error
                )
            write_result = target_schema.write_attribute(parse_result.value)
        else:
            parse_result_oc = source_schema.parse_objectclass(value)
            if parse_result_oc.failure:
                return r[str].fail_op(
                    f"parse {attr_name} definition for OUD write", parse_result_oc.error
                )
            write_result = target_schema.write_objectclass(parse_result_oc.value)
        if write_result.failure:
            return r[str].fail_op(
                f"serialize {attr_name} definition for OUD write", write_result.error
            )
        return write_result


__all__: list[str] = ["FlextLdifServersOudSchemaWriteMixin"]
