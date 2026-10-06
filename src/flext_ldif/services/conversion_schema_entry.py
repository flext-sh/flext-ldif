"""Schema-entry-attribute conversion concern for server-to-server translation.

Holds the embedded-schema-definition conversion (``_convert_schema_entry_value``
and ``_convert_schema_entry_attributes``) used by the entry mixin. Inherits the
shared schema helpers (``_validate_parsed_schema``, the ``_resolve_schema_server``
stub) from :class:`FlextLdifConversionSchemaMixin`; the concrete resolver wins via
the facade MRO (Support precedes this mixin).

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services.conversion_schema import FlextLdifConversionSchemaMixin


class FlextLdifConversionSchemaEntryMixin(FlextLdifConversionSchemaMixin, s, ABC):
    """Conversion of schema definitions embedded inside a schema entry."""

    @staticmethod
    def _schema_field_name_for(
        schema_item_kind: c.Ldif.SchemaItemKind,
    ) -> str:
        """Map a schema item kind to its canonical entry field name.

        Returns:
            The resulting ``str``.
        """
        return (
            c.Ldif.ATTRIBUTE_TYPES
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else c.Ldif.OBJECT_CLASSES
        )

    def _convert_schema_entry_value(
        self,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
        value: str,
        *,
        schema_item_kind: c.Ldif.SchemaItemKind,
    ) -> p.Result[str]:
        """Convert a schema definition string embedded inside an LDIF entry.

        Returns:
            The resulting ``p.Result[str]``.
        """
        schema_field_name = self._schema_field_name_for(schema_item_kind)
        parse_result = (
            self._validate_parsed_schema(
                source_schema.parse_attribute(value),
                m.Ldif.SchemaAttribute,
            )
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else self._validate_parsed_schema(
                source_schema.parse_objectclass(value),
                m.Ldif.SchemaObjectClass,
            )
        )
        return (
            parse_result.map_error(
                lambda error: error or f"Failed to parse {schema_field_name}",
            )
            .flat_map(
                lambda parsed_item: self._write_converted_schema_item(
                    target_schema,
                    schema_item_kind,
                    schema_field_name,
                    parsed_item,
                ),
            )
        )

    @staticmethod
    def _write_converted_schema_item(
        target_schema: p.Ldif.SchemaServer,
        schema_item_kind: c.Ldif.SchemaItemKind,
        schema_field_name: str,
        parsed_item: t.Ldif.SchemaConversionValue,
    ) -> p.Result[str]:
        """Write one parsed schema item back in the target format.

        Returns:
            The resulting ``p.Result[str]``.
        """
        expected_item_cls = (
            m.Ldif.SchemaAttribute
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else m.Ldif.SchemaObjectClass
        )
        if not isinstance(parsed_item, expected_item_cls):
            return r[str].fail(
                f"Expected {expected_item_cls.__name__} for "
                f"{schema_field_name}, got {type(parsed_item).__name__}",
            )
        write_result = (
            target_schema.write_attribute(parsed_item)
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else target_schema.write_objectclass(parsed_item)
        )
        return r[str].from_result(write_result).map_error(
            lambda error: error
            or f"Failed to write converted {schema_field_name}",
        )

    def _convert_schema_entry_attributes(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> p.Result[m.Ldif.Entry]:
        """Convert schema definition attributes embedded in a schema entry.

        Returns:
            The resulting ``p.Result[m.Ldif.Entry]``.
        """
        if entry.attributes is None or not u.Ldif.is_schema_entry(entry):
            return r[m.Ldif.Entry].ok(entry)
        schema_pair = self._resolve_schema_pair(source_server, target_server)
        if schema_pair.failure:
            return r[m.Ldif.Entry].from_failure(schema_pair)
        source_schema, target_schema = schema_pair.value
        schema_fields = self._schema_fields_to_convert(entry)
        if not schema_fields:
            return r[m.Ldif.Entry].ok(entry)
        converted_fields_result = r[tuple[str, list[str]]].traverse(
            schema_fields,
            lambda field: self._convert_one_schema_field(
                source_schema,
                target_schema,
                field,
            ),
        )
        if converted_fields_result.failure:
            return r[m.Ldif.Entry].from_failure(converted_fields_result)
        return r[m.Ldif.Entry].ok(
            self._entry_with_converted_fields(entry, converted_fields_result.value),
        )

    def _resolve_schema_pair(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
    ) -> p.Result[tuple[p.Ldif.SchemaServer, p.Ldif.SchemaServer]]:
        """Resolve the schema servers for both conversion endpoints.

        Returns:
            The resulting ``p.Result[tuple[p.Ldif.SchemaServer,
                p.Ldif.SchemaServer]]``.
        """
        source_schema_result = self._resolve_schema_server(
            source_server,
            role="Source",
        )
        if source_schema_result.failure:
            return r[tuple[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].from_failure(
                source_schema_result,
            )
        target_schema_result = self._resolve_schema_server(
            target_server,
            role="Target",
        )
        if target_schema_result.failure:
            return r[tuple[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].from_failure(
                target_schema_result,
            )
        return r[tuple[p.Ldif.SchemaServer, p.Ldif.SchemaServer]].ok(
            (source_schema_result.value, target_schema_result.value),
        )

    @staticmethod
    def _schema_fields_to_convert(
        entry: m.Ldif.Entry,
    ) -> list[tuple[str, c.Ldif.SchemaItemKind, t.MutableSequenceOf[str]]]:
        """Collect the schema-definition fields present in one entry.

        Returns:
            The resulting list of (field name, item kind, values) triples.
        """
        schema_field_kinds: t.MappingKV[str, c.Ldif.SchemaItemKind] = {
            c.Ldif.ATTRIBUTE_TYPES.lower(): c.Ldif.SchemaItemKind.ATTRIBUTE,
            c.Ldif.OBJECT_CLASSES.lower(): c.Ldif.SchemaItemKind.OBJECTCLASS,
        }
        return [
            (attr_name, schema_item_kind, values)
            for attr_name, values in entry.attributes.attributes.items()
            if (schema_item_kind := schema_field_kinds.get(attr_name.lower()))
            is not None
        ]

    def _convert_one_schema_field(
        self,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
        field: tuple[str, c.Ldif.SchemaItemKind, t.MutableSequenceOf[str]],
    ) -> p.Result[tuple[str, list[str]]]:
        """Convert every definition value of one schema field.

        Returns:
            The resulting ``p.Result[tuple[str, list[str]]]``.
        """
        attr_name, schema_item_kind, values = field
        converted_values = r[str].traverse(
            values,
            lambda value: self._convert_schema_entry_value(
                source_schema,
                target_schema,
                value,
                schema_item_kind=schema_item_kind,
            ),
        )
        return (
            converted_values.map(lambda converted: (attr_name, list(converted)))
            .map_error(
                lambda error: error or f"Failed converting schema field {attr_name}",
            )
        )

    @staticmethod
    def _entry_with_converted_fields(
        entry: m.Ldif.Entry,
        converted_fields: t.SequenceOf[tuple[str, list[str]]],
    ) -> m.Ldif.Entry:
        """Rebuild the entry with converted schema fields applied.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        updated_attributes = dict(entry.attributes.attributes)
        updated_attributes.update(dict(converted_fields))
        return entry.model_copy(
            update={
                "attributes": entry.attributes.model_copy(
                    update={"attributes": updated_attributes},
                    deep=True,
                ),
            },
            deep=True,
        )


__all__: list[str] = ["FlextLdifConversionSchemaEntryMixin"]
