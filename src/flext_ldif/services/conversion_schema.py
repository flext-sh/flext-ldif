"""Schema-conversion helpers for server-to-server translation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable

from flext_ldif import c, m, p, r, s, t, u


class FlextLdifConversionSchemaMixin(s, ABC):
    """Schema-conversion helpers shared by the conversion facade."""

    def _resolve_schema_server(
        self,
        server_or_type: p.Ldif.ServerReference | p.Ldif.ServerServer | str,
        *,
        role: str,
    ) -> p.Result[p.Ldif.SchemaServer]:
        """Resolve the schema server for a concrete server endpoint."""
        raise NotImplementedError

    @abstractmethod
    def _convert_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Convert an entry through the concrete conversion facade."""

    def _convert_schema_model_via_entry(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Orchestrate schema conversion through an m.Ldif.Entry intermediary.

        Returns:
            The resulting ``p.Result[t.Ldif.ConvertedModel]``.
        """
        source_write = self._write_schema_source_value(item, source_schema)
        if source_write.failure:
            return r[t.Ldif.ConvertedModel].from_failure(source_write)
        _, field_name, source_value = source_write.value
        bridge_entry = self._schema_bridge_entry(
            source_server,
            field_name,
            source_value,
        )
        converted_entry_result = self._convert_entry(
            source_server,
            target_server,
            bridge_entry,
        )
        if converted_entry_result.failure:
            return r[t.Ldif.ConvertedModel].from_failure(converted_entry_result)
        converted_values = self._schema_values_from_converted(
            converted_entry_result.value,
            field_name,
        )
        if converted_values.failure:
            return r[t.Ldif.ConvertedModel].from_failure(converted_values)
        return self._parse_converted_schema_item(
            target_schema,
            field_name,
            converted_values.value[0],
        )

    @staticmethod
    def _schema_write_error(item_name: str) -> Callable[[str], str]:
        """Build the canonical source-write failure mapper for one schema kind.

        Returns:
            A callable mapping a write error to its message.
        """

        def default_write_error(error: str) -> str:
            return (
                f"Failed to write {item_name} in source format: "
                f"{error or 'Unknown write error'}"
            )

        return default_write_error

    def _write_schema_source_value(
        self,
        item: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        source_schema: p.Ldif.SchemaServer,
    ) -> p.Result[tuple[str, str, str]]:
        """Write the schema item in source format.

        Returns:
            The resulting ``p.Result[tuple[str, str, str]]``:
            (item kind, schema field name, written source value).
        """
        if isinstance(item, m.Ldif.SchemaAttribute):
            item_name = c.Ldif.SchemaItemKind.ATTRIBUTE.value
            field_name = c.Ldif.ATTRIBUTE_TYPES
            write_result = source_schema.write_attribute(item)
        else:
            item_name = c.Ldif.SchemaItemKind.OBJECTCLASS.value
            field_name = c.Ldif.OBJECT_CLASSES
            write_result = source_schema.write_objectclass(item)
        return (
            r[str]
            .from_result(write_result)
            .map_error(self._schema_write_error(item_name))
            .map(lambda source_value: (item_name, field_name, source_value))
        )

    @staticmethod
    def _schema_bridge_entry(
        source_server: p.Ldif.ServerServer,
        field_name: str,
        source_value: str,
    ) -> m.Ldif.Entry:
        """Build the synthetic schema entry that carries one written definition.

        Returns:
            The resulting ``m.Ldif.Entry``.
        """
        source_server_type = u.try_(
            lambda: u.Ldif.normalize_server_type(source_server.server_type),
        ).map_or(None)
        return m.Ldif.Entry.model_validate({
            "dn": m.Ldif.DN(value="cn=schema,dc=example,dc=com", metadata={}),
            "attributes": m.Ldif.Attributes.model_validate({
                "attributes": {field_name: [source_value]},
                "attribute_metadata": {},
                "metadata": None,
            }),
            "metadata": u.Ldif.server_metadata_for(source_server_type),
        })

    @staticmethod
    def _schema_values_from_converted(
        converted_entry_value: t.Ldif.ConvertedModel,
        field_name: str,
    ) -> p.Result[tuple[str, ...]]:
        """Extract the converted schema values from the entry intermediary.

        Returns:
            The resulting ``p.Result[tuple[str, ...]]``.
        """
        if not isinstance(converted_entry_value, m.Ldif.Entry):
            return r[tuple[str, ...]].fail(
                "Entry intermediary returned unexpected type: "
                f"{type(converted_entry_value).__name__}",
            )
        attributes_model = converted_entry_value.attributes
        if attributes_model is not None:
            for attr_name, values in attributes_model.attributes.items():
                if attr_name.lower() == field_name.lower():
                    return r[tuple[str, ...]].ok(tuple(values))
        return r[tuple[str, ...]].fail(
            f"Converted Entry does not contain {field_name}",
        )

    def _parse_converted_schema_item(
        self,
        target_schema: p.Ldif.SchemaServer,
        field_name: str,
        first_value: str,
    ) -> p.Result[t.Ldif.ConvertedModel]:
        """Parse the converted definition back into its target model.

        Returns:
            The resulting ``p.Result[t.Ldif.ConvertedModel]``.
        """
        if field_name == c.Ldif.ATTRIBUTE_TYPES:
            validated = self._validate_parsed_schema(
                target_schema.parse_attribute(first_value),
                m.Ldif.SchemaAttribute,
            )
        else:
            validated = self._validate_parsed_schema(
                target_schema.parse_objectclass(first_value),
                m.Ldif.SchemaObjectClass,
            )
        if validated.failure:
            return r[t.Ldif.ConvertedModel].from_failure(validated)
        return r[t.Ldif.ConvertedModel].ok(validated.value)

    @staticmethod
    def _validate_parsed_schema[T: m.Ldif.SchemaElement](
        parse_result: p.Result[T],
        model_cls: type[T],
    ) -> p.Result[T]:
        """Re-validate a schema parse result into its model (attr / objectclass).

        Returns:
            The resulting ``p.Result[T]``.
        """
        if parse_result.failure:
            return r[T].from_failure(parse_result)
        return r[T].ok(model_cls.model_validate(parse_result.value))


__all__: list[str] = ["FlextLdifConversionSchemaMixin"]
