"""Schema-conversion helpers for server-to-server translation."""

from __future__ import annotations

from abc import ABC, abstractmethod

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
        """Orchestrate schema conversion through m.Ldif.Entry intermediary."""
        if isinstance(item, m.Ldif.SchemaAttribute):
            item_name = c.Ldif.SchemaItemKind.ATTRIBUTE.value
            write_result = source_schema.write_attribute(item)
            field_name = c.Ldif.ATTRIBUTE_TYPES
        else:
            item_name = c.Ldif.SchemaItemKind.OBJECTCLASS.value
            write_result = source_schema.write_objectclass(item)
            field_name = c.Ldif.OBJECT_CLASSES
        source_server_type = u.try_(
            lambda: u.Ldif.normalize_server_type(
                source_server.server_type,
            ),
        ).map_or(None)
        source_value_result = (
            r[str]
            .from_result(write_result)
            .map_error(
                lambda error: (
                    f"Failed to write {item_name} in source format: "
                    f"{error or 'Unknown write error'}"
                ),
            )
        )
        if source_value_result.failure:
            return r[t.Ldif.ConvertedModel].fail(
                source_value_result.error
                or "Failed to write schema item in source format",
            )
        bridge_entry = m.Ldif.Entry.model_validate(
            {
                "dn": m.Ldif.DN(
                    value="cn=schema,dc=example,dc=com",
                    metadata=m.Ldif.EntryMetadata(),
                ),
                "attributes": m.Ldif.Attributes.model_validate(
                    {
                        "attributes": {field_name: [source_value_result.value]},
                        "attribute_metadata": {},
                        "metadata": None,
                    },
                ),
                "metadata": m.Ldif.ServerMetadata.create_for(
                    source_server_type,
                    extensions=None,
                ),
            },
        )
        converted_entry_result = self._convert_entry(
            source_server,
            target_server,
            bridge_entry,
        )
        if converted_entry_result.failure:
            return r[t.Ldif.ConvertedModel].fail(
                converted_entry_result.error
                or f"Failed to convert {item_name} via Entry intermediary",
            )
        converted_entry_value = converted_entry_result.value
        if not isinstance(converted_entry_value, m.Ldif.Entry):
            return r[t.Ldif.ConvertedModel].fail(
                "Entry intermediary returned unexpected type: "
                f"{type(converted_entry_value).__name__}",
            )
        attributes_model = converted_entry_value.attributes
        converted_values: tuple[str, ...] = ()
        if attributes_model is not None:
            for attr_name, values in attributes_model.attributes.items():
                if attr_name.lower() == field_name.lower():
                    converted_values = tuple(values)
                    break
        if not converted_values:
            return r[t.Ldif.ConvertedModel].fail(
                f"Converted Entry does not contain {field_name}",
            )
        first_value = converted_values[0]
        if field_name == c.Ldif.ATTRIBUTE_TYPES:
            parsed_result = self._validate_parsed_schema(
                target_schema.parse_attribute(first_value),
                m.Ldif.SchemaAttribute,
                "Failed to parse converted attribute",
            )
        else:
            parsed_result = self._validate_parsed_schema(
                target_schema.parse_objectclass(first_value),
                m.Ldif.SchemaObjectClass,
                "Failed to parse converted objectclass",
            )
        return parsed_result.flat_map(
            r[t.Ldif.ConvertedModel].ok,
        )

    @staticmethod
    def _validate_parsed_schema[T: m.Ldif.SchemaElement](
        parse_result: p.Result[T],
        model_cls: type[T],
        parse_error_message: str,
    ) -> p.Result[T]:
        """Re-validate a schema parse result into its model (attr / objectclass)."""
        if parse_result.failure:
            return r[T].fail(parse_result.error or parse_error_message)
        return r[T].ok(model_cls.model_validate(parse_result.value))


__all__: list[str] = ["FlextLdifConversionSchemaMixin"]
