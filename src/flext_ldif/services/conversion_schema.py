"""Schema-conversion helpers for server-to-server translation."""

from __future__ import annotations

from abc import ABC, abstractmethod

from flext_ldif import c, m, p, r, t, u


class FlextLdifConversionSchemaMixin(ABC):
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
            item_name = "attribute"
            write_result = source_schema.write_attribute(item)
            field_name = c.Ldif.ATTRIBUTE_TYPES
        else:
            item_name = "objectclass"
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
        converted_values: t.StrSequence = tuple[str, ...]()
        if attributes_model is not None:
            for attr_name, values in attributes_model.attributes.items():
                if attr_name.lower() == field_name.lower():
                    converted_values = list(values)
                    break
        if not converted_values:
            return r[t.Ldif.ConvertedModel].fail(
                f"Converted Entry does not contain {field_name}",
            )
        first_value = converted_values[0]
        if field_name == c.Ldif.ATTRIBUTE_TYPES:
            parsed_result = self._parse_attribute_with_schema(
                target_schema,
                first_value,
                parse_error_message="Failed to parse converted attribute",
            )
        else:
            parsed_result = self._parse_objectclass_with_schema(
                target_schema,
                first_value,
                parse_error_message="Failed to parse converted objectclass",
            )
        return parsed_result.flat_map(
            lambda parsed: r[t.Ldif.ConvertedModel].ok(parsed),
        )

    @staticmethod
    def _parse_attribute_with_schema(
        schema: p.Ldif.SchemaServer,
        value: str,
        *,
        parse_error_message: str,
    ) -> p.Result[m.Ldif.SchemaAttribute]:
        parse_result = schema.parse_attribute(value)
        if parse_result.failure:
            return r[m.Ldif.SchemaAttribute].fail(
                parse_result.error or parse_error_message,
            )
        parsed_attribute = m.Ldif.SchemaAttribute.model_validate(parse_result.value)
        return r[m.Ldif.SchemaAttribute].ok(parsed_attribute)

    @staticmethod
    def _parse_objectclass_with_schema(
        schema: p.Ldif.SchemaServer,
        value: str,
        *,
        parse_error_message: str,
    ) -> p.Result[m.Ldif.SchemaObjectClass]:
        parse_result = schema.parse_objectclass(value)
        if parse_result.failure:
            return r[m.Ldif.SchemaObjectClass].fail(
                parse_result.error or parse_error_message,
            )
        parsed_objectclass = m.Ldif.SchemaObjectClass.model_validate(
            parse_result.value,
        )
        return r[m.Ldif.SchemaObjectClass].ok(parsed_objectclass)

    def _convert_schema_entry_value(
        self,
        source_schema: p.Ldif.SchemaServer,
        target_schema: p.Ldif.SchemaServer,
        value: str,
        *,
        schema_item_kind: c.Ldif.SchemaItemKind,
    ) -> p.Result[str]:
        """Convert a schema definition string embedded inside an LDIF entry."""
        schema_field_name = (
            c.Ldif.ATTRIBUTE_TYPES
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE
            else c.Ldif.OBJECT_CLASSES
        )

        def write_schema_item(
            parsed_item: t.Ldif.SchemaConversionValue,
        ) -> p.Result[str]:
            if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
                if not isinstance(parsed_item, m.Ldif.SchemaAttribute):
                    return r[str].fail(
                        "Expected SchemaAttribute for "
                        f"{schema_field_name}, got {type(parsed_item).__name__}",
                    )
                return (
                    r[str]
                    .from_result(
                        target_schema.write_attribute(parsed_item),
                    )
                    .map_error(
                        lambda error: (
                            error or f"Failed to write converted {schema_field_name}"
                        ),
                    )
                )
            if not isinstance(parsed_item, m.Ldif.SchemaObjectClass):
                return r[str].fail(
                    "Expected SchemaObjectClass for "
                    f"{schema_field_name}, got {type(parsed_item).__name__}",
                )
            return (
                r[str]
                .from_result(
                    target_schema.write_objectclass(parsed_item),
                )
                .map_error(
                    lambda error: (
                        error or f"Failed to write converted {schema_field_name}"
                    ),
                )
            )

        parse_result: p.Result[t.Ldif.SchemaConversionValue]
        if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
            parse_result = self._parse_attribute_with_schema(
                source_schema,
                value,
                parse_error_message=(f"Failed to parse {schema_field_name} definition"),
            ).map(lambda parsed: parsed)
        else:
            parse_result = self._parse_objectclass_with_schema(
                source_schema,
                value,
                parse_error_message=(f"Failed to parse {schema_field_name} definition"),
            ).map(lambda parsed: parsed)

        return parse_result.map_error(
            lambda error: error or f"Failed to parse {schema_field_name}",
        ).flat_map(write_schema_item)

    def _convert_schema_entry_attributes(
        self,
        source_server: p.Ldif.ServerServer,
        target_server: p.Ldif.ServerServer,
        entry: m.Ldif.Entry,
    ) -> p.Result[m.Ldif.Entry]:
        """Convert schema definition attributes embedded in a schema entry."""
        if entry.attributes is None or not u.Ldif.is_schema_entry(entry):
            return r[m.Ldif.Entry].ok(entry)
        source_schema_result = self._resolve_schema_server(
            source_server,
            role="Source",
        )
        target_schema_result = self._resolve_schema_server(
            target_server,
            role="Target",
        )
        source_schema = source_schema_result.map_or(None)
        target_schema = target_schema_result.map_or(None)
        if source_schema is None or target_schema is None:
            return r[m.Ldif.Entry].fail(
                source_schema_result.error
                or target_schema_result.error
                or "Schema server not available",
            )
        schema_field_kinds: dict[str, c.Ldif.SchemaItemKind] = {
            c.Ldif.ATTRIBUTE_TYPES.lower(): c.Ldif.SchemaItemKind.ATTRIBUTE,
            c.Ldif.OBJECT_CLASSES.lower(): c.Ldif.SchemaItemKind.OBJECTCLASS,
        }
        schema_fields = [
            (attr_name, schema_item_kind, values)
            for attr_name, values in entry.attributes.attributes.items()
            if (schema_item_kind := schema_field_kinds.get(attr_name.lower()))
            is not None
        ]
        if not schema_fields:
            return r[m.Ldif.Entry].ok(entry)
        converted_fields_result = r[tuple[str, list[str]]].traverse(
            schema_fields,
            lambda field: (
                r[str]
                .traverse(
                    field[2],
                    lambda value, schema_item_kind=field[1]: (
                        self._convert_schema_entry_value(
                            source_schema,
                            target_schema,
                            value,
                            schema_item_kind=schema_item_kind,
                        )
                    ),
                )
                .map(
                    lambda converted_values, attr_name=field[0]: (
                        attr_name,
                        list(converted_values),
                    )
                )
                .map_error(
                    lambda error, attr_name=field[0]: (
                        error or f"Failed converting schema field {attr_name}"
                    ),
                )
            ),
        )
        if converted_fields_result.failure:
            return r[m.Ldif.Entry].fail(
                converted_fields_result.error or "Schema field conversion failed",
            )
        updated_attributes = dict(entry.attributes.attributes)
        updated_attributes.update(dict(converted_fields_result.value))
        updated_entry = entry.model_copy(
            update={
                "attributes": entry.attributes.model_copy(
                    update={"attributes": updated_attributes},
                    deep=True,
                ),
            },
            deep=True,
        )
        return r[m.Ldif.Entry].ok(updated_entry)


__all__: list[str] = ["FlextLdifConversionSchemaMixin"]
