"""Schema-entry-attribute conversion concern for server-to-server translation.

Holds the embedded-schema-definition conversion (``_convert_schema_entry_value``
and ``_convert_schema_entry_attributes``) used by the entry mixin. Inherits the
shared schema helpers (``_validate_parsed_schema``, the ``_resolve_schema_server``
stub) from :class:`FlextLdifConversionSchemaMixin`; the concrete resolver wins via
the facade MRO (Support precedes this mixin).
"""

from __future__ import annotations

from flext_ldif import c, m, p, r, s, t, u
from flext_ldif.services.conversion_schema import FlextLdifConversionSchemaMixin


class FlextLdifConversionSchemaEntryMixin(FlextLdifConversionSchemaMixin, s):
    """Conversion of schema definitions embedded inside a schema entry."""

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

        definition_error = f"Failed to parse {schema_field_name} definition"
        if schema_item_kind == c.Ldif.SchemaItemKind.ATTRIBUTE:
            parse_result = self._validate_parsed_schema(
                source_schema.parse_attribute(value),
                m.Ldif.SchemaAttribute,
                definition_error,
            )
        else:
            parse_result = self._validate_parsed_schema(
                source_schema.parse_objectclass(value),
                m.Ldif.SchemaObjectClass,
                definition_error,
            )

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


__all__: list[str] = ["FlextLdifConversionSchemaEntryMixin"]
