"""Base schema server — metadata extension building and OID tracking.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping

from flext_ldif import c, m, r, t, u


class FlextLdifServersBaseSchemaMetadataMixin:
    """Build attribute/objectClass metadata extensions with OID tracking."""

    @staticmethod
    def _extract_metadata_extensions(
        attr_definition: str,
    ) -> t.Ldif.SchemaExtensionsMapping:
        """Extract metadata extensions from attribute definition.

        Returns:
            The resulting ``t.Ldif.SchemaExtensionsMapping``.
        """
        extract_method = getattr(u.Ldif, "extract_extensions", None)
        if extract_method is None or not callable(extract_method):
            return {}
        extensions_raw = extract_method(attr_definition)
        if not isinstance(extensions_raw, Mapping):
            return {}
        extensions_map: t.MutableJsonMapping = t.json_dict_adapter().validate_python(
            extensions_raw,
        )
        extracted: t.Ldif.SchemaExtensionsMapping = {}
        for raw_key, raw_value in extensions_map.items():
            if isinstance(raw_value, str | bool):
                extracted[raw_key] = raw_value
                continue
            if isinstance(raw_value, list):
                extracted[raw_key] = [str(item) for item in raw_value]
        return extracted

    @staticmethod
    def _preserve_formatting(
        metadata: m.Ldif.ServerMetadata,
        attr_definition: str,
    ) -> None:
        """Preserve schema formatting via FlextLdifUtilities.Metadata."""
        preserve_method = getattr(u.Ldif, "preserve_schema_formatting", None)
        if preserve_method is not None and callable(preserve_method):
            _ = preserve_method(metadata, attr_definition)

    @staticmethod
    def _resolve_server_type(server_type: str | None) -> c.Ldif.ServerTypes:
        """Resolve server type to valid StrEnum, defaulting to GENERIC.

        Returns:
            The resulting ``c.Ldif.ServerTypes``.
        """
        if not server_type:
            return c.Ldif.ServerTypes.RFC
        try:
            normalized: c.Ldif.ServerTypes = u.Ldif.normalize_server_type(server_type)
        except ValueError:
            return c.Ldif.ServerTypes.RFC
        else:
            return normalized

    @staticmethod
    def _attribute_oid_fields(
        parsed_definition: t.Ldif.MutableMetadataMapping,
    ) -> t.MappingKV[str, str | None]:
        """Collect the OID slots declared by one parsed attribute definition.

        Returns:
            The resulting ``t.MappingKV[str, str | None]``.
        """

        def optional_oid(key: str) -> str | None:
            value = parsed_definition.get(key)
            return str(value) if value else None

        return {
            "attribute": optional_oid("oid"),
            "equality matching rule": optional_oid("equality"),
            "ordering matching rule": optional_oid("ordering"),
            "substring matching rule": optional_oid("substr"),
            "SUP": optional_oid("sup"),
        }

    @staticmethod
    def build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        parsed_definition: t.Ldif.MutableMetadataMapping,
        server_type: str | None = None,
    ) -> m.Ldif.ServerMetadata | None:
        """Build metadata for attribute including extensions and OID validation.

        Returns:
            The resulting ``m.Ldif.ServerMetadata | None``.
        """
        metadata_extensions = FlextLdifServersBaseSchemaMetadataMixin._extract_metadata_extensions(
            attr_definition,
        )
        if syntax:
            metadata_extensions["syntax_oid_valid"] = syntax_validation_error is None
            if syntax_validation_error:
                metadata_extensions["syntax_validation_error"] = syntax_validation_error
        oid_fields = FlextLdifServersBaseSchemaMetadataMixin._attribute_oid_fields(
            parsed_definition,
        )
        for rule_name, rule_oid in oid_fields.items():
            FlextLdifServersBaseSchemaMetadataMixin.validate_and_track_oid(
                metadata_extensions,
                rule_oid,
                rule_name,
            )
        metadata_extensions["original_format"] = attr_definition.strip()
        metadata_extensions["schema_original_string_complete"] = attr_definition
        resolved_server_type: c.Ldif.ServerTypes = (
            FlextLdifServersBaseSchemaMetadataMixin._resolve_server_type(server_type)
        )
        schema_source_server: str = resolved_server_type.value
        metadata_extensions[c.Ldif.SCHEMA_SOURCE_SERVER] = schema_source_server
        extensions_typed: t.Ldif.MutableMetadataMapping = {}
        for key, val in metadata_extensions.items():
            if val is not None:
                extensions_typed[key] = u.normalize_to_metadata(val)
        metadata = m.Ldif.ServerMetadata(
            server_type=resolved_server_type,
            extensions=extensions_typed or {},
            original_server_type=resolved_server_type,
            target_server_type=resolved_server_type,
        )
        FlextLdifServersBaseSchemaMetadataMixin._preserve_formatting(metadata, attr_definition)
        return (
            metadata if metadata_extensions or metadata.schema_format_details else None
        )

    @staticmethod
    def validate_and_track_oid(
        metadata_extensions: MutableMapping[
            str,
            t.MutableSequenceOf[str] | str | bool | None,
        ],
        oid_value: str | None,
        oid_name: str,
    ) -> None:
        """Validate OID and track result in metadata extensions."""
        if not oid_value:
            return

        def default_oid_error(error: str) -> str:
            return error or f"{oid_name} OID validation failed"

        oid_validate_result = (
            r[bool]
            .from_result(u.Ldif.validate_format(oid_value))
            .map_error(default_oid_error)
        )
        if oid_validate_result.failure:
            metadata_extensions["syntax_validation_error"] = (
                f"{oid_name.capitalize()} OID validation "
                f"failed: {oid_validate_result.error}"
            )
            metadata_extensions["syntax_oid_valid"] = False
        elif not oid_validate_result.value:
            metadata_extensions["syntax_validation_error"] = (
                f"Invalid {oid_name} OID format: {oid_value} "
                f"(must be numeric dot-separated format)"
            )
            metadata_extensions["syntax_oid_valid"] = False
        else:
            metadata_extensions["syntax_oid_valid"] = True



__all__: list[str] = ["FlextLdifServersBaseSchemaMetadataMixin"]
