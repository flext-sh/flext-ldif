"""LDIF parsing metadata builder utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_cli import u

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._utilities._parser_schema_fields import FlextLdifParserSchemaFields
from flext_ldif._utilities.metadata import FlextLdifUtilitiesMetadata as um
from flext_ldif._utilities.server import FlextLdifUtilitiesServer as us


class FlextLdifParserMetadataBuilders:
    """Build server metadata payloads for parsed LDIF records."""

    @staticmethod
    def _as_str_list(
        value: t.MutableSequenceOf[t.JsonValue] | t.JsonValue | None,
    ) -> t.MutableSequenceOf[str] | None:
        """Normalize a JSON list of strings, rejecting mixed payloads.

        Returns:
            The resulting ``t.MutableSequenceOf[str] | None``.
        """
        if isinstance(value, list):
            normalized: t.MutableSequenceOf[str] = []
            for item in value:
                if not isinstance(item, str):
                    return None
                normalized.append(item)
            return normalized
        return None

    @staticmethod
    def _strict_str_list_view(
        mapping: t.Ldif.MetadataInputMapping,
    ) -> t.MutableStrSequenceMapping:
        """Keep only the entries whose payload is a plain string list.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        extensions: t.MutableStrSequenceMapping = {}
        for key, value in mapping.items():
            str_list = FlextLdifParserMetadataBuilders._as_str_list(value)
            if str_list is not None:
                extensions[key] = str_list
        return extensions

    @staticmethod
    def ext(metadata: t.Ldif.MetadataInputMapping) -> t.MutableStrSequenceMapping:
        """Extract extension information from parsed metadata.

        Returns:
            The resulting ``t.MutableStrSequenceMapping``.
        """
        result: t.JsonMapping | t.JsonValue | None = metadata.get("extensions")
        if not isinstance(result, Mapping):
            return FlextLdifParserMetadataBuilders._strict_str_list_view(metadata)
        extensions_metadata: t.MutableJsonMapping = (
            t.json_dict_adapter().validate_python({
                key: u.normalize_to_metadata(value) for key, value in result.items()
            })
        )
        return FlextLdifParserMetadataBuilders._strict_str_list_view(
            extensions_metadata,
        )

    @staticmethod
    def build_rfc_entry_metadata(
        dn: str,
        raw_record_lines: t.MutableSequenceOf[str],
        comments: t.MutableSequenceOf[str],
    ) -> FlextLdifModels.Ldif.ServerMetadata:
        """Build RFC metadata for a parsed LDIF record.

        Returns:
            The resulting ``FlextLdifModels.Ldif.ServerMetadata``.
        """
        metadata = um.server_metadata_for("rfc")
        metadata.original_server_type = c.Ldif.ServerTypes.RFC
        metadata.target_server_type = c.Ldif.ServerTypes.RFC
        metadata.original_strings["dn_original"] = dn
        metadata.original_strings["entry_original_ldif"] = "\n".join(raw_record_lines)
        if comments:
            comments_payload: t.JsonValueList = list(comments)
            metadata.extensions["entry_comments"] = comments_payload
        return metadata

    @staticmethod
    def _build_attribute_metadata(
        attr_definition: str,
        syntax: str | None,
        syntax_validation_error: str | None,
        server_type: str | None = None,
    ) -> FlextLdifModels.Ldif.ServerMetadata | None:
        """Build metadata for attribute including extensions.

        Returns:
            The resulting ``FlextLdifModels.Ldif.ServerMetadata | None``.
        """
        metadata_extensions = FlextLdifParserSchemaFields.extract_extensions(
            attr_definition,
        )
        if syntax:
            metadata_extensions["syntax_oid_valid"] = [
                str(syntax_validation_error is None),
            ]
            if syntax_validation_error:
                metadata_extensions["syntax_validation_error"] = [
                    syntax_validation_error,
                ]
        metadata_extensions["original_format"] = [attr_definition.strip()]
        metadata_extensions["schema_original_string_complete"] = [attr_definition]
        server_type = (
            us.normalize_server_type(server_type)
            if server_type
            else us.normalize_server_type("rfc")
        )
        if metadata_extensions:
            extensions_typed: t.Ldif.MutableMetadataMapping = {}
            for key, val in metadata_extensions.items():
                val_payload: t.JsonValueList = list(val)
                extensions_typed[key] = val_payload
            return FlextLdifModels.Ldif.ServerMetadata(
                server_type=server_type,
                extensions=extensions_typed,
            )
        return None


__all__: list[str] = ["FlextLdifParserMetadataBuilders"]
