"""LDIF metadata factory and builder utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping

from flext_ldif import FlextLdifModels, c, t


class FlextLdifMetadataBuilders:
    """Build ServerMetadata and compliance metadata payloads."""

    @staticmethod
    def server_metadata_for(
        server_type: str | c.Ldif.ServerTypes | None = None,
        extensions: t.MutableJsonMapping | t.Ldif.MetadataInputMapping | None = None,
    ) -> FlextLdifModels.Ldif.ServerMetadata:
        """Create ServerMetadata with extensions validated at the model boundary.

        Args:
            server_type: Server type identifier. Defaults to RFC if not provided.
            extensions: Extensions as a plain mapping. Defaults to empty if not
            provided.

        Returns:
            ServerMetadata instance with defaults from Constants.

        """
        default_server_type: c.Ldif.ServerTypes | str = (
            server_type if server_type is not None else c.Ldif.ServerTypes.RFC
        )
        extensions_map: t.MutableJsonMapping = (
            {} if extensions is None else dict(extensions)
        )
        validated: FlextLdifModels.Ldif.ServerMetadata = (
            FlextLdifModels.Ldif.ServerMetadata.model_validate({
                "server_type": default_server_type,
                "extensions": extensions_map,
            })
        )
        return validated

    @staticmethod
    def build_acl_metadata_complete(
        server_type: str,
        _original_acl_format: str | None = None,
        **extra: t.Ldif.Scalar,
    ) -> t.MutableConfigurationMapping:
        """Build metadata for ACL parsing as a dictionary.

        Returns:
            The resulting ``t.MutableConfigurationMapping``.
        """
        result: t.MutableConfigurationMapping = {
            "server_type": server_type,
            "source_server": server_type,
        }
        result.update({
            key: value
            for key, value in extra.items()
            if isinstance(value, (str, int, bool))
        })
        return result

    @staticmethod
    def build_entry_metadata_extensions(
        server_type: str,
    ) -> t.Ldif.MutableMetadataMapping:
        """Build metadata extensions for entry as a dictionary.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        return {"server_type": server_type, "source_server": server_type}

    @staticmethod
    def _collect_parse_server_data(
        settings: FlextLdifModels.Ldif.EntryParseMetadataConfig,
    ) -> t.Ldif.MutableMetadataMapping:
        """Collect server-specific data fields from parse settings.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        server_data_dict: t.Ldif.MutableMetadataMapping = {}
        server_data_dict["original_entry_dn"] = settings.original_entry_dn
        server_data_dict["cleaned_dn"] = settings.cleaned_dn
        server_data_dict["dn_was_base64"] = settings.dn_was_base64
        if settings.original_dn_line:
            server_data_dict["original_dn_line"] = settings.original_dn_line
        if settings.original_attr_lines:
            attr_lines_payload: t.JsonValueList = list(settings.original_attr_lines)
            server_data_dict["original_attribute_lines"] = attr_lines_payload
        if settings.original_attribute_case:
            attr_case_payload: t.JsonDict = dict(settings.original_attribute_case)
            server_data_dict["original_attribute_case"] = attr_case_payload
        return server_data_dict

    @staticmethod
    def _collect_original_ldif(
        settings: FlextLdifModels.Ldif.EntryParseMetadataConfig,
    ) -> str:
        """Reassemble the original LDIF text from parse settings.

        Returns:
            The resulting ``str``.
        """
        original_ldif_parts: t.MutableSequenceOf[str] = []
        if settings.original_dn_line:
            original_ldif_parts.append(settings.original_dn_line)
        if settings.original_attr_lines:
            original_ldif_parts.extend(settings.original_attr_lines)
        return "\n".join(original_ldif_parts) if original_ldif_parts else ""

    @staticmethod
    def build_entry_parse_metadata(
        settings: FlextLdifModels.Ldif.EntryParseMetadataConfig,
    ) -> FlextLdifModels.Ldif.ServerMetadata:
        """Build ServerMetadata for entry parsing with format preservation.

        Returns:
            The resulting ``FlextLdifModels.Ldif.ServerMetadata``.
        """
        server_data_dict = FlextLdifMetadataBuilders._collect_parse_server_data(
            settings,
        )
        extensions_dict: t.Ldif.MutableMetadataMapping = {}
        mk = c.Ldif
        extensions_dict[mk.ORIGINAL_DN_COMPLETE] = settings.original_entry_dn
        metadata = FlextLdifModels.Ldif.ServerMetadata(
            server_type=settings.server_type,
            server_specific_data=server_data_dict,
            extensions=extensions_dict,
        )
        original_ldif = FlextLdifMetadataBuilders._collect_original_ldif(settings)
        if original_ldif:
            metadata.original_strings["entry_original_ldif"] = original_ldif
        return metadata

    @staticmethod
    def build_original_format_details(
        server_type: str,
        **extra: t.Ldif.Scalar,
    ) -> FlextLdifModels.Ldif.FormatDetails:
        """Build original format details for round-trip preservation.

        Returns:
            The resulting ``FlextLdifModels.Ldif.FormatDetails``.
        """
        original_dn_line = extra.get("original_dn_line")
        dn_line = str(original_dn_line) if original_dn_line is not None else None
        return FlextLdifModels.Ldif.FormatDetails(
            dn_line=dn_line,
            trailing_info=f"server={server_type}",
        )

    @staticmethod
    def build_rfc_compliance_metadata(
        server_type: str,
        **extra: t.Ldif.Scalar,
    ) -> MutableMapping[
        str,
        str | bool | t.MutableSequenceOf[str] | t.MutableAttributeMapping,
    ]:
        """Build RFC compliance metadata as a dictionary.

        Returns:
            The resulting ``MutableMapping[str, str | bool | t.MutableSequenceOf[str] |
                t.MutableAttributeMapping]``.
        """
        result: MutableMapping[
            str,
            str | bool | t.MutableSequenceOf[str] | t.MutableAttributeMapping,
        ] = {"server_type": server_type, "source_server": server_type}
        if "rfc_violations" in extra:
            violations_val = extra["rfc_violations"]
            if isinstance(violations_val, str):
                result["rfc_violations"] = [violations_val]
        if "attribute_conflicts" in extra:
            conflicts_val = extra["attribute_conflicts"]
            if isinstance(conflicts_val, str):
                result["has_attribute_conflicts"] = conflicts_val
        return result


__all__: list[str] = ["FlextLdifMetadataBuilders"]
