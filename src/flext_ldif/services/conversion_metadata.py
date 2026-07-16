"""Metadata-analysis helpers for server-to-server conversion."""

from __future__ import annotations

from collections.abc import Mapping

from flext_ldif import c, m, s, t, u


class FlextLdifConversionMetadataMixin(s):
    """Metadata-analysis helpers shared by the conversion facade."""

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze attribute case for target compatibility."""
        if bool(original_attribute_case):
            payload: t.JsonMapping = t.json_mapping_adapter().validate_python({
                "source_case": original_attribute_case,
                "target_server": target_server_type,
                "action": "apply_target_conventions",
            })
            # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: validate the
            # mapping directly instead of a model round-trip.
            return {
                "attribute_case": t.json_dict_adapter().validate_python(payload),
            }
        return {}

    @staticmethod
    def _analyze_boolean_conversions(
        boolean_conversions: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze boolean conversions for target compatibility."""
        if not boolean_conversions:
            return {}
        result: t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping] = {}
        for attr_name, conv_info in boolean_conversions.items():
            source_format = ""
            if isinstance(conv_info, Mapping):
                conv_info_dict: t.MutableJsonMapping = (
                    t.json_dict_adapter().validate_python(conv_info)
                )
                source_format = str(conv_info_dict.get("format", "") or "")
            result[f"boolean_{attr_name}"] = t.json_dict_adapter().validate_python({
                "source_format": source_format,
                "target_server": target_server_type,
                "action": "convert_to_target_format",
            })
        return result

    @staticmethod
    def _analyze_dn_format(
        original_format_details: t.MappingKV[str, t.JsonPayload | None],
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze DN spacing for target compatibility."""
        spacing = original_format_details.get("spacing")
        if spacing is None:
            spacing = original_format_details.get("dn_spacing")
        if spacing is None:
            return {}
        payload: t.JsonMapping = t.json_mapping_adapter().validate_python({
            "source_dn": spacing,
            "target_server": target_server_type,
            "action": "normalize_for_target",
        })
        return {
            "dn_format": t.json_dict_adapter().validate_python(payload),
        }

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: m.Ldif.ServerMetadata | t.MutableJsonMapping | None,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: t.MutableMappingKV[
            str,
            t.Ldif.MutableMetadataInputMapping,
        ] = {}
        if not source_metadata:
            return conversion_analysis
        if isinstance(source_metadata, m.Ldif.ServerMetadata):
            boolean_conversions = source_metadata.boolean_conversions
            attr_case_val = source_metadata.original_attribute_case
            format_val: t.JsonMapping = (
                t.json_mapping_adapter().validate_python({})
                if source_metadata.original_format_details is None
                else t.json_mapping_adapter().validate_python(
                    source_metadata.original_format_details.model_dump(
                        mode="json",
                        exclude_none=True,
                    ),
                )
            )
        else:
            boolean_conversions = u.Cli.json_as_mapping(
                source_metadata.get("boolean_conversions"),
            )
            attr_case_val = u.Cli.json_as_mapping(
                source_metadata.get("original_attribute_case"),
            )
            format_val = u.Cli.json_as_mapping(
                source_metadata.get("original_format_details"),
            )
        boolean_analysis = (
            FlextLdifConversionMetadataMixin._analyze_boolean_conversions(
                boolean_conversions,
                target_server_type,
            )
        )
        attr_case_analysis = FlextLdifConversionMetadataMixin._analyze_attribute_case(
            attr_case_val,
            target_server_type,
        )
        dn_format_analysis = FlextLdifConversionMetadataMixin._analyze_dn_format(
            format_val,
            target_server_type,
        )
        for analysis in (
            boolean_analysis,
            attr_case_analysis,
            dn_format_analysis,
        ):
            conversion_analysis.update(analysis)
        return conversion_analysis

    def _update_entry_metadata(
        self,
        entry: p.Ldif.Entry,
        validated_server_type: c.Ldif.ServerTypes,
        conversion_analysis: str | None,
        source_server_name: str,
    ) -> p.Ldif.Entry:
        """Update entry metadata for conversion (internal helper)."""
        get_metadata = u.prop("metadata")
        get_extensions = u.prop("extensions")
        current_entry = entry
        if not get_metadata(current_entry):
            metadata_obj = u.Ldif.server_metadata_for(
                server_type=validated_server_type,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": metadata_obj},
                deep=True,
            )
        entry_metadata = current_entry.metadata
        if (
            entry_metadata
            and get_metadata(current_entry)
            and (not get_extensions(entry_metadata))
        ):
            updated_metadata = entry_metadata.model_copy(
                update={"extensions": {}},
                deep=True,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        entry_metadata = current_entry.metadata
        if entry_metadata and get_metadata(current_entry):
            normalized_source_server: c.Ldif.ServerTypes | None = None
            if source_server_name != c.IDENTIFIER_UNKNOWN:
                normalized_source_server = u.try_(
                    lambda: u.Ldif.normalize_server_type(source_server_name),
                ).map_or(None)
            extensions_update: t.Ldif.MutableMetadataInputMapping = {
                "converted_from_server": source_server_name,
            }
            if conversion_analysis:
                extensions_update["conversion_analysis"] = conversion_analysis
            # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: merge into a new
            # plain mapping (was model_copy(update=..., deep=True)).
            updated_extensions: t.MutableJsonMapping = {
                **(entry_metadata.extensions or {}),
                **extensions_update,
            }
            updated_metadata = entry_metadata.model_copy(
                update={
                    "server_type": validated_server_type,
                    "extensions": updated_extensions,
                    "original_server_type": (
                        entry_metadata.original_server_type or normalized_source_server
                    ),
                    "target_server_type": validated_server_type,
                },
                deep=True,
            )
            current_entry = current_entry.model_copy(
                update={"metadata": updated_metadata},
                deep=True,
            )
        return current_entry


__all__: list[str] = ["FlextLdifConversionMetadataMixin"]
