"""Metadata-analysis helpers for server-to-server conversion."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from flext_ldif import m, t, u


class FlextLdifConversionMetadataMixin:
    """Metadata-analysis helpers shared by the conversion facade."""

    @staticmethod
    def _analyze_attribute_case(
        original_attribute_case: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze attribute case for target compatibility."""
        if bool(original_attribute_case):
            return {
                "attribute_case": {
                    "source_case": (
                        FlextLdifConversionMetadataMixin._normalize_metadata_value(
                            original_attribute_case,
                        )
                    ),
                    "target_server": target_server_type,
                    "action": "apply_target_conventions",
                },
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
                conv_info_dict = u.Cli.json_as_mapping(
                    u.normalize_to_metadata(conv_info),
                )
                source_format = str(conv_info_dict.get("format", "") or "")
            result[f"boolean_{attr_name}"] = {
                "source_format": source_format,
                "target_server": target_server_type,
                "action": "convert_to_target_format",
            }
        return result

    @staticmethod
    def _analyze_dn_format(
        original_format_details: t.JsonMapping,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze DN spacing for target compatibility."""
        spacing = original_format_details.get("dn_spacing")
        if spacing:
            return {
                "dn_format": {
                    "source_dn": (
                        FlextLdifConversionMetadataMixin._normalize_metadata_value(
                            spacing,
                        )
                    ),
                    "target_server": target_server_type,
                    "action": "normalize_for_target",
                },
            }
        return {}

    @staticmethod
    def _analyze_metadata_for_conversion(
        source_metadata: m.Ldif.ServerMetadata | m.Ldif.DynamicMetadata | None,
        target_server_type: str,
    ) -> t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping]:
        """Analyze source metadata for intelligent conversion to target server."""
        conversion_analysis: t.MutableMappingKV[
            str,
            t.Ldif.MutableMetadataInputMapping,
        ] = {}
        if not source_metadata:
            return conversion_analysis
        target_server_str = target_server_type
        get_boolean = u.prop("boolean_conversions")
        get_attr_case = u.prop("original_attribute_case")
        get_format_details = u.prop("original_format_details")
        boolean_raw = get_boolean(source_metadata)
        boolean_conversions = u.Cli.json_as_mapping(boolean_raw)
        boolean_analysis = (
            FlextLdifConversionMetadataMixin._analyze_boolean_conversions(
                boolean_conversions,
                target_server_str,
            )
        )
        acc_typed: t.MutableMappingKV[str, t.Ldif.MutableMetadataInputMapping] = {}
        for key, value in boolean_analysis.items():
            if isinstance(value, dict):
                acc_typed[key] = {
                    k: FlextLdifConversionMetadataMixin._normalize_metadata_value(v)
                    for k, v in value.items()
                }
        attr_case_raw = get_attr_case(source_metadata)
        attr_case_val = u.Cli.json_as_mapping(attr_case_raw)
        attr_case_analysis = FlextLdifConversionMetadataMixin._analyze_attribute_case(
            attr_case_val,
            target_server_str,
        )
        for key, attr_case_value in attr_case_analysis.items():
            if isinstance(attr_case_value, dict):
                acc_typed[key] = {
                    k: FlextLdifConversionMetadataMixin._normalize_metadata_value(v)
                    for k, v in attr_case_value.items()
                }
        format_raw = get_format_details(source_metadata)
        format_val = u.Cli.json_as_mapping(format_raw)
        dn_format_analysis = FlextLdifConversionMetadataMixin._analyze_dn_format(
            format_val,
            target_server_str,
        )
        for key, dn_format_value in dn_format_analysis.items():
            if isinstance(dn_format_value, dict):
                acc_typed[key] = {
                    k: FlextLdifConversionMetadataMixin._normalize_metadata_value(v)
                    for k, v in dn_format_value.items()
                }
        return acc_typed

    @staticmethod
    def _normalize_metadata_value(
        value: t.JsonPayload | t.MappingKV[str, t.JsonPayload] | None,
    ) -> t.JsonValue:
        """Normalize metadata value to proper type."""
        if value is None:
            empty_val: t.JsonValue = u.normalize_to_json_value("")
            return empty_val
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, t.JsonValue] = {
                key: u.normalize_to_json_value(item) for key, item in value.items()
            }
            return normalized_mapping
        if isinstance(value, Sequence) and not isinstance(value, str | bytes):
            normalized_sequence: list[t.JsonValue] = [
                u.normalize_to_json_value(item) for item in value
            ]
            return normalized_sequence
        normalized: t.JsonValue = t.Cli.JSON_VALUE_ADAPTER.validate_python(value)
        return normalized


__all__: list[str] = ["FlextLdifConversionMetadataMixin"]
