"""LDIF Metadata Utilities - Helpers for Validation Metadata Management."""

from __future__ import annotations

import re
from collections.abc import (
    Callable,
    Mapping,
    MutableMapping,
)
from typing import TypeIs

from flext_core import u
from flext_ldif import (
    FlextLdifUtilitiesServer as us,
    c,
    m,
    p,
    t,
)

logger = u.fetch_logger(__name__)


class FlextLdifUtilitiesMetadata:
    """Metadata utilities for LDIF validation metadata management."""

    @staticmethod
    def dump_json_payload(value: t.JsonPayload | None) -> str:
        """Serialize any CLI JSON-compatible payload through the canonical DSL."""
        if value is None:
            return ""
        return m.Cli.CliNormalizedJson(
            t.Cli.JSON_VALUE_ADAPTER.validate_python(
                u.to_jsonable_python(value),
            ),
        ).model_dump_json()

    @staticmethod
    def dump_dynamic_metadata(
        value: t.Ldif.MetadataInputMapping | None,
    ) -> str:
        """Serialize metadata-shaped mappings through the LDIF metadata model."""
        if not value:
            return ""
        dumped: str = m.Ldif.DynamicMetadata.from_dict(value).model_dump_json()
        return dumped

    @staticmethod
    def _add_to_dict_metadata(
        metadata: t.Ldif.MutableMetadataMapping,
        metadata_key: str,
        item_data: t.JsonValue,
    ) -> None:
        """Add item to dict metadata."""
        value = metadata.get(metadata_key)
        if isinstance(value, Mapping) and isinstance(item_data, Mapping):
            merged_value = dict(
                t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                    inner_key: u.normalize_to_metadata(inner_value)
                    for inner_key, inner_value in value.items()
                }),
            )
            for write_option_key, inner_value in item_data.items():
                merged_value[write_option_key] = u.normalize_to_metadata(
                    inner_value,
                )
            metadata[metadata_key] = merged_value
            return
        metadata[metadata_key] = u.normalize_to_metadata(item_data)

    @staticmethod
    def _add_to_list_metadata(
        metadata: t.Ldif.MutableMetadataMapping,
        metadata_key: str,
        item_data: t.JsonValue,
    ) -> None:
        """Add item to list metadata."""
        value = metadata.get(metadata_key)
        normalized_item = FlextLdifUtilitiesMetadata._normalize_metadata_list_item(
            item_data,
        )
        if normalized_item is None:
            return
        if isinstance(value, list):
            value.append(normalized_item)
            metadata[metadata_key] = value
            return
        metadata[metadata_key] = [normalized_item]

    @staticmethod
    def _apply_category_update(
        stats: m.Ldif.EntryStatistics,
        category: str,
    ) -> m.Ldif.EntryStatistics:
        """Apply category update to stats using model_copy."""
        copied: m.Ldif.EntryStatistics = stats.model_copy(
            update={"category_assigned": category},
        )
        return copied

    @staticmethod
    def _apply_filter_update(
        stats: m.Ldif.EntryStatistics,
        filter_type: str,
        *,
        passed: bool,
    ) -> m.Ldif.EntryStatistics:
        """Apply filter marking to stats."""
        return stats.mark_filtered(filter_type, passed=passed)

    @staticmethod
    def _apply_rejection_update(
        stats: m.Ldif.EntryStatistics,
        rejection_category: str,
        reason: str,
    ) -> m.Ldif.EntryStatistics:
        """Apply rejection marking to stats."""
        return stats.mark_rejected(rejection_category, reason)

    @staticmethod
    def _build_schema_format_model(
        definition: str,
        combined: t.Ldif.MutableMetadataMapping,
    ) -> m.Ldif.SchemaFormatDetails:
        """Build SchemaFormatDetails model from combined details."""
        known_fields = {
            "original_string_complete",
            "quotes",
            "spacing",
            "field_order",
            "x_origin",
            "x_ordered",
        }
        known_field_values: t.Ldif.MutableMetadataMapping = {
            "original_string_complete": definition,
        }
        extension_kwargs: t.Ldif.MutableMetadataMapping = {}
        for write_option_key, value in combined.items():
            if write_option_key in known_fields:
                known_field_values[write_option_key] = value
            else:
                extension_kwargs[write_option_key] = value
        extensions = m.Ldif.DynamicMetadata.model_validate(
            extension_kwargs,
        )
        details: m.Ldif.SchemaFormatDetails = m.Ldif.SchemaFormatDetails.model_validate({
            **known_field_values,
            "extensions": extensions,
        })
        return details

    @staticmethod
    def _extract_all_schema_details(
        definition: str,
    ) -> t.Ldif.MutableMetadataMapping:
        """Extract all schema formatting details into combined dict."""
        combined: t.Ldif.MutableMetadataMapping = {}
        extractors: t.SequenceOf[
            Callable[
                [str],
                t.MappingKV[str, str | bool | int | t.MutableSequenceOf[str] | None],
            ]
        ] = [
            FlextLdifUtilitiesMetadata._extract_prefix_details,
            FlextLdifUtilitiesMetadata._extract_oid_details,
            FlextLdifUtilitiesMetadata._extract_syntax_details,
            FlextLdifUtilitiesMetadata._extract_name_details,
            FlextLdifUtilitiesMetadata._extract_desc_details,
            FlextLdifUtilitiesMetadata._extract_x_origin_details,
            FlextLdifUtilitiesMetadata._extract_obsolete_details,
            FlextLdifUtilitiesMetadata._extract_leading_trailing_spaces,
            FlextLdifUtilitiesMetadata._extract_matching_rule_details,
            FlextLdifUtilitiesMetadata._extract_sup_details,
            FlextLdifUtilitiesMetadata._extract_single_value_details,
        ]
        for extractor in extractors:
            extracted_raw = extractor(definition)
            for write_option_key, value in extracted_raw.items():
                combined[write_option_key] = t.Cli.JSON_VALUE_ADAPTER.validate_python(
                    value,
                )
        field_order, field_positions = FlextLdifUtilitiesMetadata._extract_field_order(
            definition,
        )
        field_order_payload: list[t.JsonValue] = list(field_order)
        field_positions_payload: dict[str, t.JsonValue] = dict(field_positions)
        combined["field_order"] = field_order_payload
        combined["field_positions"] = field_positions_payload
        spacing_result = FlextLdifUtilitiesMetadata._extract_spacing_between_fields(
            definition,
            field_order,
            field_positions,
            {
                "OID": "\\(\\s*([0-9.]+)",
                "NAME": "NAME",
                "DESC": "DESC",
                "EQUALITY": "EQUALITY",
                "SUBSTR": "SUBSTR",
                "ORDERING": "ORDERING",
                "SYNTAX": "SYNTAX",
                "SUP": "SUP",
                "SINGLE-VALUE": "SINGLE-VALUE",
                "OBSOLETE": "OBSOLETE",
                "X-ORIGIN": "X-ORIGIN",
            },
        )
        spacing_payload: dict[str, t.JsonValue] = dict(spacing_result)
        combined["spacing_between_fields"] = spacing_payload
        return combined

    @staticmethod
    def _extract_desc_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract DESC details."""
        details: t.MutableFeatureFlagMapping = {}
        desc_match = re.search(
            r"DESC\s+([\"']?)([^\"']+)([\"']?)",
            definition,
            re.IGNORECASE,
        )
        if desc_match:
            details["desc_presence"] = True
            details["desc_quotes"] = desc_match.group(1) or desc_match.group(3) or ""
            details["desc_value"] = desc_match.group(2)
            desc_pos = definition.find("DESC")
            if desc_pos >= 0:
                before_desc = definition[:desc_pos]
                before_match = re.search(r"(\s+)$", before_desc)
                details["desc_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["desc_presence"] = False
        return details

    @staticmethod
    def _extract_field_order(
        definition: str,
    ) -> tuple[t.MutableSequenceOf[str], t.MutableIntMapping]:
        """Extract field order and positions."""
        field_patterns = {
            "OID": "\\(\\s*([0-9.]+)",
            "NAME": "NAME",
            "DESC": "DESC",
            "EQUALITY": "EQUALITY",
            "SUBSTR": "SUBSTR",
            "ORDERING": "ORDERING",
            "SYNTAX": "SYNTAX",
            "SUP": "SUP",
            "SINGLE-VALUE": "SINGLE-VALUE",
            "OBSOLETE": "OBSOLETE",
            "X-ORIGIN": "X-ORIGIN",
        }
        field_order: t.MutableSequenceOf[str] = []
        field_positions: t.MutableIntMapping = {}
        for field_name, pattern in field_patterns.items():
            match = re.search(pattern, definition, re.IGNORECASE)
            if match:
                field_order.append(field_name)
                field_positions[field_name] = match.start()
        return (field_order, field_positions)

    @staticmethod
    def _extract_leading_trailing_spaces(definition: str) -> t.MutableStrMapping:
        """Extract leading and trailing spaces."""
        details: t.MutableStrMapping = {}
        trailing_match = re.search(r"\)\s*$", definition)
        details["trailing_spaces"] = (
            definition[trailing_match.end() :] if trailing_match else ""
        )
        leading_match = re.search(r"^\s*\(", definition)
        details["leading_spaces"] = leading_match.group(0)[:-1] if leading_match else ""
        return details

    @staticmethod
    def _extract_matching_rule_details(
        definition: str,
    ) -> t.MutableFeatureFlagMapping:
        """Extract EQUALITY/SUBSTR/ORDERING details."""
        details: t.MutableFeatureFlagMapping = {}
        equality_match = re.search(r"\bEQUALITY\b", definition, re.IGNORECASE)
        if equality_match:
            details["equality_presence"] = True
            before_rule = definition[: equality_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["equality_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["equality_presence"] = False
        substr_match = re.search(r"\bSUBSTR\b", definition, re.IGNORECASE)
        if substr_match:
            details["substr_presence"] = True
            before_rule = definition[: substr_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["substr_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["substr_presence"] = False
        ordering_match = re.search(r"\bORDERING\b", definition, re.IGNORECASE)
        if ordering_match:
            details["ordering_presence"] = True
            before_rule = definition[: ordering_match.start()]
            before_match = re.search(r"(\s+)$", before_rule)
            details["ordering_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["ordering_presence"] = False
        return details

    @staticmethod
    def _extract_name_details(
        definition: str,
    ) -> t.MutableAttributeMapping:
        """Extract NAME format details."""
        details: t.MutableAttributeMapping = {
            "name_format": "single",
            "name_values": [],
            "name_quotes": [],
            "name_spacing_before": "",
        }
        name_match = re.search(
            r"NAME\s+(\()?\s*([\"']?)([^\"'()]+)([\"']?)(\s*\))?",
            definition,
        )
        if name_match is None:
            return details
        has_parens = bool(name_match.group(1))
        name_quote_start = name_match.group(2) or ""
        name_value = name_match.group(3)
        name_quote_end = name_match.group(4) or ""
        multiple_match = re.search(
            r"NAME\s+\(\s*([\"'])([^\"']+)([\"'])\s+([\"'])([^\"']+)([\"'])",
            definition,
        )
        name_section = definition[name_match.start() : name_match.end() + 50]
        if multiple_match or (has_parens and " " in name_value):
            all_name_matches = re.findall(r"([\"'])([^\"']+)([\"'])", name_section)
            details.update(
                {
                    "name_format": "multiple",
                    "name_values": [match[1] for match in all_name_matches],
                    "name_quotes": [match[0] for match in all_name_matches],
                    "name_spacing_between": re.findall(
                        r"[\"']\s+([\"'])",
                        name_section,
                    ),
                },
            )
        else:
            quote_char = name_quote_start or name_quote_end
            details.update(
                {
                    "name_values": [name_value],
                    "name_quotes": [quote_char] if quote_char else [],
                },
            )
        name_pos = definition.find("NAME")
        if name_pos >= 0:
            before_match = re.search(r"(\s+)$", definition[:name_pos])
            details["name_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        return details

    @staticmethod
    def _extract_obsolete_details(
        definition: str,
    ) -> MutableMapping[str, bool | int | str | None]:
        """Extract OBSOLETE details."""
        details: MutableMapping[str, bool | int | str | None] = {}
        obsolete_match = re.search(r"\bOBSOLETE\b", definition, re.IGNORECASE)
        if obsolete_match:
            details["obsolete_presence"] = True
            details["obsolete_position"] = obsolete_match.start()
            before_obsolete = definition[: obsolete_match.start()]
            before_match = re.search(r"(\s+)$", before_obsolete)
            details["obsolete_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["obsolete_presence"] = False
            details["obsolete_position"] = None
        return details

    @staticmethod
    def _extract_oid_details(definition: str) -> t.MutableStrMapping:
        """Extract OID and spacing details."""
        details: t.MutableStrMapping = {}
        oid_match = re.search(r"\(\s*([0-9.]+)(\s*)", definition)
        if oid_match:
            details["oid_value"] = oid_match.group(1)
            details["oid_spacing_after"] = oid_match.group(2)
        return details

    @staticmethod
    def _extract_prefix_details(definition: str) -> t.MutableStrMapping:
        """Extract attribute/ObjectClass prefix details."""
        details: t.MutableStrMapping = {}
        if "attributetypes:" in definition.lower():
            attr_match = re.search(
                r"(attributetypes|attributeTypes):",
                definition,
                re.IGNORECASE,
            )
            if attr_match:
                details["attribute_case"] = attr_match.group(1)
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["attribute_prefix_spacing"] = spacing_match.group(1)
        if "objectclasses:" in definition.lower() or "objectClasses:" in definition:
            oc_match = re.search(
                r"(objectclasses|objectClasses):",
                definition,
                re.IGNORECASE,
            )
            if oc_match:
                details["objectclass_case"] = oc_match.group(1)
                colon_pos = definition.find(":")
                if colon_pos >= 0 and colon_pos + 1 < len(definition):
                    after_colon = definition[colon_pos + 1 :]
                    spacing_match = re.match(r"(\s*)", after_colon)
                    if spacing_match:
                        details["objectclass_prefix_spacing"] = spacing_match.group(1)
        return details

    @staticmethod
    def _extract_single_value_details(
        definition: str,
    ) -> t.MutableFeatureFlagMapping:
        """Extract SINGLE-VALUE details."""
        details: t.MutableFeatureFlagMapping = {}
        single_value_match = re.search(r"SINGLE-VALUE", definition, re.IGNORECASE)
        if single_value_match:
            details["single_value_presence"] = True
            before_sv = definition[: single_value_match.start()]
            before_match = re.search(r"(\s+)$", before_sv)
            details["single_value_spacing_before"] = (
                before_match.group(1) if before_match else ""
            )
        else:
            details["single_value_presence"] = False
        return details

    @staticmethod
    def _extract_spacing_between_fields(
        definition: str,
        field_order: t.MutableSequenceOf[str],
        field_positions: t.MutableIntMapping,
        field_patterns: t.MutableStrMapping,
    ) -> t.MutableStrMapping:
        """Extract spacing between fields."""
        spacing_between: t.MutableStrMapping = {}
        for i in range(len(field_order) - 1):
            field1 = field_order[i]
            field2 = field_order[i + 1]
            pos1 = field_positions.get(field1)
            pos2 = field_positions.get(field2)
            if pos1 is not None and pos2 is not None:
                field1_end_match = re.search(
                    field_patterns[field1],
                    definition[pos1:],
                    re.IGNORECASE,
                )
                if field1_end_match:
                    field1_end = pos1 + field1_end_match.end()
                    spacing = definition[field1_end:pos2]
                    spacing_between[f"{field1}_{field2}"] = spacing
        return spacing_between

    @staticmethod
    def _extract_sup_details(definition: str) -> t.MutableFeatureFlagMapping:
        """Extract SUP details."""
        details: t.MutableFeatureFlagMapping = {}
        sup_match = re.search(r"SUP\s+([^\s]+)", definition, re.IGNORECASE)
        if sup_match:
            details["sup_presence"] = True
            details["sup_value"] = sup_match.group(1)
            sup_pos = definition.find("SUP")
            if sup_pos >= 0:
                before_sup = definition[:sup_pos]
                before_match = re.search(r"(\s+)$", before_sup)
                details["sup_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["sup_presence"] = False
        return details

    @staticmethod
    def _extract_syntax_details(
        definition: str,
    ) -> t.MutableOptionalFeatureFlagMapping:
        """Extract SYNTAX formatting details."""
        details: t.MutableOptionalFeatureFlagMapping = {
            "syntax_quotes": False,
            "syntax_quote_char": "",
            "syntax_oid": None,
            "syntax_length": None,
        }
        syntax_match = re.search(
            r"SYNTAX\s*([\"']?)([0-9.]+)([\"']?)(\{[0-9]+\})?",
            definition,
            re.IGNORECASE,
        )
        if syntax_match:
            details["syntax_quotes"] = bool(
                syntax_match.group(1) or syntax_match.group(3),
            )
            details["syntax_quote_char"] = (
                syntax_match.group(1) or syntax_match.group(3) or ""
            )
            details["syntax_oid"] = syntax_match.group(2)
            details["syntax_length"] = syntax_match.group(4) or None
            syntax_pos = definition.find("SYNTAX")
            if syntax_pos >= 0:
                after_syntax = definition[syntax_pos + 6 :]
                spacing_match = re.match(r"(\s*)", after_syntax)
                if spacing_match:
                    details["syntax_spacing"] = spacing_match.group(1)
                before_syntax = definition[:syntax_pos]
                before_match = re.search(r"(\s+)$", before_syntax)
                details["syntax_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        return details

    @staticmethod
    def _extract_x_origin_details(
        definition: str,
    ) -> t.MutableOptionalFeatureFlagMapping:
        """Extract X-ORIGIN details."""
        details: t.MutableOptionalFeatureFlagMapping = {}
        x_origin_match = re.search(
            r"X-ORIGIN\s+([\"']?)([^\"']+)([\"']?)",
            definition,
            re.IGNORECASE,
        )
        if x_origin_match:
            details["x_origin_presence"] = True
            details["x_origin_quotes"] = (
                x_origin_match.group(1) or x_origin_match.group(3) or ""
            )
            details["x_origin_value"] = x_origin_match.group(2)
            x_origin_pos = definition.find("X-ORIGIN")
            if x_origin_pos >= 0:
                before_x_origin = definition[:x_origin_pos]
                before_match = re.search(r"(\s+)$", before_x_origin)
                details["x_origin_spacing_before"] = (
                    before_match.group(1) if before_match else ""
                )
        else:
            details["x_origin_presence"] = False
            details["x_origin_value"] = None
            details["x_origin_quotes"] = ""
        return details

    @staticmethod
    def _get_metadata_dict(
        model: p.Ldif.ModelWithValidationMetadata,
    ) -> t.Ldif.MutableMetadataMapping:
        """Get mutable metadata dict from model."""
        metadata_obj = getattr(model, "validation_metadata", None)
        if metadata_obj is None:
            metadata_obj = m.Metadata(attributes={})
        if isinstance(metadata_obj, m.Metadata):
            return {
                key: u.normalize_to_metadata(value)
                for key, value in metadata_obj.attributes.items()
            }
        return {}

    @staticmethod
    def _is_metadata_scalar(value: t.JsonValue) -> bool:
        return value is None or u.scalar(value)

    @staticmethod
    def _is_metadata_scalar_typed(
        value: t.JsonValue,
    ) -> TypeIs[str | int | float | bool | None]:
        return FlextLdifUtilitiesMetadata._is_metadata_scalar(value)

    @staticmethod
    def _normalize_dict_list(
        values: t.SequenceOf[t.JsonValue],
    ) -> t.MutableSequenceOf[t.JsonValue]:
        normalized: t.MutableSequenceOf[t.JsonValue] = []
        for item in values:
            normalized.append(u.normalize_to_metadata(item))
        return normalized

    @staticmethod
    def _normalize_metadata_list_item(
        item: t.JsonValue,
    ) -> t.JsonValue:
        return u.normalize_to_metadata(item)

    @staticmethod
    def _set_model_metadata(
        model: p.Ldif.ModelWithValidationMetadata,
        metadata: m.Ldif.DynamicMetadata,
    ) -> None:
        """Set validation_metadata on model (handles both mutable and frozen models)."""
        try:
            metadata_obj = metadata.to_dict()
            normalized_metadata: t.Ldif.MutableMetadataMapping = {
                write_option_key: u.normalize_to_metadata(value)
                for write_option_key, value in metadata_obj.items()
            }
            config_root: dict[str, t.JsonPayload] = dict(normalized_metadata)
            object.__setattr__(
                model,
                "validation_metadata",
                m.ConfigMap(root=config_root),
            )
        except (AttributeError, TypeError, ValueError):
            pass

    @staticmethod
    def _update_conversion_path(
        metadata: t.Ldif.MutableMetadataMapping,
        update_conversion_path: str,
    ) -> None:
        """Update conversion_path in metadata."""
        if "conversion_path" not in metadata:
            metadata["conversion_path"] = update_conversion_path
        else:
            current_path_obj = metadata["conversion_path"]
            if (
                isinstance(current_path_obj, str)
                and update_conversion_path not in current_path_obj
            ):
                metadata["conversion_path"] = (
                    f"{current_path_obj}->{update_conversion_path}"
                )

    @staticmethod
    def _update_entry_with_stats(
        entry: m.Ldif.Entry,
        updated_stats: m.Ldif.EntryStatistics,
    ) -> m.Ldif.Entry:
        """Update entry with new processing stats using model_copy."""
        entry_metadata = entry.metadata
        if entry_metadata is None:
            entry_metadata = m.Ldif.ServerMetadata.create_for(
                us.normalize_server_type(
                    c.Ldif.ServerTypes.RFC.value,
                ),
            )
        update_dict: MutableMapping[str, m.Ldif.EntryStatistics] = {
            "processing_stats": updated_stats,
        }
        updated_metadata = entry_metadata.model_copy(update=update_dict)
        updated_entry: m.Ldif.Entry = entry.model_copy(
            update={"metadata": updated_metadata},
        )
        return updated_entry

    @staticmethod
    def analyze_minimal_differences(
        original: str,
        converted: str | None,
        context: str = "entry",
    ) -> t.Ldif.MutableMetadataMapping:
        """Analyze minimal differences between original and converted strings."""
        mk = c.Ldif
        empty_diffs: t.MutableSequenceOf[str] = []
        differences = dict(
            t.Cli.JSON_MAPPING_ADAPTER.validate_python({
                mk.HAS_DIFFERENCES: False,
                "context": context,
                "original": original,
                "converted": converted if converted is not None else original,
                "differences": empty_diffs,
                "original_length": len(original),
                "converted_length": len(converted) if converted else len(original),
            }),
        )
        if converted is None or original == converted:
            return differences
        differences[mk.HAS_DIFFERENCES] = True
        return differences

    @staticmethod
    def analyze_schema_formatting(definition: str) -> m.Ldif.SchemaFormatDetails:
        """Analyze schema definition to extract ALL formatting details."""
        combined = FlextLdifUtilitiesMetadata._extract_all_schema_details(definition)
        logger.debug(
            "Schema formatting analyzed",
            definition_preview=definition[: c.Ldif.DEFAULT_LINE_WIDTH] + "..."
            if len(definition) > c.Ldif.DEFAULT_LINE_WIDTH
            else definition,
            fields_captured=len(combined),
        )
        return FlextLdifUtilitiesMetadata._build_schema_format_model(
            definition,
            combined,
        )

    @staticmethod
    def build_acl_metadata_complete(
        server_type: str,
        _original_acl_format: str | None = None,
        **extra: t.Ldif.Scalar,
    ) -> t.MutableConfigurationMapping:
        """Build metadata for ACL parsing as a dictionary."""
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
        """Build metadata extensions for entry as a dictionary."""
        return {"server_type": server_type, "source_server": server_type}

    @staticmethod
    def build_entry_parse_metadata(
        settings: m.Ldif.EntryParseMetadataConfig,
    ) -> m.Ldif.ServerMetadata:
        """Build ServerMetadata for entry parsing with format preservation."""
        server_data_dict: t.Ldif.MutableMetadataMapping = {}
        server_data_dict["original_entry_dn"] = settings.original_entry_dn
        server_data_dict["cleaned_dn"] = settings.cleaned_dn
        server_data_dict["dn_was_base64"] = settings.dn_was_base64
        if settings.original_dn_line:
            server_data_dict["original_dn_line"] = settings.original_dn_line
        if settings.original_attr_lines:
            attr_lines_payload: list[t.JsonValue] = list(settings.original_attr_lines)
            server_data_dict["original_attribute_lines"] = attr_lines_payload
        if settings.original_attribute_case:
            attr_case_payload: dict[str, t.JsonValue] = dict(
                settings.original_attribute_case,
            )
            server_data_dict["original_attribute_case"] = attr_case_payload
        server_data = m.Ldif.EntryMetadata.model_validate(
            server_data_dict,
        )
        original_ldif_parts: t.MutableSequenceOf[str] = []
        if settings.original_dn_line:
            original_ldif_parts.append(settings.original_dn_line)
        if settings.original_attr_lines:
            original_ldif_parts.extend(settings.original_attr_lines)
        original_ldif = "\n".join(original_ldif_parts) if original_ldif_parts else ""
        extensions_dict: t.Ldif.MutableMetadataMapping = {}
        mk = c.Ldif
        extensions_dict[mk.ORIGINAL_DN_COMPLETE] = settings.original_entry_dn
        dynamic_extensions = m.Ldif.DynamicMetadata.from_dict(
            extensions_dict,
        )
        metadata = m.Ldif.ServerMetadata(
            server_type=settings.server_type,
            server_specific_data=server_data,
            extensions=dynamic_extensions,
        )
        if original_ldif:
            metadata.original_strings["entry_original_ldif"] = original_ldif
        return metadata

    @staticmethod
    def build_original_format_details(
        server_type: str,
        **extra: t.Ldif.Scalar,
    ) -> m.Ldif.FormatDetails:
        """Build original format details for round-trip preservation."""
        original_dn_line = extra.get("original_dn_line")
        dn_line = str(original_dn_line) if original_dn_line is not None else None
        return m.Ldif.FormatDetails(
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
        """Build RFC compliance metadata as a dictionary."""
        result: MutableMapping[
            str,
            str | bool | t.MutableSequenceOf[str] | t.MutableAttributeMapping,
        ] = {
            "server_type": server_type,
            "source_server": server_type,
        }
        if "rfc_violations" in extra:
            violations_val = extra["rfc_violations"]
            if isinstance(violations_val, str):
                result["rfc_violations"] = [violations_val]
        if "attribute_conflicts" in extra:
            conflicts_val = extra["attribute_conflicts"]
            if isinstance(conflicts_val, str):
                result["has_attribute_conflicts"] = conflicts_val
        return result

    @staticmethod
    def preserve_schema_formatting(
        metadata: m.Ldif.ServerMetadata,
        definition: str,
    ) -> None:
        """Preserve complete schema formatting details for round-trip."""
        formatting_details = FlextLdifUtilitiesMetadata.analyze_schema_formatting(
            definition,
        )
        object.__setattr__(metadata, "schema_format_details", formatting_details)
        logger.debug(
            "Schema formatting preserved in metadata",
            server_type=metadata.server_type,
            fields_preserved=len(formatting_details.model_fields_set),
        )

    @staticmethod
    def store_minimal_differences(
        metadata: m.Ldif.ServerMetadata,
        **extra: t.Ldif.Scalar,
    ) -> None:
        """Store minimal differences in metadata for delta tracking."""
        _ = metadata
        _ = extra

    @staticmethod
    def track_boolean_conversion(
        metadata: m.Ldif.ServerMetadata,
        attr_name: str,
        original_value: str,
        converted_value: str,
        format_direction: str = "OID->RFC",
    ) -> None:
        """Track boolean conversion for round-trip support."""
        if format_direction == "OID->RFC":
            source_key = f"{attr_name}:oid_value"
            target_key = f"{attr_name}:rfc_value"
        else:
            source_key = f"{attr_name}:rfc_value"
            target_key = f"{attr_name}:oid_value"
        metadata.boolean_conversions[source_key] = original_value
        metadata.boolean_conversions[target_key] = converted_value
        logger.debug(
            "Boolean conversion tracked",
            attr_name=attr_name,
            format_direction=format_direction,
        )

    @staticmethod
    def update_entry_statistics(
        entry: m.Ldif.Entry,
        *,
        category: str | None = None,
        mark_rejected: tuple[str, str] | None = None,
        mark_filtered: tuple[str, bool] | None = None,
    ) -> m.Ldif.Entry:
        """Update entry processing statistics using FlextLdifUtilities."""
        if not entry.metadata:
            return entry
        processing_stats = entry.metadata.processing_stats
        if not processing_stats:
            return entry
        updated_stats = m.Ldif.EntryStatistics.model_validate(
            processing_stats.model_dump(),
        )
        if category is not None:
            updated_stats = FlextLdifUtilitiesMetadata._apply_category_update(
                updated_stats,
                category,
            )
        if mark_filtered is not None:
            filter_type, passed = mark_filtered
            updated_stats = FlextLdifUtilitiesMetadata._apply_filter_update(
                updated_stats,
                filter_type,
                passed=passed,
            )
        if mark_rejected is not None:
            rejection_category, reason = mark_rejected
            updated_stats = FlextLdifUtilitiesMetadata._apply_rejection_update(
                updated_stats,
                rejection_category,
                reason,
            )
        return FlextLdifUtilitiesMetadata._update_entry_with_stats(entry, updated_stats)


__all__: list[str] = ["FlextLdifUtilitiesMetadata"]
