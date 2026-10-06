"""LDIF schema formatting analysis orchestration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable

from flext_ldif import FlextLdifModels, c, t
from flext_ldif._utilities._metadata_match import FlextLdifMetadataMatchDetails
from flext_ldif._utilities._metadata_name_desc import FlextLdifMetadataNameDescDetails
from flext_ldif._utilities._metadata_prefix import FlextLdifMetadataPrefixDetails
from flext_ldif._utilities._metadata_syntax_origin import (
    FlextLdifMetadataSyntaxOriginDetails,
)

_FIELD_PATTERNS: t.MutableStrMapping = {
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


class FlextLdifMetadataSchemaAnalysis:
    """Analyze complete schema definition formatting for round-trip fidelity."""

    @staticmethod
    def _extract_field_order(
        definition: str,
    ) -> tuple[t.MutableSequenceOf[str], t.MutableIntMapping]:
        """Extract field order and positions.

        Returns:
            The resulting ``tuple[t.MutableSequenceOf[str], t.MutableIntMapping]``.
        """
        field_order: t.MutableSequenceOf[str] = []
        field_positions: t.MutableIntMapping = {}
        for field_name, pattern in _FIELD_PATTERNS.items():
            match = c.Ldif.compile_pattern(pattern, ignorecase=True).search(definition)
            if match:
                field_order.append(field_name)
                field_positions[field_name] = match.start()
        return (field_order, field_positions)

    @staticmethod
    def _extract_spacing_between_fields(
        definition: str,
        field_order: t.MutableSequenceOf[str],
        field_positions: t.MutableIntMapping,
        field_patterns: t.MutableStrMapping,
    ) -> t.MutableStrMapping:
        """Extract spacing between fields.

        Returns:
            The resulting ``t.MutableStrMapping``.
        """
        spacing_between: t.MutableStrMapping = {}
        for i in range(len(field_order) - 1):
            field1 = field_order[i]
            field2 = field_order[i + 1]
            pos1 = field_positions.get(field1)
            pos2 = field_positions.get(field2)
            if pos1 is not None and pos2 is not None:
                field1_end_match = c.Ldif.compile_pattern(
                    field_patterns[field1],
                    ignorecase=True,
                ).search(definition[pos1:])
                if field1_end_match:
                    field1_end = pos1 + field1_end_match.end()
                    spacing = definition[field1_end:pos2]
                    spacing_between[f"{field1}_{field2}"] = spacing
        return spacing_between

    @staticmethod
    def _extract_all_schema_details(definition: str) -> t.Ldif.MutableMetadataMapping:
        """Extract all schema formatting details into combined dict.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        combined: t.Ldif.MutableMetadataMapping = {}
        extractors: t.SequenceOf[
            Callable[
                [str],
                t.MappingKV[str, str | bool | int | t.MutableSequenceOf[str] | None],
            ]
        ] = [
            FlextLdifMetadataPrefixDetails.extract_prefix_details,
            FlextLdifMetadataSyntaxOriginDetails.extract_oid_details,
            FlextLdifMetadataSyntaxOriginDetails.extract_syntax_details,
            FlextLdifMetadataNameDescDetails.extract_name_details,
            FlextLdifMetadataNameDescDetails.extract_desc_details,
            FlextLdifMetadataSyntaxOriginDetails.extract_x_origin_details,
            FlextLdifMetadataSyntaxOriginDetails.extract_obsolete_details,
            FlextLdifMetadataMatchDetails.extract_leading_trailing_spaces,
            FlextLdifMetadataMatchDetails.extract_matching_rule_details,
            FlextLdifMetadataMatchDetails.extract_sup_details,
            FlextLdifMetadataMatchDetails.extract_single_value_details,
        ]
        for extractor in extractors:
            extracted_raw = extractor(definition)
            for write_option_key, value in extracted_raw.items():
                combined[write_option_key] = t.Cli.JSON_VALUE_ADAPTER.validate_python(
                    value,
                )
        field_order, field_positions = (
            FlextLdifMetadataSchemaAnalysis._extract_field_order(definition)
        )
        field_order_payload: t.JsonValueList = list(field_order)
        field_positions_payload: t.JsonDict = dict(field_positions)
        combined["field_order"] = field_order_payload
        combined["field_positions"] = field_positions_payload
        spacing_result = (
            FlextLdifMetadataSchemaAnalysis._extract_spacing_between_fields(
                definition,
                field_order,
                field_positions,
                dict(_FIELD_PATTERNS),
            )
        )
        spacing_payload: t.JsonDict = dict(spacing_result)
        combined["spacing_between_fields"] = spacing_payload
        return combined

    @staticmethod
    def _build_schema_format_model(
        definition: str,
        combined: t.Ldif.MutableMetadataMapping,
    ) -> FlextLdifModels.Ldif.SchemaFormatDetails:
        """Build SchemaFormatDetails model from combined details.

        Returns:
            The resulting ``FlextLdifModels.Ldif.SchemaFormatDetails``.
        """
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
        details: FlextLdifModels.Ldif.SchemaFormatDetails = (
            FlextLdifModels.Ldif.SchemaFormatDetails.model_validate({
                **known_field_values,
                "extensions": extension_kwargs,
            })
        )
        return details

    @staticmethod
    def analyze_schema_formatting(
        definition: str,
    ) -> FlextLdifModels.Ldif.SchemaFormatDetails:
        """Analyze schema definition to extract ALL formatting details.

        Returns:
            The resulting ``FlextLdifModels.Ldif.SchemaFormatDetails``.
        """
        combined = FlextLdifMetadataSchemaAnalysis._extract_all_schema_details(
            definition,
        )
        return FlextLdifMetadataSchemaAnalysis._build_schema_format_model(
            definition,
            combined,
        )

    @staticmethod
    def preserve_schema_formatting(
        metadata: FlextLdifModels.Ldif.ServerMetadata,
        definition: str,
    ) -> None:
        """Preserve complete schema formatting details for round-trip."""
        formatting_details = FlextLdifMetadataSchemaAnalysis.analyze_schema_formatting(
            definition,
        )
        target: FlextLdifModels.Ldif.ServerMetadata = metadata
        target.schema_format_details = formatting_details


__all__: list[str] = ["FlextLdifMetadataSchemaAnalysis"]
