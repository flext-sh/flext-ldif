# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Schema package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._schema.build import FlextLdifUtilitiesSchemaBuild
    from flext_ldif._utilities._schema.extract import FlextLdifUtilitiesSchemaExtract
    from flext_ldif._utilities._schema.format import FlextLdifUtilitiesSchemaFormat
    from flext_ldif._utilities._schema.normalize import (
        FlextLdifUtilitiesSchemaNormalize,
    )
    from flext_ldif._utilities._schema.parse import FlextLdifUtilitiesSchemaParse


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesSchemaBuild",
    "FlextLdifUtilitiesSchemaExtract",
    "FlextLdifUtilitiesSchemaFormat",
    "FlextLdifUtilitiesSchemaNormalize",
    "FlextLdifUtilitiesSchemaParse",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesSchemaBuild": ".build",
        "FlextLdifUtilitiesSchemaExtract": ".extract",
        "FlextLdifUtilitiesSchemaFormat": ".format",
        "FlextLdifUtilitiesSchemaNormalize": ".normalize",
        "FlextLdifUtilitiesSchemaParse": ".parse",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesSchemaBuild": (
            "_build_attribute_parts_from_model",
            "_append_objectclass_core_parts",
            "_build_objectclass_parts_from_model",
            "_write_schema_element",
            "build_attribute_parts_with_metadata",
            "build_objectclass_parts_with_metadata",
            "should_restore_schema_original_format",
            "validate_syntax_oid",
            "write_attribute",
            "write_objectclass",
        ),
        "FlextLdifUtilitiesSchemaExtract": (
            "schema_definition_identifiers",
            "logger",
            "extract_attribute_flags",
            "extract_attribute_matching_rules",
            "extract_attribute_sup_usage",
            "extract_attribute_syntax",
            "extract_objectclass_kind",
            "extract_objectclass_must_may",
            "extract_objectclass_sup",
            "extract_schema_basic_fields",
            "extract_schema_items_from_lines",
            "split_schema_values",
        ),
        "FlextLdifUtilitiesSchemaFormat": (
            "apply_trailing_spaces",
            "build_name_part",
            "build_obsolete_part",
            "build_x_origin_part",
            "format_attribute_list",
            "format_sup_list",
            "resolve_field_order",
            "try_restore_objectclass_original_format",
            "try_restore_original_format",
        ),
        "FlextLdifUtilitiesSchemaNormalize": (
            "schema_definition_semantics",
            "build_available_attributes_set",
            "boolean_attribute",
            "normalize_attribute_name",
            "normalize_matching_rules",
            "normalize_name",
            "normalize_syntax_oid",
            "replace_invalid_substr_rule",
        ),
        "FlextLdifUtilitiesSchemaParse": (
            "_module_logger",
            "_convert_metadata_extensions",
            "_validate_attribute_syntax",
            "build_metadata",
            "_detect_schema_kind_from_text",
            "detect_schema_type",
            "extract_attributes_from_lines",
            "extract_objectclasses_from_lines",
            "parse_attribute",
            "_attribute_syntax_fields",
            "_validated_syntax_extensions",
            "parse_objectclass",
        ),
    },
)
