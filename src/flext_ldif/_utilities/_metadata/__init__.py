# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Metadata package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._metadata.builders import (
        FlextLdifUtilitiesMetadataBuilders,
    )
    from flext_ldif._utilities._metadata.entry_stats import (
        FlextLdifUtilitiesMetadataEntryStats,
    )
    from flext_ldif._utilities._metadata.json_core import (
        FlextLdifUtilitiesMetadataJsonCore,
    )
    from flext_ldif._utilities._metadata.match import FlextLdifUtilitiesMetadataMatch
    from flext_ldif._utilities._metadata.name_desc import (
        FlextLdifUtilitiesMetadataNameDesc,
    )
    from flext_ldif._utilities._metadata.prefix import FlextLdifUtilitiesMetadataPrefix
    from flext_ldif._utilities._metadata.schema_analysis import (
        FlextLdifUtilitiesMetadataSchemaAnalysis,
    )
    from flext_ldif._utilities._metadata.spacing import (
        FlextLdifUtilitiesMetadataSpacing,
    )
    from flext_ldif._utilities._metadata.syntax_origin import (
        FlextLdifUtilitiesMetadataSyntaxOrigin,
    )
    from flext_ldif._utilities._metadata.tracking import (
        FlextLdifUtilitiesMetadataTracking,
    )


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesMetadataBuilders",
    "FlextLdifUtilitiesMetadataEntryStats",
    "FlextLdifUtilitiesMetadataJsonCore",
    "FlextLdifUtilitiesMetadataMatch",
    "FlextLdifUtilitiesMetadataNameDesc",
    "FlextLdifUtilitiesMetadataPrefix",
    "FlextLdifUtilitiesMetadataSchemaAnalysis",
    "FlextLdifUtilitiesMetadataSpacing",
    "FlextLdifUtilitiesMetadataSyntaxOrigin",
    "FlextLdifUtilitiesMetadataTracking",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesMetadataBuilders": ".builders",
        "FlextLdifUtilitiesMetadataEntryStats": ".entry_stats",
        "FlextLdifUtilitiesMetadataJsonCore": ".json_core",
        "FlextLdifUtilitiesMetadataMatch": ".match",
        "FlextLdifUtilitiesMetadataNameDesc": ".name_desc",
        "FlextLdifUtilitiesMetadataPrefix": ".prefix",
        "FlextLdifUtilitiesMetadataSchemaAnalysis": ".schema_analysis",
        "FlextLdifUtilitiesMetadataSpacing": ".spacing",
        "FlextLdifUtilitiesMetadataSyntaxOrigin": ".syntax_origin",
        "FlextLdifUtilitiesMetadataTracking": ".tracking",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesMetadataBuilders": (
            "server_metadata_for",
            "build_acl_metadata_complete",
            "build_entry_metadata_extensions",
            "_collect_parse_server_data",
            "_collect_original_ldif",
            "build_entry_parse_metadata",
            "build_original_format_details",
            "build_rfc_compliance_metadata",
        ),
        "FlextLdifUtilitiesMetadataEntryStats": ("update_entry_statistics",),
        "FlextLdifUtilitiesMetadataJsonCore": (
            "dump_json_payload",
            "dump_dynamic_metadata",
            "_add_to_dict_metadata",
            "_get_metadata_dict",
            "_is_metadata_scalar",
            "_normalize_dict_list",
            "_update_conversion_path",
        ),
        "FlextLdifUtilitiesMetadataMatch": (
            "extract_matching_rule_details",
            "extract_sup_details",
            "extract_single_value_details",
            "extract_leading_trailing_spaces",
        ),
        "FlextLdifUtilitiesMetadataNameDesc": (
            "extract_name_details",
            "extract_desc_details",
        ),
        "FlextLdifUtilitiesMetadataPrefix": (
            "PrefixSpec",
            "_extract_single_prefix_details",
            "extract_prefix_details",
        ),
        "FlextLdifUtilitiesMetadataSchemaAnalysis": (
            "_FIELD_PATTERNS",
            "_extract_field_order",
            "_extract_spacing_between_fields",
            "_extract_all_schema_details",
            "_build_schema_format_model",
            "analyze_schema_formatting",
            "preserve_schema_formatting",
        ),
        "FlextLdifUtilitiesMetadataSpacing": (
            "spacing_before",
            "token_details",
        ),
        "FlextLdifUtilitiesMetadataSyntaxOrigin": (
            "extract_syntax_details",
            "extract_x_origin_details",
            "extract_obsolete_details",
            "extract_oid_details",
        ),
        "FlextLdifUtilitiesMetadataTracking": (
            "_module_logger",
            "track_boolean_conversion",
        ),
    },
)
