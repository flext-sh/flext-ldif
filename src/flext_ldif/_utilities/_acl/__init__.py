# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Acl package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._acl.extensions import FlextLdifUtilitiesACLExtensions
    from flext_ldif._utilities._acl.extract import FlextLdifUtilitiesACLExtract
    from flext_ldif._utilities._acl.format import FlextLdifUtilitiesACLFormat
    from flext_ldif._utilities._acl.parse import FlextLdifUtilitiesACLParse
    from flext_ldif._utilities._acl.permissions import FlextLdifUtilitiesACLPermissions


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesACLExtensions",
    "FlextLdifUtilitiesACLExtract",
    "FlextLdifUtilitiesACLFormat",
    "FlextLdifUtilitiesACLParse",
    "FlextLdifUtilitiesACLPermissions",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesACLExtensions": ".extensions",
        "FlextLdifUtilitiesACLExtract": ".extract",
        "FlextLdifUtilitiesACLFormat": ".format",
        "FlextLdifUtilitiesACLParse": ".parse",
        "FlextLdifUtilitiesACLPermissions": ".permissions",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesACLExtensions": (
            "_module_logger",
            "_OPERATOR_PLACEHOLDER",
            "_format_bind_rule_from_extension",
            "extract_bind_rules_from_extensions",
            "extract_target_extensions",
            "format_conversion_comments",
        ),
        "FlextLdifUtilitiesACLExtract": (
            "_extract_from_match",
            "extract_component",
            "extract_permissions",
            "extract_bind_rules",
        ),
        "FlextLdifUtilitiesACLFormat": (
            "build_aci_target_clause",
            "format_aci_subject",
            "sanitize_acl_name",
            "format_aci_line",
            "build_metadata_extensions",
            "split_acl_line",
            "validate_aci_format",
        ),
        "FlextLdifUtilitiesACLParse": (
            "_check_special_value",
            "build_aci_subject",
            "parse_targetattr",
            "_extract_target_info",
            "_extract_version_and_name",
            "_build_extensions",
            "_build_subject_and_permissions",
            "parse_aci",
        ),
        "FlextLdifUtilitiesACLPermissions": (
            "valid_acl_subject_type",
            "_normalize_permission",
            "_process_permission_list",
            "build_permissions_dict",
            "normalize_permission_key",
            "_normalized_permissions",
            "_pass_through_permissions",
            "map_oid_to_oud_permissions",
            "map_oud_to_oid_permissions",
            "build_mapped_permissions_dict",
            "filter_supported_permissions",
        ),
    },
)
