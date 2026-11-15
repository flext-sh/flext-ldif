# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Entry package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._entry.access import FlextLdifUtilitiesEntryAccess
    from flext_ldif._utilities._entry.analysis import FlextLdifUtilitiesEntryAnalysis
    from flext_ldif._utilities._entry.attr_validation import (
        FlextLdifUtilitiesEntryAttrValidation,
    )
    from flext_ldif._utilities._entry.boolean import FlextLdifUtilitiesEntryBoolean
    from flext_ldif._utilities._entry.criteria import FlextLdifUtilitiesEntryCriteria
    from flext_ldif._utilities._entry.matching import FlextLdifUtilitiesEntryMatching
    from flext_ldif._utilities._entry.oid_rfc import FlextLdifUtilitiesEntryOidRfc
    from flext_ldif._utilities._entry.rfc_violations import (
        FlextLdifUtilitiesEntryRfcViolations,
    )
    from flext_ldif._utilities._entry.server_rules import (
        FlextLdifUtilitiesEntryServerRules,
    )
    from flext_ldif._utilities._entry.validation import (
        FlextLdifUtilitiesEntryValidation,
    )


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesEntryAccess",
    "FlextLdifUtilitiesEntryAnalysis",
    "FlextLdifUtilitiesEntryAttrValidation",
    "FlextLdifUtilitiesEntryBoolean",
    "FlextLdifUtilitiesEntryCriteria",
    "FlextLdifUtilitiesEntryMatching",
    "FlextLdifUtilitiesEntryOidRfc",
    "FlextLdifUtilitiesEntryRfcViolations",
    "FlextLdifUtilitiesEntryServerRules",
    "FlextLdifUtilitiesEntryValidation",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesEntryAccess": ".access",
        "FlextLdifUtilitiesEntryAnalysis": ".analysis",
        "FlextLdifUtilitiesEntryAttrValidation": ".attr_validation",
        "FlextLdifUtilitiesEntryBoolean": ".boolean",
        "FlextLdifUtilitiesEntryCriteria": ".criteria",
        "FlextLdifUtilitiesEntryMatching": ".matching",
        "FlextLdifUtilitiesEntryOidRfc": ".oid_rfc",
        "FlextLdifUtilitiesEntryRfcViolations": ".rfc_violations",
        "FlextLdifUtilitiesEntryServerRules": ".server_rules",
        "FlextLdifUtilitiesEntryValidation": ".validation",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesEntryAccess": (
            "resolve_attribute_values",
            "resolve_objectclass_names",
            "has_attribute",
            "has_object_class",
            "matches_filter",
        ),
        "FlextLdifUtilitiesEntryAnalysis": (
            "logger",
            "analyze_minimal_differences",
            "_collect_original_attribute_case",
            "_original_values_list",
            "_analyze_attribute_differences",
            "analyze_differences",
            "normalize_unconverted_attributes",
        ),
        "FlextLdifUtilitiesEntryAttrValidation": (
            "_base_name_violation",
            "_option_violation",
            "_iter_attribute_parts",
            "validate_attribute_descriptions",
            "validate_attribute_syntax",
            "validate_binary_options",
        ),
        "FlextLdifUtilitiesEntryBoolean": (
            "_raw_value_items",
            "_decode_raw_value",
            "_convert_boolean_value",
            "convert_boolean_attributes",
        ),
        "FlextLdifUtilitiesEntryCriteria": (
            "_membership_criterion",
            "_schema_criterion",
            "_objectclass_criterion",
            "_attrs_criterion",
            "_required_attrs_criterion",
            "_any_attrs_criterion",
            "_dn_pattern_criterion",
            "matches_criteria",
        ),
        "FlextLdifUtilitiesEntryMatching": (
            "detects_schema_entry",
            "matches_entry_server_patterns",
        ),
        "FlextLdifUtilitiesEntryOidRfc": (
            "remap_oid_rfc_attributes",
            "transform_entry_attributes_between_oid_rfc",
            "transform_schema_dn_between_oid_rfc",
        ),
        "FlextLdifUtilitiesEntryRfcViolations": (
            "logger",
            "collect_rfc_violations",
            "rfc_violation_context",
        ),
        "FlextLdifUtilitiesEntryServerRules": (
            "check_binary_option_rule",
            "check_naming_attr_rule",
            "check_objectclass_rule",
            "parse_validation_rules",
        ),
        "FlextLdifUtilitiesEntryValidation": (
            "validate_dn_format",
            "dn_components",
            "naming_attribute",
            "dn_component_violations",
            "validate_attributes_required",
            "validate_changetype",
            "_attribute_required",
            "validate_naming_attribute",
            "validate_objectclass",
        ),
    },
)
