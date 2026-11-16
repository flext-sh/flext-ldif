# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Dn package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._dn.chars import FlextLdifUtilitiesDNChars
    from flext_ldif._utilities._dn.clean import FlextLdifUtilitiesDNClean
    from flext_ldif._utilities._dn.escape import FlextLdifUtilitiesDNEscape
    from flext_ldif._utilities._dn.hierarchy import FlextLdifUtilitiesDNHierarchy
    from flext_ldif._utilities._dn.normalize import FlextLdifUtilitiesDNNormalize
    from flext_ldif._utilities._dn.parse import FlextLdifUtilitiesDNParse
    from flext_ldif._utilities._dn.rdn import FlextLdifUtilitiesDNRdn
    from flext_ldif._utilities._dn.rebase import FlextLdifUtilitiesDNRebase
    from flext_ldif._utilities._dn.transform import FlextLdifUtilitiesDNTransform
    from flext_ldif._utilities._dn.validate import FlextLdifUtilitiesDNValidate


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesDNChars",
    "FlextLdifUtilitiesDNClean",
    "FlextLdifUtilitiesDNEscape",
    "FlextLdifUtilitiesDNHierarchy",
    "FlextLdifUtilitiesDNNormalize",
    "FlextLdifUtilitiesDNParse",
    "FlextLdifUtilitiesDNRdn",
    "FlextLdifUtilitiesDNRebase",
    "FlextLdifUtilitiesDNTransform",
    "FlextLdifUtilitiesDNValidate",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesDNChars": ".chars",
        "FlextLdifUtilitiesDNClean": ".clean",
        "FlextLdifUtilitiesDNEscape": ".escape",
        "FlextLdifUtilitiesDNHierarchy": ".hierarchy",
        "FlextLdifUtilitiesDNNormalize": ".normalize",
        "FlextLdifUtilitiesDNParse": ".parse",
        "FlextLdifUtilitiesDNRdn": ".rdn",
        "FlextLdifUtilitiesDNRebase": ".rebase",
        "FlextLdifUtilitiesDNTransform": ".transform",
        "FlextLdifUtilitiesDNValidate": ".validate",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesDNChars": (
            "_is_rfc_char_class",
            "lutf1_char",
            "sutf1_char",
            "tutf1_char",
            "utfmb_char",
            "valid_dn_string",
        ),
        "FlextLdifUtilitiesDNClean": (
            "_apply_dn_transformations",
            "_statistics_from_flags",
            "clean_dn",
            "clean_dn_with_statistics",
        ),
        "FlextLdifUtilitiesDNEscape": (
            "esc",
            "unesc",
        ),
        "FlextLdifUtilitiesDNHierarchy": (
            "under_base",
            "hierarchy_key",
        ),
        "FlextLdifUtilitiesDNNormalize": (
            "norm",
            "norm_or_fallback",
            "dn_key",
            "_normalize_dns_for_comparison",
            "_compare_dns_core",
            "compare_dns",
        ),
        "FlextLdifUtilitiesDNParse": (
            "resolve_dn_value",
            "split",
            "_parse_dn_components",
            "parse_dn",
        ),
        "FlextLdifUtilitiesDNRdn": ("parse_rdn",),
        "FlextLdifUtilitiesDNRebase": (
            "_first_rdn_component",
            "_rdn_attribute_pairs",
            "_modrdn_naming_delta",
            "_rebase_entry_dn",
            "_transform_dn_valued_values",
            "_collect_changed_dn_attrs",
            "_merge_rdn_delta_values",
            "_apply_rdn_delta",
            "_apply_changed_attributes",
            "transform_entry_base_dn",
        ),
        "FlextLdifUtilitiesDNTransform": (
            "transform_dn_attribute",
            "_transform_ldif_content",
            "transform_ldif_files_in_directory",
        ),
        "FlextLdifUtilitiesDNValidate": (
            "_has_double_unescaped_commas",
            "_consume_dn_escape",
            "_validate_escape_sequences",
            "_validate_basic_format",
            "_validate_components",
            "_validate_dn_structure",
            "validate_dn",
        ),
    },
)
