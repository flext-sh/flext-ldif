# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Server package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._server.config import FlextLdifUtilitiesServerConfig
    from flext_ldif._utilities._server.detect import FlextLdifUtilitiesServerDetect
    from flext_ldif._utilities._server.server_type import (
        FlextLdifUtilitiesServerServerType,
    )


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesServerConfig",
    "FlextLdifUtilitiesServerDetect",
    "FlextLdifUtilitiesServerServerType",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifUtilitiesServerConfig": ".config",
        "FlextLdifUtilitiesServerDetect": ".detect",
        "FlextLdifUtilitiesServerServerType": ".server_type",
    },
    public_exports=__all__,
    deferred_members={
        "FlextLdifUtilitiesServerConfig": (
            "normalize_server_type",
            "resolve_all_server_types",
            "resolve_server_type_value",
            "matches",
            "resolve_attribute_match_score",
            "resolve_confidence_threshold",
            "resolve_server_detection_default_max_lines",
            "validation_rule_flags",
        ),
        "FlextLdifUtilitiesServerDetect": (
            "_check_name_patterns",
            "_extract_pattern_name_candidates",
            "_matches_definition_text",
            "entry_carries_markers",
            "matches_server_patterns",
        ),
        "FlextLdifUtilitiesServerServerType": (
            "_is_valid_server_type",
            "_extract_server_name",
            "extract_server_type_from_constants",
            "_get_type_from_independent_class",
            "_resolve_parent_class",
            "_server_type_from_parent",
            "_server_type_from_mro",
            "_get_type_from_nested_class",
            "resolve_parent_server_type",
        ),
    },
)
