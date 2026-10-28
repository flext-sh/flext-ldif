# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for metadata.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
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
    MappingProxyType({
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
    }),
    public_exports=__all__,
)
