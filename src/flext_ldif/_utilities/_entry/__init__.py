# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for entry.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
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
    MappingProxyType({
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
    }),
    public_exports=__all__,
)
