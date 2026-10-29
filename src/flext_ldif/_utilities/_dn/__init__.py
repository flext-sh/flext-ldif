# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Dn package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
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
    MappingProxyType({
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
    }),
    public_exports=__all__,
)
