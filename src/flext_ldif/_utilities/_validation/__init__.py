# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for validation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._validation.ldif_value import (
        FlextLdifUtilitiesValidationLdifValue,
    )
    from flext_ldif._utilities._validation.rfc import FlextLdifUtilitiesValidationRfc

__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesValidationLdifValue",
    "FlextLdifUtilitiesValidationRfc",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesValidationLdifValue": ".ldif_value",
        "FlextLdifUtilitiesValidationRfc": ".rfc",
    }),
    public_exports=__all__,
)
