# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Utilities. Writer package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._utilities._writer.chars import FlextLdifUtilitiesWriterChars
    from flext_ldif._utilities._writer.fold import FlextLdifUtilitiesWriterFold
    from flext_ldif._utilities._writer.schema import FlextLdifUtilitiesWriterSchema


__all__: tuple[str, ...] = (
    "FlextLdifUtilitiesWriterChars",
    "FlextLdifUtilitiesWriterFold",
    "FlextLdifUtilitiesWriterSchema",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifUtilitiesWriterChars": ".chars",
        "FlextLdifUtilitiesWriterFold": ".fold",
        "FlextLdifUtilitiesWriterSchema": ".schema",
    }),
    public_exports=__all__,
)
