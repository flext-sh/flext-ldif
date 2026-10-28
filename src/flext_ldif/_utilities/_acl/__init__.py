# AUTO-GENERATED FILE — Regenerate with: make gen
"""Internal package for acl.

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
    MappingProxyType({
        "FlextLdifUtilitiesACLExtensions": ".extensions",
        "FlextLdifUtilitiesACLExtract": ".extract",
        "FlextLdifUtilitiesACLFormat": ".format",
        "FlextLdifUtilitiesACLParse": ".parse",
        "FlextLdifUtilitiesACLPermissions": ".permissions",
    }),
    public_exports=__all__,
)
