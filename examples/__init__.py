# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from examples.constants import ExamplesFlextLdifConstants
    from examples.models import ExamplesFlextLdifModels
    from examples.protocols import ExamplesFlextLdifProtocols
    from examples.typings import ExamplesFlextLdifTypes
    from examples.utilities import ExamplesFlextLdifUtilities
    from flext_ldif import c, d, e, h, m, p, r, s, t, u, x


__all__: tuple[str, ...] = (
    "ExamplesFlextLdifConstants",
    "ExamplesFlextLdifModels",
    "ExamplesFlextLdifProtocols",
    "ExamplesFlextLdifTypes",
    "ExamplesFlextLdifUtilities",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "ExamplesFlextLdifConstants": ".constants",
        "ExamplesFlextLdifModels": ".models",
        "ExamplesFlextLdifProtocols": ".protocols",
        "ExamplesFlextLdifTypes": ".typings",
        "ExamplesFlextLdifUtilities": ".utilities",
        "c": "flext_ldif",
        "d": "flext_ldif",
        "e": "flext_ldif",
        "h": "flext_ldif",
        "m": "flext_ldif",
        "p": "flext_ldif",
        "r": "flext_ldif",
        "s": "flext_ldif",
        "t": "flext_ldif",
        "u": "flext_ldif",
        "x": "flext_ldif",
    }),
    public_exports=__all__,
)
