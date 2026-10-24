# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_cli import d, e, h, r, x

    from flext_ldif import servers as servers, services as services
    from flext_ldif.__version__ import (
        FlextLdifVersion,
        __author__,
        __author_email__,
        __description__,
        __license__,
        __title__,
        __url__,
        __version__,
        __version_info__,
    )
    from flext_ldif._config import FlextLdifConfig, config
    from flext_ldif._settings import FlextLdifSettings, settings
    from flext_ldif.api import FlextLdif, ldif
    from flext_ldif.base import FlextLdifServiceBase, s
    from flext_ldif.cli import main
    from flext_ldif.constants import FlextLdifConstants, c
    from flext_ldif.models import FlextLdifModels, m
    from flext_ldif.protocols import FlextLdifProtocols, p
    from flext_ldif.shared import FlextLdifShared
    from flext_ldif.typings import FlextLdifTypes, t
    from flext_ldif.utilities import FlextLdifUtilities, u


__all__: tuple[str, ...] = (
    "FlextLdif",
    "FlextLdifConfig",
    "FlextLdifConstants",
    "FlextLdifModels",
    "FlextLdifProtocols",
    "FlextLdifServiceBase",
    "FlextLdifSettings",
    "FlextLdifShared",
    "FlextLdifTypes",
    "FlextLdifUtilities",
    "FlextLdifVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
    "c",
    "config",
    "d",
    "e",
    "h",
    "ldif",
    "m",
    "main",
    "p",
    "r",
    "s",
    "servers",
    "services",
    "settings",
    "t",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdif": ".api",
        "FlextLdifConfig": "._config",
        "FlextLdifConstants": ".constants",
        "FlextLdifModels": ".models",
        "FlextLdifProtocols": ".protocols",
        "FlextLdifServiceBase": ".base",
        "FlextLdifSettings": "._settings",
        "FlextLdifShared": ".shared",
        "FlextLdifTypes": ".typings",
        "FlextLdifUtilities": ".utilities",
        "FlextLdifVersion": ".__version__",
        "__author__": ".__version__",
        "__author_email__": ".__version__",
        "__description__": ".__version__",
        "__license__": ".__version__",
        "__title__": ".__version__",
        "__url__": ".__version__",
        "__version_info__": ".__version__",
        "c": ".constants",
        "config": "._config",
        "d": "flext_cli",
        "e": "flext_cli",
        "h": "flext_cli",
        "ldif": ".api",
        "m": ".models",
        "main": ".cli",
        "p": ".protocols",
        "r": "flext_cli",
        "s": ".base",
        "servers": ".servers",
        "services": ".services",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_cli",
    }),
    public_exports=__all__,
)

if not TYPE_CHECKING:
    from flext_ldif.__version__ import __version__
