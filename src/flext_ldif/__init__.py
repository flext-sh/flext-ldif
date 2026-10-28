# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif package.

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
    from flext_cli import (
        build_lazy_import_map,
        cleanup_submodule_namespace,
        cli,
        core,
        d,
        e,
        h,
        install_lazy_exports,
        lazy,
        lazy_getattr,
        lazy_member,
        merge_lazy_imports,
        normalize_lazy_imports,
        r,
        resolve_lazy_members,
        x,
    )

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
    "build_lazy_import_map",
    "c",
    "cleanup_submodule_namespace",
    "cli",
    "config",
    "core",
    "d",
    "e",
    "h",
    "install_lazy_exports",
    "lazy",
    "lazy_getattr",
    "lazy_member",
    "ldif",
    "m",
    "main",
    "merge_lazy_imports",
    "normalize_lazy_imports",
    "p",
    "r",
    "resolve_lazy_members",
    "s",
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
        "build_lazy_import_map": "flext_cli",
        "c": ".constants",
        "cleanup_submodule_namespace": "flext_cli",
        "cli": "flext_cli",
        "config": "._config",
        "core": "flext_cli",
        "d": "flext_cli",
        "e": "flext_cli",
        "h": "flext_cli",
        "install_lazy_exports": "flext_cli",
        "lazy": "flext_cli",
        "lazy_getattr": "flext_cli",
        "lazy_member": "flext_cli",
        "ldif": ".api",
        "m": ".models",
        "main": ".cli",
        "merge_lazy_imports": "flext_cli",
        "normalize_lazy_imports": "flext_cli",
        "p": ".protocols",
        "r": "flext_cli",
        "resolve_lazy_members": "flext_cli",
        "s": ".base",
        "settings": "._settings",
        "t": ".typings",
        "u": ".utilities",
        "x": "flext_cli",
    }),
    public_exports=__all__,
)

if not TYPE_CHECKING:
    from flext_ldif.__version__ import __version__
