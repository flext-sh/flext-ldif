# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_tests import (
        api,
        cli,
        config,
        d,
        e,
        h,
        install_local_packages,
        main,
        r,
        settings,
        td,
        tf,
        tk,
        tm,
        x,
    )

    from flext_ldif import (
        build_lazy_import_map,
        cleanup_submodule_namespace,
        core,
        install_lazy_exports,
        lazy,
        lazy_getattr,
        lazy_member,
        ldif,
        merge_lazy_imports,
        normalize_lazy_imports,
        resolve_lazy_members,
    )
    from tests.base import TestsFlextLdifServiceBase, s
    from tests.constants import TestsFlextLdifConstants, c
    from tests.constants_ldap import TestsFlextLdifLdapConstants
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifLdapProtocols, TestsFlextLdifProtocols, p
    from tests.settings import TestsFlextLdifSettings
    from tests.typings import TestsFlextLdifTypes, t
    from tests.utilities import (
        TestsFlextLdifSchemaExpectations,
        TestsFlextLdifUtilities,
        u,
    )


__all__: tuple[str, ...] = (
    "TestsFlextLdifConstants",
    "TestsFlextLdifLdapConstants",
    "TestsFlextLdifLdapProtocols",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifSchemaExpectations",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifSettings",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "api",
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
    "install_local_packages",
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
    "td",
    "tf",
    "tk",
    "tm",
    "u",
    "x",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "TestsFlextLdifConstants": ".constants",
        "TestsFlextLdifLdapConstants": ".constants_ldap",
        "TestsFlextLdifLdapProtocols": ".protocols",
        "TestsFlextLdifModels": ".models",
        "TestsFlextLdifProtocols": ".protocols",
        "TestsFlextLdifSchemaExpectations": ".utilities",
        "TestsFlextLdifServiceBase": ".base",
        "TestsFlextLdifSettings": ".settings",
        "TestsFlextLdifTypes": ".typings",
        "TestsFlextLdifUtilities": ".utilities",
        "api": "flext_tests",
        "build_lazy_import_map": "flext_ldif",
        "c": ".constants",
        "cleanup_submodule_namespace": "flext_ldif",
        "cli": "flext_tests",
        "config": "flext_tests",
        "core": "flext_ldif",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "install_lazy_exports": "flext_ldif",
        "install_local_packages": "flext_tests",
        "lazy": "flext_ldif",
        "lazy_getattr": "flext_ldif",
        "lazy_member": "flext_ldif",
        "ldif": "flext_ldif",
        "m": ".models",
        "main": "flext_tests",
        "merge_lazy_imports": "flext_ldif",
        "normalize_lazy_imports": "flext_ldif",
        "p": ".protocols",
        "r": "flext_tests",
        "resolve_lazy_members": "flext_ldif",
        "s": ".base",
        "settings": "flext_tests",
        "t": ".typings",
        "td": "flext_tests",
        "tf": "flext_tests",
        "tk": "flext_tests",
        "tm": "flext_tests",
        "u": ".utilities",
        "x": "flext_tests",
    }),
    public_exports=__all__,
)
