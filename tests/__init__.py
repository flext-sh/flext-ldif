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
    from flext_cli import cli
    from flext_tests import (
        api,
        config,
        d,
        e,
        h,
        install_local_packages,
        r,
        settings,
        td,
        tf,
        tk,
        tm,
        x,
    )

    from flext_ldif import ldif, main
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
    "c",
    "cli",
    "config",
    "d",
    "e",
    "h",
    "install_local_packages",
    "ldif",
    "m",
    "main",
    "p",
    "r",
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
        "c": ".constants",
        "cli": "flext_cli",
        "config": "flext_tests",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "install_local_packages": "flext_tests",
        "ldif": "flext_ldif",
        "m": ".models",
        "main": "flext_ldif",
        "p": ".protocols",
        "r": "flext_tests",
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
