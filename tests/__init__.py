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
    from flext_tests import api, d, e, h, r, td, tf, tk, tm, x

    from tests._constants_ldap import TestsFlextLdifLdapConstants
    from tests._protocols_ldap import TestsFlextLdifLdapProtocols
    from tests._utilities_entries import TestsFlextLdifEntryBuildersMixin
    from tests._utilities_ldap import TestsFlextLdifLdapClientMixin
    from tests._utilities_schema import (
        PARSE_DISPATCH,
        TestsSchemaAclAssertionsMixin,
        assert_field_eq,
        assert_must_contain,
    )
    from tests.base import TestsFlextLdifServiceBase, s
    from tests.constants import TestsFlextLdifConstants, c
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifProtocols, p
    from tests.settings import TestsFlextLdifSettings
    from tests.typings import TestsFlextLdifTypes, t
    from tests.utilities import (
        TestsFlextLdifSchemaExpectations,
        TestsFlextLdifUtilities,
        u,
    )


__all__: tuple[str, ...] = (
    "PARSE_DISPATCH",
    "TestsFlextLdifConstants",
    "TestsFlextLdifEntryBuildersMixin",
    "TestsFlextLdifLdapClientMixin",
    "TestsFlextLdifLdapConstants",
    "TestsFlextLdifLdapProtocols",
    "TestsFlextLdifModels",
    "TestsFlextLdifProtocols",
    "TestsFlextLdifSchemaExpectations",
    "TestsFlextLdifServiceBase",
    "TestsFlextLdifSettings",
    "TestsFlextLdifTypes",
    "TestsFlextLdifUtilities",
    "TestsSchemaAclAssertionsMixin",
    "api",
    "assert_field_eq",
    "assert_must_contain",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
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
        "PARSE_DISPATCH": "._utilities_schema",
        "TestsFlextLdifConstants": ".constants",
        "TestsFlextLdifLdapConstants": "._constants_ldap",
        "TestsFlextLdifLdapProtocols": "._protocols_ldap",
        "TestsFlextLdifModels": ".models",
        "TestsFlextLdifProtocols": ".protocols",
        "TestsFlextLdifSchemaExpectations": ".utilities",
        "TestsFlextLdifServiceBase": ".base",
        "TestsFlextLdifSettings": ".settings",
        "TestsFlextLdifTypes": ".typings",
        "TestsFlextLdifUtilities": ".utilities",
        "TestsFlextLdifLdapClientMixin": "._utilities_ldap",
        "TestsFlextLdifEntryBuildersMixin": "._utilities_entries",
        "TestsSchemaAclAssertionsMixin": "._utilities_schema",
        "api": "flext_tests",
        "assert_field_eq": "._utilities_schema",
        "assert_must_contain": "._utilities_schema",
        "c": ".constants",
        "d": "flext_tests",
        "e": "flext_tests",
        "h": "flext_tests",
        "m": ".models",
        "p": ".protocols",
        "r": "flext_tests",
        "s": ".base",
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
