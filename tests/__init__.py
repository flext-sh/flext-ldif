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

    from _utilities.utilities_entries import TestsFlextLdifEntryBuildersMixin
    from _utilities.utilities_ldap import TestsFlextLdifLdapClientMixin
    from _utilities.utilities_schema import (
        PARSE_DISPATCH,
        TestsFlextLdifSchemaExpectations,
        TestsSchemaAclAssertionsMixin,
        assert_field_eq,
        assert_must_contain,
    )
    from tests.base import TestsFlextLdifServiceBase, s
    from tests.constants import TestsFlextLdifConstants, c
    from tests.constants_ldap import TestsFlextLdifLdapConstants
    from tests.models import TestsFlextLdifModels, m
    from tests.protocols import TestsFlextLdifLdapProtocols, TestsFlextLdifProtocols, p
    from tests.settings import TestsFlextLdifSettings
    from tests.typings import TestsFlextLdifTypes, t
    from tests.utilities import TestsFlextLdifUtilities, u


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
        "PARSE_DISPATCH": ".utilities_schema",
        "TestsFlextLdifConstants": ".constants",
        "TestsFlextLdifEntryBuildersMixin": ".utilities_entries",
        "TestsFlextLdifLdapClientMixin": ".utilities_ldap",
        "TestsFlextLdifLdapConstants": ".constants_ldap",
        "TestsFlextLdifLdapProtocols": ".protocols",
        "TestsFlextLdifModels": ".models",
        "TestsFlextLdifProtocols": ".protocols",
        "TestsFlextLdifSchemaExpectations": ".utilities_schema",
        "TestsFlextLdifServiceBase": ".base",
        "TestsFlextLdifSettings": ".settings",
        "TestsFlextLdifTypes": ".typings",
        "TestsFlextLdifUtilities": ".utilities",
        "TestsSchemaAclAssertionsMixin": ".utilities_schema",
        "api": "flext_tests",
        "assert_field_eq": ".utilities_schema",
        "assert_must_contain": ".utilities_schema",
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
