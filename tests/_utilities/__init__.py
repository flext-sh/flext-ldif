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
    from tests._utilities.utilities_entries import TestsFlextLdifEntryBuildersMixin
    from tests._utilities.utilities_ldap import TestsFlextLdifLdapClientMixin
    from tests._utilities.utilities_schema import (
        PARSE_DISPATCH,
        TestsFlextLdifSchemaExpectations,
        TestsSchemaAclAssertionsMixin,
        assert_field_eq,
        assert_must_contain,
    )


__all__: tuple[str, ...] = (
    "PARSE_DISPATCH",
    "TestsFlextLdifEntryBuildersMixin",
    "TestsFlextLdifLdapClientMixin",
    "TestsFlextLdifSchemaExpectations",
    "TestsSchemaAclAssertionsMixin",
    "assert_field_eq",
    "assert_must_contain",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "PARSE_DISPATCH": ".utilities_schema",
        "TestsFlextLdifConstants": ".constants",
        "TestsFlextLdifEntryBuildersMixin": ".utilities_entries",
        "TestsFlextLdifLdapClientMixin": ".utilities_ldap",
        "TestsFlextLdifUtilities": ".utilities",
        "TestsSchemaAclAssertionsMixin": ".utilities_schema",
        "assert_field_eq": ".utilities_schema",
        "assert_must_contain": ".utilities_schema",
    }),
    public_exports=__all__,
)
