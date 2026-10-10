"""Test utilities facade with shared helper re-exports.

The focused helper mixins live in ``tests._utilities_ldap``,
``tests._utilities_entries``, and ``tests._utilities_schema``; this module is
the stable import surface and re-exports the composed namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_tests import FlextTestsUtilities

from flext_ldif import FlextLdifUtilities
from tests import p
from tests._utilities_entries import TestsLdifEntryBuildersMixin
from tests._utilities_ldap import TestsLdapClientMixin
from tests._utilities_schema import (
    TestsFlextLdifSchemaExpectations,
    TestsSchemaAclAssertionsMixin,
)


class TestsFlextLdifUtilities(FlextTestsUtilities, FlextLdifUtilities):
    """Project test utility namespace extension."""

    class Tests(
        TestsLdapClientMixin,
        TestsLdifEntryBuildersMixin,
        TestsSchemaAclAssertionsMixin,
        FlextTestsUtilities.Tests,
    ):
        """Flat test utility namespace for flext-ldif."""

        logger: ClassVar[p.Logger] = FlextLdifUtilities.fetch_logger(__name__)


u = TestsFlextLdifUtilities

__all__: list[str] = [
    "TestsFlextLdifSchemaExpectations",
    "TestsFlextLdifUtilities",
    "u",
]
