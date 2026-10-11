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
from tests import c, m, p, t
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

        @classmethod
        def server_attribute_test_cases(
            cls,
            server: str,
        ) -> t.VariadicTuple[m.Tests.AttributeTestCase]:
            """Construct the selected dialect's attribute cases from constant rows.

            Args:
                server: The server dialect to construct attribute test cases for.

            Returns:
                A tuple of constructed attribute test cases.
            """
            return cls.attribute_test_cases(
                tuple(
                    (scenario, definition, can_handle, oid, name)
                    for dialect, scenario, definition, can_handle, oid, name in c.ATTRIBUTE_CASE_ROWS
                    if dialect == server
                )
            )

        @staticmethod
        def attribute_test_cases(
            rows: t.SequenceOf[t.Tests.AttributeCaseRow],
        ) -> t.VariadicTuple[m.Tests.AttributeTestCase]:
            """Construct attribute cases from immutable declaration data.

            Args:
                rows: The sequence of attribute case rows to construct test cases from.

            Returns:
                A tuple of constructed attribute test cases.
            """
            return tuple(
                m.Tests.AttributeTestCase(
                    scenario=scenario,
                    attr_definition=definition,
                    expected_can_handle=can_handle,
                    expected_oid=oid,
                    expected_name=name,
                )
                for scenario, definition, can_handle, oid, name in rows
            )

        @staticmethod
        def objectclass_test_cases(
            rows: t.SequenceOf[t.Tests.ObjectClassCaseRow],
        ) -> t.VariadicTuple[m.Tests.ObjectClassTestCase]:
            """Construct objectClass cases from immutable declaration data.

            Args:
                rows: The sequence of objectClass case rows to construct test cases from.

            Returns:
                A tuple of constructed objectClass test cases.
            """
            return tuple(
                m.Tests.ObjectClassTestCase(
                    scenario=scenario,
                    oc_definition=definition,
                    expected_can_handle=can_handle,
                    expected_oid=oid,
                    expected_name=name,
                    expected_kind=kind,
                )
                for scenario, definition, can_handle, oid, name, kind in rows
            )

        @staticmethod
        def entry_test_cases(
            rows: t.SequenceOf[t.Tests.EntryCaseRow],
        ) -> t.VariadicTuple[m.Tests.EntryTestCase]:
            """Construct entry cases with fresh mutable protocol attributes.

            Args:
                rows: The sequence of entry case rows to construct test cases from.

            Returns:
                A tuple of constructed entry test cases.
            """
            return tuple(
                m.Tests.EntryTestCase(
                    scenario=scenario,
                    entry_dn=dn,
                    attributes={
                        key: list(values) for key, values in attributes.items()
                    },
                    expected_can_handle=can_handle,
                )
                for scenario, dn, attributes, can_handle in rows
            )


u = TestsFlextLdifUtilities

__all__: list[str] = [
    "TestsFlextLdifSchemaExpectations",
    "TestsFlextLdifUtilities",
    "u",
]
