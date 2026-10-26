# AUTO-GENERATED FILE — Regenerate with: make gen
"""Test utilities facade with shared helper re-exports.

The focused helper mixins live in ``tests.utilities_ldap``,
``tests.utilities_entries``, and ``tests.utilities_schema``; this module is
the stable import surface and re-exports the composed namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_tests import u as flext_tests_u

from flext_ldif import u as flext_ldif_u
from tests import c, m, p, t
from tests._utilities import (
    TestsFlextLdifEntryBuildersMixin,
    TestsFlextLdifLdapClientMixin,
    TestsFlextLdifSchemaExpectations,
    TestsSchemaAclAssertionsMixin,
)


class TestsFlextLdifUtilities(flext_tests_u, flext_ldif_u):
    """Project test utility namespace extension."""

    class Tests(
        TestsFlextLdifEntryBuildersMixin,
        TestsFlextLdifLdapClientMixin,
        TestsSchemaAclAssertionsMixin,
        flext_tests_u.Tests,
    ):
        """Flat test utility namespace for flext-ldif."""

        logger: ClassVar[p.Logger] = flext_ldif_u.fetch_logger(__name__)

        @classmethod
        def server_attribute_test_cases(
            cls,
            server: str,
        ) -> t.VariadicTuple[m.Tests.AttributeTestCase]:
            """Materialize the selected dialect's canonical attribute cases.

            Args:
                server: The server dialect to construct attribute test cases for.

            Returns:
                A tuple of independent attribute test cases.

            """
            cases = {
                c.Tests.APACHE: c.Tests.APACHE_ATTRIBUTE_DETECTION_ROWS,
                c.Tests.DS389: c.Tests.DS389_ATTRIBUTE_DETECTION_ROWS,
                c.Tests.NOVELL: c.Tests.NOVELL_ATTRIBUTE_DETECTION_ROWS,
            }
            return cls.attribute_test_cases(
                tuple(
                    row
                    for dialect, dialect_cases in cases.items()
                    if dialect == server
                    for row in dialect_cases
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
                rows: The sequence of objectClass case rows used to construct cases.

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
