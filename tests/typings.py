"""Test type definitions extending src typings for centralized test types."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from flext_ldap import t
from flext_tests import FlextTestsTypes


class TestsFlextLdifTypes(FlextTestsTypes, t):
    """Test types extending TestsFlextTypes and FlextLdapTypes."""

    class Ldif(t.Ldif):
        """LDIF test type namespace."""

        class Tests(FlextTestsTypes.Tests):
            """flext-ldif-specific test type definitions namespace."""

            type GenericFieldsDict = TestsFlextLdifTypes.StrMapping
            type DnRefData = Mapping[
                str,
                TestsFlextLdifTypes.StrMapping
                | TestsFlextLdifTypes.StrSequence
                | str,
            ]
            type FixtureServer = str
            type FixtureKind = str
            type ParseMethod = Literal[
                "parse_quirk",
                "parse_attribute",
                "parse_objectclass",
                "parse_input",
            ]
            type WriteMethod = Literal[
                "write",
                "_write_attribute",
                "_write_objectclass",
                "_write_acl",
            ]


type GenericFieldsDict = TestsFlextLdifTypes.Ldif.Tests.GenericFieldsDict

t = TestsFlextLdifTypes

__all__ = ["GenericFieldsDict", "TestsFlextLdifTypes", "t"]
