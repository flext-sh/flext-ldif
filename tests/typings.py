"""Test type definitions extending src typings for centralized test types."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from flext_ldap import t
from flext_tests import FlextTestsTypes


class TestsFlextLdifTypes(FlextTestsTypes, t):
    """Test types extending TestsFlextTypes and t."""

    class Ldif(t.Ldif):
        """LDIF test type namespace."""

        class Tests(FlextTestsTypes.Tests):
            """flext-ldif-specific test type definitions namespace."""

            type GenericFieldsDict = t.StrMapping
            type DnRefData = Mapping[
                str,
                t.StrMapping | t.StrSequence | str,
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


t = TestsFlextLdifTypes

__all__: list[str] = ["TestsFlextLdifTypes", "t"]
