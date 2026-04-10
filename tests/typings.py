"""Test type definitions extending src typings for centralized test types."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Literal

from flext_ldap import FlextLdapTypes, t
from flext_tests import FlextTestsTypes


class TestsFlextLdifTypes(FlextTestsTypes, FlextLdapTypes):
    """Test types extending TestsFlextTypes and FlextLdapTypes."""

    class Ldif(FlextLdapTypes.Ldif):
        """LDIF test type namespace."""

        class Tests(FlextTestsTypes.Tests):
            """flext-ldif-specific test type definitions namespace."""

            type GenericFieldsDict = FlextLdapTypes.StrMapping
            type DnRefData = Mapping[
                str,
                FlextLdapTypes.StrMapping | FlextLdapTypes.StrSequence | str,
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

__all__ = ["TestsFlextLdifTypes", "t"]
