"""Test type definitions extending src typings for centralized test types."""

from __future__ import annotations

from typing import Literal

from flext_tests import FlextTestsTypes

from flext_ldif import FlextLdifTypes


class TestsFlextLdifTypes(FlextTestsTypes, FlextLdifTypes):
    """Test types extending TestsFlextTypes and t."""

    class Tests(FlextTestsTypes.Tests):
        """flext-ldif-specific test type definitions namespace."""

        type GenericFieldsDict = FlextLdifTypes.StrMapping
        type DnRefData = FlextLdifTypes.MappingKV[
            str, FlextLdifTypes.StrMapping | FlextLdifTypes.StrSequence | str
        ]
        type FixtureServer = str
        type FixtureKind = str
        type ParseMethod = Literal[
            "parse_server", "parse_attribute", "parse_objectclass", "parse_input"
        ]
        type WriteMethod = Literal[
            "write", "_write_attribute", "_write_objectclass", "_write_acl"
        ]


t = TestsFlextLdifTypes

__all__: list[str] = ["TestsFlextLdifTypes", "t"]
