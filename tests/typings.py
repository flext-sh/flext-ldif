"""Test type definitions extending src typings for centralized test types.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import Literal

from flext_tests import FlextTestsTypes

from flext_ldif import FlextLdifTypes


class TestsFlextLdifTypes(FlextTestsTypes, FlextLdifTypes):
    """Test types extending TestsFlextTypes and t."""

    class Tests(FlextTestsTypes.Tests):
        """flext-ldif-specific test type definitions namespace."""

        type GenericFieldsDict = FlextLdifTypes.Mapping[str, str]
        type DnRefData = FlextLdifTypes.Mapping[
            str,
            FlextLdifTypes.Mapping[str, str] | FlextLdifTypes.Sequence[str] | str,
        ]
        type FixtureServer = str
        type FixtureKind = str
        type AttributeCaseRow = tuple[str, str, bool, str | None, str | None]
        type ObjectClassCaseRow = tuple[
            str, str, bool, str | None, str | None, str | None
        ]
        type EntryCaseRow = tuple[
            str, str, FlextLdifTypes.Mapping[str, FlextLdifTypes.Sequence[str]], bool
        ]
        type ParseMethod = Literal[
            "parse_server",
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
