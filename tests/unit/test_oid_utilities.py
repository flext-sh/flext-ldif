"""Unit tests for OID-specific LDIF utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from tests import tm

from tests import c, t, u


class TestsFlextLdifOidUtilities:
    """Behavioral contract for the OID schema-definition utilities."""

    @staticmethod
    @pytest.mark.parametrize(
        ("definition", "expected_oid"),
        [
            ("( 1.2.840.113556.1.4.221 NAME 'x' )", "1.2.840.113556.1.4.221"),
            ("(  2.5.4.3 NAME 'cn' )", "2.5.4.3"),
            ("(1.2.3 NAME 'nospace')", "1.2.3"),
            (
                "attributetypes: ( 0.9.2342.19200300.100.1.1 NAME 'uid' )",
                "0.9.2342.19200300.100.1.1",
            ),
        ],
    )
    def test_extract_from_definition_returns_leading_oid(
        definition: str,
        expected_oid: str,
    ) -> None:
        """Test extract from definition returns leading oid."""
        result = u.Ldif.extract_from_definition(definition)

        value = u.Tests.assert_success(result)
        tm.that(value, eq=expected_oid)

    @staticmethod
    @pytest.mark.parametrize(
        "definition",
        [
            "( NAME 'cn' DESC 'no oid' )",
            "NAME 'cn'",
            "",
            "( NAME 'has 1.2.3 but no leading paren-oid' )",
        ],
    )
    def test_extract_from_definition_fails_without_leading_oid(
        definition: str,
    ) -> None:
        """Test extract from definition fails without leading oid."""
        result = u.Ldif.extract_from_definition(definition)

        u.Tests.assert_failure(result)
        tm.that(result.error, contains=repr(definition))

    @staticmethod
    def test_extract_from_definition_result_is_chainable_on_success() -> None:
        """Test extract from definition result is chainable on success."""
        result = u.Ldif.extract_from_definition("( 1.2.3 NAME 'x' )")

        mapped = result.map(lambda oid: oid.split("."))
        value = u.Tests.assert_success(mapped)

        tm.that(value, eq=["1", "2", "3"])

    @staticmethod
    def test_extract_from_definition_is_idempotent() -> None:
        """Test extract from definition is idempotent."""
        definition = "( 1.2.840.113556.1.4.221 NAME 'x' )"

        first = u.Ldif.extract_from_definition(definition)
        second = u.Ldif.extract_from_definition(definition)

        tm.that(u.Tests.assert_success(first), eq=u.Tests.assert_success(second))

    @staticmethod
    @pytest.mark.parametrize(
        ("definition", "pattern", "expected"),
        [
            ("( 1.2.3 NAME 'x' )", "^1\\.2\\.3$", True),
            ("( 9.9.9 NAME 'x' )", "^1\\.2\\.3$", False),
            ("( 1.2.3.4 NAME 'x' )", "^1\\.2\\.3$", False),
            ("( 2.5.4.3 NAME 'cn' )", "^2\\.5\\.", True),
        ],
    )
    def test_matches_pattern_reflects_extracted_oid(
        definition: str,
        pattern: str,
        *,
        expected: bool,
    ) -> None:
        """Test matches pattern reflects extracted oid."""
        compiled: t.Ldif.RegexPattern = c.Ldif.compile_pattern(pattern)

        result = u.Ldif.matches_pattern(definition, compiled)

        tm.that(result, eq=expected)

    @staticmethod
    @pytest.mark.parametrize(
        "definition",
        ["( NAME 'cn' DESC 'no oid' )", "( NAME 'no oid' )"],
    )
    def test_matches_pattern_rejects_definition_without_oid(
        definition: str,
    ) -> None:
        """Malformed definitions propagate extraction failure instead of no-match."""
        with pytest.raises(ValueError, match="missing an OID"):
            u.Ldif.matches_pattern(definition, c.Tests.EXACT_OID_1_2_3_RE)

    @staticmethod
    def test_matches_pattern_true_against_exact_oid_constant() -> None:
        """Test matches pattern true against exact oid constant."""
        result = u.Ldif.matches_pattern(
            "( 1.2.3 NAME 'cn' )",
            c.Tests.EXACT_OID_1_2_3_RE,
        )

        tm.that(result, eq=True)
