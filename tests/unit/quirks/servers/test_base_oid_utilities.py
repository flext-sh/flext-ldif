"""Tests for OID utility functions and OID-specific operations.

This module tests utility functions for Oracle Internet Directory (OID)
including OID extraction, validation, pattern matching, and server detection.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import ClassVar

import pytest
from tests import m, s, u


class TestsTestFlextLdifUtilitiesOid(s):
    """Comprehensive test suite for FlextLdifUtilities OID functions.

    Tests OID extraction, validation, pattern matching, and server type detection
    using parametrized test scenarios and real implementations.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS
    # ═══════════════════════════════════════════════════════════════════════════

    class ExtractOidScenario(StrEnum):
        """Test scenarios for extracting OID from schema objects."""

        FROM_ORIGINAL_FORMAT = "from_original_format"
        FALLBACK_TO_MODEL_OID = "fallback_to_model_oid"
        FROM_OBJECTCLASS = "from_objectclass"
        WHITESPACE_IN_FORMAT = "whitespace_in_format"
        NON_STRING_FORMAT = "non_string_format"
        DICT_FORMAT = "dict_format"
        NONE_FORMAT = "none_format"
        EMPTY_STRING_FORMAT = "empty_string_format"
        METADATA_NO_EXTENSIONS = "metadata_no_extensions"
        OBJECTCLASS_NON_STRING = "objectclass_non_string"
        MALFORMED_FORMAT = "malformed_format"
        ORIGINAL_FORMAT_MISSING_OID = "original_format_missing_oid"
        NO_METADATA = "no_metadata"

    class ExtractDefinitionScenario(StrEnum):
        """Test scenarios for extracting OID from definition strings."""

        VALID_DEFINITION = "valid_definition"
        WITH_WHITESPACE = "with_whitespace"
        NO_MATCH = "no_match"
        EMPTY_STRING = "empty_string"
        MALFORMED_PATTERNS = "malformed_patterns"

    class ValidateFormatScenario(StrEnum):
        """Test scenarios for OID format validation."""

        VALID_STANDARD = "valid_standard"
        VALID_STARTING_0 = "valid_starting_0"
        VALID_STARTING_2 = "valid_starting_2"
        VALID_LEADING_ZEROS = "valid_leading_zeros"
        VALID_SINGLE_DIGIT = "valid_single_digit"
        VALID_VERY_LONG = "valid_very_long"
        INVALID_EMPTY = "invalid_empty"
        INVALID_START_3 = "invalid_start_3"
        INVALID_NON_NUMERIC = "invalid_non_numeric"
        INVALID_WITH_SPACES = "invalid_with_spaces"
        INVALID_NO_DOTS = "invalid_no_dots"
        INVALID_SPECIAL_AT = "invalid_special_at"
        INVALID_SPECIAL_HASH = "invalid_special_hash"

    class MatchPatternScenario(StrEnum):
        """Test scenarios for OID pattern matching."""

        ORACLE_PATTERN_MATCH = "oracle_pattern_match"
        RFC_PATTERN_NO_MATCH = "rfc_pattern_no_match"
        OPENLDAP_PATTERN_MATCH = "openldap_pattern_match"
        ORACLE_OR_NOVELL_ORACLE = "oracle_or_novell_oracle"
        ORACLE_OR_NOVELL_NOVELL = "oracle_or_novell_novell"
        ORACLE_OR_NOVELL_RFC = "oracle_or_novell_rfc"

    class ServerTypeDetectionScenario(StrEnum):
        """Test scenarios for server type detection from OID."""

        ORACLE_OID = "oracle_oid"
        MICROSOFT_AD_OID = "microsoft_ad_oid"
        OPENLDAP_OID = "openldap_oid"
        REDHAT_389DS_OID = "redhat_389ds_oid"
        NOVELL_OID = "novell_oid"
        IBM_TIVOLI_OID = "ibm_tivoli_oid"
        RFC_STANDARD_OID = "rfc_standard_oid"
        ORACLE_DEFINITION = "oracle_definition"
        MICROSOFT_AD_DEFINITION = "microsoft_ad_definition"
        OPENLDAP_DEFINITION = "openldap_definition"

    class IsServerTypeScenario(StrEnum):
        """Test scenarios for is_*_oid type checking functions."""

        ORACLE_DEFINITION = "oracle_definition"
        ORACLE_OID = "oracle_oid"
        ORACLE_NON_OID = "oracle_non_oid"
        ORACLE_EMPTY = "oracle_empty"
        MICROSOFT_AD_DEFINITION = "microsoft_ad_definition"
        MICROSOFT_AD_OID = "microsoft_ad_oid"
        MICROSOFT_AD_NON_OID = "microsoft_ad_non_oid"
        MICROSOFT_AD_EMPTY = "microsoft_ad_empty"
        OPENLDAP_DEFINITION = "openldap_definition"
        OPENLDAP_OID = "openldap_oid"
        OPENLDAP_NON_OID = "openldap_non_oid"
        OPENLDAP_EMPTY = "openldap_empty"

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS
    # ═══════════════════════════════════════════════════════════════════════════

    EXTRACT_OID_TEST_DATA: ClassVar[
        dict[
            str,
            tuple[
                m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
                str,
            ],
        ]
    ] = {
        ExtractOidScenario.FROM_ORIGINAL_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.16.840.1.113894.1.1.1",
                name="orclGUID",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )",
                    ),
                ),
            ),
            "2.16.840.1.113894.1.1.1",
        ),
        ExtractOidScenario.FALLBACK_TO_MODEL_OID: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.FROM_OBJECTCLASS: (
            m.Ldif.SchemaObjectClass(
                oid="2.16.840.1.113894.1.1.5",
                name="orcldASObject",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="( 2.16.840.1.113894.1.1.5 NAME 'orcldASObject' ... )",
                    ),
                ),
            ),
            "2.16.840.1.113894.1.1.5",
        ),
        ExtractOidScenario.WHITESPACE_IN_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.6.0",
                name="top",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="(   2.5.6.0   NAME 'top' ... )",
                    ),
                ),
            ),
            "2.5.6.0",
        ),
        ExtractOidScenario.NON_STRING_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format=12345,
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.DICT_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format={"key": "value"},
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.NONE_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format=None,
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.EMPTY_STRING_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="",
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.METADATA_NO_EXTENSIONS: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.OBJECTCLASS_NON_STRING: (
            m.Ldif.SchemaObjectClass(
                oid="2.5.6.0",
                name="top",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format=[],
                    ),
                ),
            ),
            "2.5.6.0",
        ),
        ExtractOidScenario.MALFORMED_FORMAT: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="NAME 'cn' DESC 'test'",
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.ORIGINAL_FORMAT_MISSING_OID: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
                metadata=m.Ldif.QuirkMetadata(
                    quirk_type="oid",
                    extensions=m.Ldif.DynamicMetadata(
                        original_format="( NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
                    ),
                ),
            ),
            "2.5.4.3",
        ),
        ExtractOidScenario.NO_METADATA: (
            m.Ldif.SchemaAttribute(
                oid="2.5.4.3",
                name="cn",
            ),
            "2.5.4.3",
        ),
    }

    EXTRACT_DEFINITION_TEST_DATA: ClassVar[dict[str, tuple[str, str | None]]] = {
        ExtractDefinitionScenario.VALID_DEFINITION: (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' DESC 'Oracle GUID' )",
            "2.16.840.1.113894.1.1.1",
        ),
        ExtractDefinitionScenario.WITH_WHITESPACE: (
            "(   2.5.4.3   NAME 'cn' ... )",
            "2.5.4.3",
        ),
        ExtractDefinitionScenario.NO_MATCH: (
            "NAME 'test' DESC 'test attribute'",
            None,
        ),
        ExtractDefinitionScenario.EMPTY_STRING: (
            "",
            None,
        ),
        ExtractDefinitionScenario.MALFORMED_PATTERNS: (
            "NAME 'cn' DESC 'test'",  # No OID pattern
            None,
        ),
    }

    VALIDATE_FORMAT_TEST_DATA: ClassVar[dict[str, tuple[str, bool]]] = {
        ValidateFormatScenario.VALID_STANDARD: ("1.3.6.1.4.1.1466.115.121.1.7", True),
        ValidateFormatScenario.VALID_STARTING_0: ("0.9.2342.19200300.100.1.1", True),
        ValidateFormatScenario.VALID_STARTING_2: ("2.16.840.1.113894.1.1.1", True),
        ValidateFormatScenario.VALID_LEADING_ZEROS: ("1.03.6.1.4.1", True),
        ValidateFormatScenario.VALID_SINGLE_DIGIT: ("1", True),
        ValidateFormatScenario.VALID_VERY_LONG: (
            "1." + ".".join(str(i) for i in range(100)),
            True,
        ),
        ValidateFormatScenario.INVALID_EMPTY: ("", False),
        ValidateFormatScenario.INVALID_START_3: ("3.6.1.4.1", False),
        ValidateFormatScenario.INVALID_NON_NUMERIC: ("1.3.6.abc.1.4.1", False),
        ValidateFormatScenario.INVALID_WITH_SPACES: ("1.3.6.1.4. 1", False),
        ValidateFormatScenario.INVALID_NO_DOTS: ("123456", False),
        ValidateFormatScenario.INVALID_SPECIAL_AT: ("1.3.6.1.4.1@test", False),
        ValidateFormatScenario.INVALID_SPECIAL_HASH: ("1.3.6.1.4.1#test", False),
    }

    MATCH_PATTERN_TEST_DATA: ClassVar[dict[str, tuple[str, str, bool]]] = {
        MatchPatternScenario.ORACLE_PATTERN_MATCH: (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )",
            r"2\.16\.840\.1\.113894\.",
            True,
        ),
        MatchPatternScenario.RFC_PATTERN_NO_MATCH: (
            "( 2.5.4.3 NAME 'cn' ... )",
            r"2\.16\.840\.1\.113894\.",
            False,
        ),
        MatchPatternScenario.OPENLDAP_PATTERN_MATCH: (
            "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )",
            r"1\.3\.6\.1\.4\.1\.4203\.",
            True,
        ),
        MatchPatternScenario.ORACLE_OR_NOVELL_ORACLE: (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclAttr' ... )",
            r"2\.16\.840\.1\.11(3894|3719)\.",
            True,
        ),
        MatchPatternScenario.ORACLE_OR_NOVELL_NOVELL: (
            "( 2.16.840.1.113719.1.1.1 NAME 'ndsAttr' ... )",
            r"2\.16\.840\.1\.11(3894|3719)\.",
            True,
        ),
        MatchPatternScenario.ORACLE_OR_NOVELL_RFC: (
            "( 2.5.4.3 NAME 'cn' ... )",
            r"2\.16\.840\.1\.11(3894|3719)\.",
            False,
        ),
    }

    SERVER_TYPE_DETECTION_TEST_DATA: ClassVar[dict[str, tuple[str, str | None]]] = {
        ServerTypeDetectionScenario.ORACLE_OID: ("2.16.840.1.113894.1.1.1", "oid"),
        ServerTypeDetectionScenario.MICROSOFT_AD_OID: ("1.2.840.113556.1.2.1", "ad"),
        ServerTypeDetectionScenario.OPENLDAP_OID: (
            "1.3.6.1.4.1.4203.1.1.1",
            "openldap",
        ),
        ServerTypeDetectionScenario.REDHAT_389DS_OID: (
            "2.16.840.1.113730.1.1.1",
            "ds389",
        ),
        ServerTypeDetectionScenario.NOVELL_OID: ("2.16.840.1.113719.1.1.1", "novell"),
        ServerTypeDetectionScenario.IBM_TIVOLI_OID: ("1.3.18.0.2.1.1.1", "tivoli"),
        ServerTypeDetectionScenario.RFC_STANDARD_OID: ("2.5.4.3", None),
        ServerTypeDetectionScenario.ORACLE_DEFINITION: (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )",
            "oid",
        ),
        ServerTypeDetectionScenario.MICROSOFT_AD_DEFINITION: (
            "( 1.2.840.113556.1.2.1 NAME 'objectClass' ... )",
            "ad",
        ),
        ServerTypeDetectionScenario.OPENLDAP_DEFINITION: (
            "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )",
            "openldap",
        ),
    }

    IS_SERVER_TYPE_TEST_DATA: ClassVar[dict[str, tuple[str, str, bool]]] = {
        IsServerTypeScenario.ORACLE_DEFINITION: (
            "( 2.16.840.1.113894.1.1.1 NAME 'orclGUID' ... )",
            "oracle",
            True,
        ),
        IsServerTypeScenario.ORACLE_OID: ("2.16.840.1.113894.1.1.1", "oracle", True),
        IsServerTypeScenario.ORACLE_NON_OID: ("2.5.4.3", "oracle", False),
        IsServerTypeScenario.ORACLE_EMPTY: ("", "oracle", False),
        IsServerTypeScenario.MICROSOFT_AD_DEFINITION: (
            "( 1.2.840.113556.1.2.1 NAME 'objectClass' ... )",
            "microsoft_ad",
            True,
        ),
        IsServerTypeScenario.MICROSOFT_AD_OID: (
            "1.2.840.113556.1.2.1",
            "microsoft_ad",
            True,
        ),
        IsServerTypeScenario.MICROSOFT_AD_NON_OID: ("2.5.4.3", "microsoft_ad", False),
        IsServerTypeScenario.MICROSOFT_AD_EMPTY: ("", "microsoft_ad", False),
        IsServerTypeScenario.OPENLDAP_DEFINITION: (
            "( 1.3.6.1.4.1.4203.1.1.1 NAME 'olcBackend' ... )",
            "openldap",
            True,
        ),
        IsServerTypeScenario.OPENLDAP_OID: ("1.3.6.1.4.1.4203.1.1.1", "openldap", True),
        IsServerTypeScenario.OPENLDAP_NON_OID: ("2.5.4.3", "openldap", False),
        IsServerTypeScenario.OPENLDAP_EMPTY: ("", "openldap", False),
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # PARAMETRIZED TESTS
    # ═══════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "schema_obj", "expected_oid"),
        [(name, data[0], data[1]) for name, data in EXTRACT_OID_TEST_DATA.items()],
    )
    def test_extract_oid_from_schema_object(
        self,
        scenario: str,
        schema_obj: m.Ldif.SchemaAttribute | m.Ldif.SchemaObjectClass,
        expected_oid: str,
    ) -> None:
        """Test extracting OID from schema objects with parametrized scenarios."""
        result = u.OID.extract_from_schema_object(schema_obj)
        assert result == expected_oid, (
            f"Failed for scenario {scenario}: expected {expected_oid}, got {result}"
        )

    @pytest.mark.parametrize(
        ("scenario", "definition", "expected_oid"),
        [
            (name, data[0], data[1])
            for name, data in EXTRACT_DEFINITION_TEST_DATA.items()
        ],
    )
    def test_extract_oid_from_definition(
        self,
        scenario: str,
        definition: str,
        expected_oid: str | None,
    ) -> None:
        """Test extracting OID from definition strings with parametrized scenarios."""
        result = u.OID.extract_from_definition(definition)
        assert result == expected_oid, (
            f"Failed for scenario {scenario}: expected {expected_oid}, got {result}"
        )

    @pytest.mark.parametrize(
        ("scenario", "oid", "is_valid"),
        [(name, data[0], data[1]) for name, data in VALIDATE_FORMAT_TEST_DATA.items()],
    )
    def test_validate_oid_format(
        self,
        scenario: str,
        oid: str,
        is_valid: bool,
    ) -> None:
        """Test OID format validation with parametrized scenarios."""
        result = u.OID.validate_format(oid)
        assert result.is_success, f"Validation failed for {scenario}"
        assert result.value is is_valid, (
            f"Format validation failed for {scenario}: expected {is_valid}, got {result.value}"
        )

    @pytest.mark.parametrize(
        ("scenario", "definition", "pattern_str", "should_match"),
        [
            (name, data[0], data[1], data[2])
            for name, data in MATCH_PATTERN_TEST_DATA.items()
        ],
    )
    def test_matches_pattern(
        self,
        scenario: str,
        definition: str,
        pattern_str: str,
        should_match: bool,
    ) -> None:
        """Test OID pattern matching with parametrized scenarios."""
        pattern = re.compile(pattern_str)
        result = u.OID.matches_pattern(definition, pattern)
        assert result is should_match, (
            f"Pattern match failed for {scenario}: expected {should_match}, got {result}"
        )

    @pytest.mark.parametrize(
        ("scenario", "input_value", "expected_server_type"),
        [
            (name, data[0], data[1])
            for name, data in SERVER_TYPE_DETECTION_TEST_DATA.items()
        ],
    )
    def test_get_server_type_from_oid(
        self,
        scenario: str,
        input_value: str,
        expected_server_type: str | None,
    ) -> None:
        """Test server type detection with parametrized scenarios."""
        result = u.OID.get_server_type_from_oid(input_value)
        assert result == expected_server_type, (
            f"Server type detection failed for {scenario}: expected {expected_server_type}, got {result}"
        )

    @pytest.mark.parametrize(
        ("scenario", "input_value", "server_type", "expected_result"),
        [
            (name, data[0], data[1], data[2])
            for name, data in IS_SERVER_TYPE_TEST_DATA.items()
        ],
    )
    def test_is_server_type_oid(
        self,
        scenario: str,
        input_value: str,
        server_type: str,
        expected_result: bool,
    ) -> None:
        """Test server type OID checking with parametrized scenarios."""
        if server_type == "oracle":
            result = u.OID.is_oracle_oid(input_value)
        elif server_type == "microsoft_ad":
            result = u.OID.is_microsoft_ad_oid(input_value)
        elif server_type == "openldap":
            result = u.OID.is_openldap_oid(input_value)
        else:
            msg = f"Unknown server type: {server_type}"
            raise ValueError(msg)

        assert result is expected_result, (
            f"Server type check failed for {scenario}: expected {expected_result}, got {result}"
        )


__all__ = [
    "TestFlextLdifUtilitiesOid",
]
