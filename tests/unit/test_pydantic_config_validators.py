"""Tests for FlextLdifSettings Pydantic validators.

This module tests field validators (encoding, server_type, line_separator, version_string)
and cross-field model validators for FlextLdifSettings using parametrized test scenarios
to ensure proper validation of all configuration options.
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar, Literal

import pytest
from flext_ldif import FlextLdifSettings
from flext_ldif.utilities import FlextLdifUtilities
from pydantic import ValidationError

from tests import s


@pytest.fixture(autouse=True)
def reset_settings_singleton() -> None:
    """Reset FlextLdifSettings singleton before each test.

    This ensures each test gets a fresh settings instance and
    validation runs properly (not bypassed by singleton reuse).
    """
    FlextLdifSettings._reset_instance()


class TestsTestFlextLdifSettingsValidators(s):
    """Comprehensive test suite for FlextLdifSettings Pydantic validators.

    Tests field validators (encoding, server_type, line_separator, version_string)
    and cross-field model validators using parametrized test scenarios.
    """

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST SCENARIO ENUMS
    # ═══════════════════════════════════════════════════════════════════════════

    class EncodingScenario(StrEnum):
        """Test scenarios for ldif_encoding field_validator."""

        UTF8_VALID = "utf8_valid"
        LATIN1_VALID = "latin1_valid"
        ASCII_VALID = "ascii_valid"
        INVALID_CODEC = "invalid_codec"
        NONEXISTENT_CODEC = "nonexistent_codec"
        FAKE_CODEC = "fake_codec"

    class ServerTypeScenario(StrEnum):
        """Test scenarios for server_type field_validator."""

        RFC_VALID = "rfc_valid"
        OID_VALID = "oid_valid"
        OUD_VALID = "oud_valid"
        OPENLDAP_VALID = "openldap_valid"
        OPENLDAP1_VALID = "openldap1_valid"
        AD_VALID = "ad_valid"
        DS389_VALID = "ds389_valid"
        APACHE_VALID = "apache_valid"
        NOVELL_VALID = "novell_valid"
        TIVOLI_VALID = "tivoli_valid"
        RELAXED_VALID = "relaxed_valid"
        GENERIC_VALID = "generic_valid"
        INVALID_TYPE = "invalid_type"

    class LineSeparatorScenario(StrEnum):
        """Test scenarios for ldif_line_separator field_validator (RFC 2849)."""

        LF_VALID = "lf_valid"
        CRLF_VALID = "crlf_valid"
        CR_VALID = "cr_valid"
        DOUBLE_NEWLINE_INVALID = "double_newline_invalid"
        EMPTY_INVALID = "empty_invalid"

    class VersionStringScenario(StrEnum):
        """Test scenarios for ldif_version_string field_validator (RFC 2849)."""

        VERSION_1_STANDARD = "version_1_standard"
        VERSION_1_NO_SPACE = "version_1_no_space"
        VERSION_1_EXTRA_SPACES = "version_1_extra_spaces"
        MISSING_COLON_INVALID = "missing_colon_invalid"
        VERSION_2_INVALID = "version_2_invalid"
        NON_NUMERIC_INVALID = "non_numeric_invalid"
        EMPTY_INVALID = "empty_invalid"

    class ModelValidatorScenario(StrEnum):
        """Test scenarios for cross-field model_validator tests."""

        MANUAL_WITH_SERVER_TYPE = "manual_with_server_type"
        MANUAL_WITHOUT_SERVER_TYPE = "manual_without_server_type"
        AUTO_WITH_NONE_SERVER_TYPE = "auto_with_none_server_type"
        DISABLED_WITH_NONE_SERVER_TYPE = "disabled_with_none_server_type"

    # ═══════════════════════════════════════════════════════════════════════════
    # TEST DATA MAPPINGS
    # ═══════════════════════════════════════════════════════════════════════════

    ENCODING_TEST_DATA: ClassVar[dict[str, tuple[str, bool]]] = {
        EncodingScenario.UTF8_VALID: ("utf-8", True),
        EncodingScenario.LATIN1_VALID: ("latin-1", True),
        EncodingScenario.ASCII_VALID: ("ascii", True),
        EncodingScenario.INVALID_CODEC: ("invalid-codec-xyz", False),
        EncodingScenario.NONEXISTENT_CODEC: ("nonexistent-encoding", False),
        EncodingScenario.FAKE_CODEC: ("fake-codec", False),
    }

    SERVER_TYPE_TEST_DATA: ClassVar[dict[str, tuple[str, bool]]] = {
        # Use canonical server type names that match c.Ldif.ServerTypes enum values
        ServerTypeScenario.RFC_VALID: ("rfc", True),
        ServerTypeScenario.OID_VALID: ("oid", True),
        ServerTypeScenario.OUD_VALID: ("oud", True),
        ServerTypeScenario.OPENLDAP_VALID: ("openldap", True),
        ServerTypeScenario.OPENLDAP1_VALID: ("openldap1", True),
        ServerTypeScenario.AD_VALID: (
            "ad",
            True,
        ),  # canonical is "ad", not "active_directory"
        ServerTypeScenario.DS389_VALID: (
            "ds389",
            True,
        ),  # canonical is "ds389", not "389ds"
        ServerTypeScenario.APACHE_VALID: (
            "apache",
            True,
        ),  # canonical is "apache", not "apache_directory"
        ServerTypeScenario.NOVELL_VALID: (
            "novell",
            True,
        ),  # canonical is "novell", not "novell_edirectory"
        ServerTypeScenario.TIVOLI_VALID: ("ibm_tivoli", True),
        ServerTypeScenario.RELAXED_VALID: ("relaxed", True),
        ServerTypeScenario.GENERIC_VALID: ("generic", True),
        ServerTypeScenario.INVALID_TYPE: ("invalid-server-xyz", False),
    }

    LINE_SEPARATOR_TEST_DATA: ClassVar[dict[str, tuple[str, bool]]] = {
        LineSeparatorScenario.LF_VALID: ("\n", True),
        LineSeparatorScenario.CRLF_VALID: ("\r\n", True),
        LineSeparatorScenario.CR_VALID: ("\r", True),
        LineSeparatorScenario.DOUBLE_NEWLINE_INVALID: ("\\n\\n", False),
        LineSeparatorScenario.EMPTY_INVALID: ("", False),
    }

    VERSION_STRING_TEST_DATA: ClassVar[dict[str, tuple[str, bool]]] = {
        VersionStringScenario.VERSION_1_STANDARD: ("version: 1", True),
        VersionStringScenario.VERSION_1_NO_SPACE: ("version:1", True),
        VersionStringScenario.VERSION_1_EXTRA_SPACES: ("version:   1", True),
        VersionStringScenario.MISSING_COLON_INVALID: ("version 1", False),
        VersionStringScenario.VERSION_2_INVALID: ("version: 2", False),
        VersionStringScenario.NON_NUMERIC_INVALID: ("version: abc", False),
        VersionStringScenario.EMPTY_INVALID: ("", False),
    }

    MODEL_VALIDATOR_TEST_DATA: ClassVar[
        dict[str, tuple[Literal["auto", "manual", "disabled"], str | None, bool]]
    ] = {
        ModelValidatorScenario.MANUAL_WITH_SERVER_TYPE: (
            "manual",
            "oud",
            True,
        ),
        ModelValidatorScenario.MANUAL_WITHOUT_SERVER_TYPE: (
            "manual",
            None,
            False,
        ),
        ModelValidatorScenario.AUTO_WITH_NONE_SERVER_TYPE: (
            "auto",
            None,
            True,
        ),
        ModelValidatorScenario.DISABLED_WITH_NONE_SERVER_TYPE: (
            "disabled",
            None,
            True,
        ),
    }

    # ═══════════════════════════════════════════════════════════════════════════
    # PARAMETRIZED TESTS
    # ═══════════════════════════════════════════════════════════════════════════

    @pytest.mark.parametrize(
        ("scenario", "encoding", "should_succeed"),
        [(name, data[0], data[1]) for name, data in ENCODING_TEST_DATA.items()],
    )
    def test_encoding_field_validator(
        self,
        scenario: str,
        encoding: str,
        should_succeed: bool,
    ) -> None:
        """Test ldif_encoding field_validator with parametrized scenarios."""
        if should_succeed:
            # Pydantic validates encoding at runtime
            config = FlextLdifSettings(ldif_encoding=encoding)
            assert config.ldif_encoding == encoding
        else:
            with pytest.raises(ValidationError) as exc_info:
                FlextLdifSettings(
                    ldif_encoding=encoding,
                )
            error_str = str(exc_info.value).lower()
            assert encoding.lower() in error_str or "invalid encoding" in error_str, (
                f"Failed for scenario {scenario}: {exc_info.value}"
            )

    @pytest.mark.parametrize(
        ("scenario", "server_type", "should_succeed"),
        [(name, data[0], data[1]) for name, data in SERVER_TYPE_TEST_DATA.items()],
    )
    def test_server_type_field_validator(
        self,
        scenario: str,
        server_type: str,
        should_succeed: bool,
    ) -> None:
        """Test server_type field_validator with parametrized scenarios."""
        if should_succeed:
            # Pydantic validates and normalizes server_type at runtime
            config = FlextLdifSettings(server_type=server_type)
            # The validator normalizes aliases to canonical form
            # So we should expect the normalized value, not the original
            expected_server_type = FlextLdifUtilities.Ldif.Server.normalize_server_type(
                server_type
            )
            assert config.server_type == expected_server_type
        else:
            with pytest.raises(ValidationError) as exc_info:
                FlextLdifSettings(
                    server_type=server_type,
                )
            error_str = str(exc_info.value).lower()
            assert server_type.lower() in error_str or "invalid server" in error_str, (
                f"Failed for scenario {scenario}: {exc_info.value}"
            )

    @pytest.mark.parametrize(
        ("scenario", "line_separator", "should_succeed"),
        [(name, data[0], data[1]) for name, data in LINE_SEPARATOR_TEST_DATA.items()],
    )
    def test_line_separator_field_validator(
        self,
        scenario: str,
        line_separator: str,
        should_succeed: bool,
    ) -> None:
        """Test ldif_line_separator field_validator (RFC 2849) with parametrized scenarios."""
        if should_succeed:
            config = FlextLdifSettings(
                ldif_line_separator=line_separator,
            )
            assert config.ldif_line_separator == line_separator
        else:
            with pytest.raises(ValidationError) as exc_info:
                FlextLdifSettings(
                    ldif_line_separator=line_separator,
                )
            error_str = str(exc_info.value).lower()
            assert "rfc 2849" in error_str or "invalid" in error_str, (
                f"Failed for scenario {scenario}: {exc_info.value}"
            )

    @pytest.mark.parametrize(
        ("scenario", "version_string", "should_succeed"),
        [(name, data[0], data[1]) for name, data in VERSION_STRING_TEST_DATA.items()],
    )
    def test_version_string_field_validator(
        self,
        scenario: str,
        version_string: str,
        should_succeed: bool,
    ) -> None:
        """Test ldif_version_string field_validator (RFC 2849) with parametrized scenarios."""
        if should_succeed:
            config = FlextLdifSettings(
                ldif_version_string=version_string,
            )
            assert config.ldif_version_string == version_string
        else:
            with pytest.raises(ValidationError) as exc_info:
                FlextLdifSettings(
                    ldif_version_string=version_string,
                )
            error_str = str(exc_info.value).lower()
            assert (
                "version:" in error_str
                or "invalid" in error_str
                or "rfc 2849" in error_str
            ), f"Failed for scenario {scenario}: {exc_info.value}"

    @pytest.mark.parametrize(
        ("scenario", "mode", "server_type", "should_succeed"),
        [
            (name, data[0], data[1], data[2])
            for name, data in MODEL_VALIDATOR_TEST_DATA.items()
        ],
    )
    def test_model_validator_quirks_consistency(
        self,
        scenario: str,
        mode: Literal["auto", "manual", "disabled"],
        server_type: str | None,
        should_succeed: bool,
    ) -> None:
        """Test cross-field model_validator for quirks_detection_mode consistency.

        mode uses Literal type matching lib_c.Ldif.LiteralTypes.DetectionMode.
        Pydantic validates the value at runtime.
        """
        if should_succeed:
            # Pydantic validates quirks_detection_mode and quirks_server_type at runtime
            config = FlextLdifSettings(
                quirks_detection_mode=mode,
                quirks_server_type=server_type,
            )
            assert config.quirks_detection_mode == mode
            assert config.quirks_server_type == server_type
        else:
            with pytest.raises(ValidationError) as exc_info:
                FlextLdifSettings(
                    quirks_detection_mode=mode,
                    quirks_server_type=server_type,
                )
            error_str = str(exc_info.value).lower()
            assert "quirks_server_type" in error_str and "manual" in error_str, (
                f"Failed for scenario {scenario}: {exc_info.value}"
            )


__all__ = [
    "TestFlextLdifSettingsValidators",
]
