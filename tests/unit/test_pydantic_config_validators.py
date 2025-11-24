"""Expert tests for Pydantic v2 validators in config - RFC compliance.

Tests validate that FlextLdifConfig field_validators:
1. Use @field_validator correctly (Pydantic v2 pattern)
2. Validate RFC 2849 compliance (encoding, line separators, version)
3. Validate server type against FlextLdifConstants.ServerTypes
4. Reject invalid values with clear error messages

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import cast

import pytest

from flext_ldif import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants


class TestFlextLdifConfigEncodingValidator:
    """FlextLdifConfig ldif_encoding field_validator tests."""

    def test_valid_utf8_encoding_accepted(self) -> None:
        """Validate UTF-8 encoding is accepted (RFC 2849 recommended)."""
        config = FlextLdifConfig(ldif_encoding="utf-8")
        assert config.ldif_encoding == "utf-8"

    def test_valid_latin1_encoding_accepted(self) -> None:
        """Validate latin-1 encoding is accepted (valid Python codec)."""
        config = FlextLdifConfig(ldif_encoding="latin-1")
        assert config.ldif_encoding == "latin-1"

    def test_valid_ascii_encoding_accepted(self) -> None:
        """Validate ASCII encoding is accepted (valid Python codec)."""
        config = FlextLdifConfig(ldif_encoding="ascii")
        assert config.ldif_encoding == "ascii"

    def test_invalid_encoding_raises_validation_error(self) -> None:
        """Validate invalid encoding raises ValidationError from field_validator."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(
                ldif_encoding=cast(
                    "FlextLdifConstants.LiteralTypes.EncodingType", "invalid-codec-xyz"
                )
            )

        # Error should mention the invalid encoding
        error_str = str(exc_info.value)
        assert (
            "invalid-codec-xyz" in error_str.lower()
            or "invalid encoding" in error_str.lower()
        )


class TestFlextLdifConfigServerTypeValidator:
    """FlextLdifConfig server_type field_validator tests."""

    def test_valid_rfc_server_type_accepted(self) -> None:
        """Validate 'rfc' server type is accepted."""
        config = FlextLdifConfig(server_type="rfc")
        assert config.server_type == "rfc"

    def test_valid_oid_server_type_accepted(self) -> None:
        """Validate 'oid' server type is accepted."""
        config = FlextLdifConfig(server_type="oid")
        assert config.server_type == "oid"

    def test_valid_oud_server_type_accepted(self) -> None:
        """Validate 'oud' server type is accepted."""
        config = FlextLdifConfig(server_type="oud")
        assert config.server_type == "oud"

    def test_valid_openldap_server_type_accepted(self) -> None:
        """Validate 'openldap' server type is accepted."""
        config = FlextLdifConfig(server_type="openldap")
        assert config.server_type == "openldap"

    def test_valid_openldap1_server_type_accepted(self) -> None:
        """Validate 'openldap1' server type is accepted."""
        config = FlextLdifConfig(server_type="openldap1")
        assert config.server_type == "openldap1"

    def test_valid_ad_server_type_accepted(self) -> None:
        """Validate 'active_directory' (Active Directory) server type is accepted."""
        config = FlextLdifConfig(server_type="active_directory")
        assert config.server_type == "active_directory"

    def test_valid_ds389_server_type_accepted(self) -> None:
        """Validate '389ds' (Red Hat Directory Server) server type is accepted."""
        config = FlextLdifConfig(server_type="389ds")
        assert config.server_type == "389ds"

    def test_valid_apache_server_type_accepted(self) -> None:
        """Validate 'apache_directory' (Apache Directory Server) server type is accepted."""
        config = FlextLdifConfig(server_type="apache_directory")
        assert config.server_type == "apache_directory"

    def test_valid_novell_server_type_accepted(self) -> None:
        """Validate 'novell_edirectory' (Novell eDirectory) server type is accepted."""
        config = FlextLdifConfig(server_type="novell_edirectory")
        assert config.server_type == "novell_edirectory"

    def test_valid_tivoli_server_type_accepted(self) -> None:
        """Validate 'ibm_tivoli' (IBM Tivoli Directory Server) server type is accepted."""
        config = FlextLdifConfig(server_type="ibm_tivoli")
        assert config.server_type == "ibm_tivoli"

    def test_valid_relaxed_server_type_accepted(self) -> None:
        """Validate 'relaxed' (lenient parsing mode) server type is accepted."""
        config = FlextLdifConfig(server_type="relaxed")
        assert config.server_type == "relaxed"

    def test_valid_generic_server_type_accepted(self) -> None:
        """Validate 'generic' (legacy alias for RFC) server type is accepted."""
        config = FlextLdifConfig(server_type="generic")
        assert config.server_type == "generic"

    def test_invalid_server_type_raises_validation_error(self) -> None:
        """Validate invalid server_type raises ValidationError from field_validator."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(
                server_type=cast(
                    "FlextLdifConstants.LiteralTypes.ServerType", "invalid-server-xyz"
                )
            )

        # Error should mention the invalid server type
        error_str = str(exc_info.value)
        assert (
            "invalid-server-xyz" in error_str.lower()
            or "invalid server" in error_str.lower()
        )


class TestFlextLdifConfigLineSeparatorValidator:
    """FlextLdifConfig ldif_line_separator field_validator tests (RFC 2849)."""

    def test_valid_lf_line_separator_accepted(self) -> None:
        r"""Validate LF (\\n) line separator is accepted (RFC 2849 § 2)."""
        config = FlextLdifConfig(ldif_line_separator="\n")
        assert config.ldif_line_separator == "\n"

    def test_valid_crlf_line_separator_accepted(self) -> None:
        r"""Validate CRLF (\\r\\n) line separator is accepted (RFC 2849 § 2)."""
        config = FlextLdifConfig(ldif_line_separator="\r\n")
        assert config.ldif_line_separator == "\r\n"

    def test_valid_cr_line_separator_accepted(self) -> None:
        r"""Validate CR (\\r) line separator is accepted (RFC 2849 § 2)."""
        config = FlextLdifConfig(ldif_line_separator="\r")
        assert config.ldif_line_separator == "\r"

    def test_invalid_line_separator_raises_validation_error(self) -> None:
        """Validate invalid line separator raises ValidationError from field_validator."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_line_separator="\\n\\n")  # Double newline - invalid

        # Error should mention RFC 2849 compliance
        error_str = str(exc_info.value)
        assert "rfc 2849" in error_str.lower() or "invalid" in error_str.lower()

    def test_empty_line_separator_raises_validation_error(self) -> None:
        """Validate empty line separator raises ValidationError."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_line_separator="")

        error_str = str(exc_info.value)
        assert "rfc 2849" in error_str.lower() or "invalid" in error_str.lower()


class TestFlextLdifConfigVersionStringValidator:
    """FlextLdifConfig ldif_version_string field_validator tests (RFC 2849)."""

    def test_valid_version_1_accepted(self) -> None:
        """Validate 'version: 1' is accepted (RFC 2849 § 2)."""
        config = FlextLdifConfig(ldif_version_string="version: 1")
        assert config.ldif_version_string == "version: 1"

    def test_valid_version_1_no_space_accepted(self) -> None:
        """Validate 'version:1' (no space) is accepted."""
        config = FlextLdifConfig(ldif_version_string="version:1")
        assert config.ldif_version_string == "version:1"

    def test_valid_version_1_extra_spaces_accepted(self) -> None:
        """Validate 'version:   1' (extra spaces) is accepted."""
        config = FlextLdifConfig(ldif_version_string="version:   1")
        assert config.ldif_version_string == "version:   1"

    def test_invalid_version_missing_colon_raises_error(self) -> None:
        """Validate version string without colon raises ValidationError."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_version_string="version 1")

        error_str = str(exc_info.value)
        assert "version:" in error_str.lower() or "rfc 2849" in error_str.lower()

    def test_invalid_version_2_raises_error(self) -> None:
        """Validate version 2 raises ValidationError (only version 1 supported)."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_version_string="version: 2")

        error_str = str(exc_info.value)
        assert "version" in error_str.lower()
        assert "1" in error_str or "unsupported" in error_str.lower()

    def test_invalid_version_non_numeric_raises_error(self) -> None:
        """Validate non-numeric version raises ValidationError."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_version_string="version: abc")

        error_str = str(exc_info.value)
        assert "invalid" in error_str.lower() or "format" in error_str.lower()

    def test_invalid_version_empty_raises_error(self) -> None:
        """Validate empty version string raises ValidationError."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(ldif_version_string="")

        error_str = str(exc_info.value)
        assert "version:" in error_str.lower() or "invalid" in error_str.lower()


class TestFlextLdifConfigModelValidator:
    """FlextLdifConfig model_validator tests (cross-field validation)."""

    def test_manual_detection_mode_requires_quirks_server_type(self) -> None:
        """Validate manual detection mode requires quirks_server_type."""
        with pytest.raises(Exception) as exc_info:  # Pydantic ValidationError
            FlextLdifConfig(
                quirks_detection_mode="manual",
                quirks_server_type=None,  # Missing required field
            )

        error_str = str(exc_info.value)
        assert "quirks_server_type" in error_str.lower()
        assert "manual" in error_str.lower()

    def test_manual_detection_mode_with_server_type_accepted(self) -> None:
        """Validate manual detection mode with quirks_server_type is accepted."""
        config = FlextLdifConfig(
            quirks_detection_mode="manual",
            quirks_server_type="oud",
        )

        assert config.quirks_detection_mode == "manual"
        assert config.quirks_server_type == "oud"

    def test_auto_detection_mode_allows_none_server_type(self) -> None:
        """Validate auto detection mode allows None quirks_server_type."""
        config = FlextLdifConfig(
            quirks_detection_mode="auto",
            quirks_server_type=None,
        )

        assert config.quirks_detection_mode == "auto"
        assert config.quirks_server_type is None

    def test_disabled_detection_mode_allows_none_server_type(self) -> None:
        """Validate disabled detection mode allows None quirks_server_type."""
        config = FlextLdifConfig(
            quirks_detection_mode="disabled",
            quirks_server_type=None,
        )

        assert config.quirks_detection_mode == "disabled"
        assert config.quirks_server_type is None


__all__ = [
    "TestFlextLdifConfigEncodingValidator",
    "TestFlextLdifConfigLineSeparatorValidator",
    "TestFlextLdifConfigModelValidator",
    "TestFlextLdifConfigServerTypeValidator",
    "TestFlextLdifConfigVersionStringValidator",
]
