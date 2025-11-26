"""Comprehensive unit tests for FlextLdifWriter format options via FlextLdifConfig.

Tests all writer format options using config-centric architecture with DRY principles.

ARCHITECTURE:
- FlextLdifConfig (registered namespace) is source of truth for all LDIF settings
- Tests use config.get_namespace() to access LDIF configuration
- Parametrized tests dramatically reduce code duplication
- Enum mappings centralize field name translations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Any

import pytest
from flext_core import FlextConfig

from flext_ldif import FlextLdifModels, FlextLdifWriter
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.utilities import FlextLdifUtilities


def config_to_write_options(
    config: FlextLdifConfig,
) -> FlextLdifModels.WriteFormatOptions:
    """Convert FlextLdifConfig to WriteFormatOptions."""
    return FlextLdifModels.WriteFormatOptions(
        line_width=config.ldif_max_line_length,
        respect_attribute_order=config.ldif_write_respect_attribute_order,
        sort_attributes=config.ldif_write_sort_attributes,
        write_hidden_attributes_as_comments=config.ldif_write_hidden_attributes_as_comments,
        write_metadata_as_comments=config.ldif_write_metadata_as_comments,
        include_version_header=config.ldif_write_include_version_header,
        include_timestamps=config.ldif_write_include_timestamps,
        base64_encode_binary=config.ldif_write_base64_encode_binary,
        fold_long_lines=config.ldif_write_fold_long_lines,
        restore_original_format=config.ldif_write_restore_original_format,
        write_empty_values=config.ldif_write_empty_values,
        normalize_attribute_names=config.ldif_write_normalize_attribute_names,
        include_dn_comments=config.ldif_write_include_dn_comments,
        write_removed_attributes_as_comments=config.ldif_write_removed_attributes_as_comments,
        write_migration_header=config.ldif_write_migration_header,
        migration_header_template=config.ldif_write_migration_header_template,
        write_rejection_reasons=config.ldif_write_rejection_reasons,
        write_transformation_comments=config.ldif_write_transformation_comments,
        include_removal_statistics=config.ldif_write_include_removal_statistics,
        ldif_changetype=config.ldif_write_changetype,
        ldif_modify_operation=config.ldif_write_modify_operation,
        write_original_entry_as_comment=config.ldif_write_original_entry_as_comment,
        entry_category=config.ldif_write_entry_category,
        acl_attribute_names=config.ldif_write_acl_attribute_names,
        comment_acl_in_non_acl_phases=config.ldif_write_comment_acl_in_non_acl_phases,
        use_rfc_attribute_order=config.ldif_write_use_rfc_attribute_order,
        rfc_order_priority_attributes=config.ldif_write_rfc_order_priority_attributes,
    )


class WriterOption(StrEnum):
    """Enum mapping WriteFormatOptions fields to FlextLdifConfig fields."""

    LINE_WIDTH = "ldif_max_line_length"
    FOLD_LONG_LINES = "ldif_write_fold_long_lines"
    RESPECT_ATTRIBUTE_ORDER = "ldif_write_respect_attribute_order"
    SORT_ATTRIBUTES = "ldif_write_sort_attributes"
    WRITE_HIDDEN_ATTRS_AS_COMMENTS = "ldif_write_hidden_attributes_as_comments"
    WRITE_METADATA_AS_COMMENTS = "ldif_write_metadata_as_comments"
    INCLUDE_VERSION_HEADER = "ldif_write_include_version_header"
    INCLUDE_TIMESTAMPS = "ldif_write_include_timestamps"
    BASE64_ENCODE_BINARY = "ldif_write_base64_encode_binary"
    WRITE_EMPTY_VALUES = "ldif_write_empty_values"
    NORMALIZE_ATTRIBUTE_NAMES = "ldif_write_normalize_attribute_names"
    INCLUDE_DN_COMMENTS = "ldif_write_include_dn_comments"
    USE_ORIGINAL_ACL_FORMAT_AS_NAME = "ldif_write_use_original_acl_format_as_name"


# Reverse mapping: config field name → WriteFormatOptions field name
CONFIG_TO_MODEL_FIELD_MAP = {
    "ldif_max_line_length": "line_width",
    "ldif_write_fold_long_lines": "fold_long_lines",
    "ldif_write_respect_attribute_order": "respect_attribute_order",
    "ldif_write_sort_attributes": "sort_attributes",
    "ldif_write_hidden_attributes_as_comments": "write_hidden_attributes_as_comments",
    "ldif_write_metadata_as_comments": "write_metadata_as_comments",
    "ldif_write_include_version_header": "include_version_header",
    "ldif_write_include_timestamps": "include_timestamps",
    "ldif_write_base64_encode_binary": "base64_encode_binary",
    "ldif_write_empty_values": "write_empty_values",
    "ldif_write_normalize_attribute_names": "normalize_attribute_names",
    "ldif_write_include_dn_comments": "include_dn_comments",
    "ldif_write_use_original_acl_format_as_name": "use_original_acl_format_as_name",
}


class TestWriterFormatOptions:
    """Test all WriteFormatOptions functionality via FlextLdifConfig."""

    @pytest.fixture
    def writer_service(self) -> FlextLdifWriter:
        """Create writer service instance."""
        return FlextLdifWriter()

    @pytest.fixture
    def config_instance(self) -> FlextConfig:
        """Create config instance for test isolation using modern API."""
        # Reset singleton for test isolation
        FlextConfig.reset_global_instance()
        return FlextConfig.get_global_instance()

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create a sample entry for testing."""
        return self._create_entry(
            dn="cn=John Doe,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person", "organizationalPerson"],
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john.doe@example.com"],
                "telephoneNumber": ["+1-555-123-4567"],
                "description": [
                    "A very long description that should definitely exceed the normal "
                    "line width limit for LDIF formatting and trigger line folding "
                    "behavior according to RFC 2849 specifications",
                ],
            },
        )

    @pytest.fixture
    def entry_with_metadata(self) -> FlextLdifModels.Entry:
        """Create an entry with metadata for testing."""
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="rfc",
            target_server_type="rfc",
            extensions={
                "attribute_order": [
                    "objectClass",
                    "cn",
                    "sn",
                    "mail",
                    "telephoneNumber",
                ],
                "hidden_attributes": ["telephoneNumber"],
                "source_file": "test.ldif",
            },
        )
        return self._create_entry(
            dn="cn=Jane Smith,ou=people,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["Jane Smith"],
                "sn": ["Smith"],
                "mail": ["jane.smith@example.com"],
                "telephoneNumber": ["+1-555-987-6543"],
                "emptyAttr": [""],
                "description": [""],
            },
            metadata=metadata,
        )

    @pytest.fixture
    def entry_with_binary_data(self) -> FlextLdifModels.Entry:
        """Create an entry with binary/special data for base64 testing."""
        return self._create_entry(
            dn="cn=binary-test,dc=example,dc=com",
            attributes={
                "objectClass": ["person"],
                "cn": ["binary-test"],
                "sn": ["Test"],
                "userPassword": ["{SSHA}abcdefghijklmnopqrstuvwxyz0123456789=="],
                "jpegPhoto": [
                    "binary data with \x00 null bytes and \x01 control chars",
                ],
                "description": ["value\x00with\x01null"],
                "comment": ["ends with null\x00"],
                "specialChars": [": colon at start"],
            },
        )

    @pytest.fixture
    def entry_with_aci_and_acl_metadata(self) -> FlextLdifModels.Entry:
        """Create an entry with aci attribute and ACL_ORIGINAL_FORMAT metadata."""
        metadata = FlextLdifModels.QuirkMetadata(
            quirk_type="oud",
            target_server_type="oud",
            extensions={
                FlextLdifConstants.MetadataKeys.ACL_ORIGINAL_FORMAT: (
                    "access to attr=(cn,sn) by self (read) by * (search)"
                ),
            },
        )
        return self._create_entry(
            dn="cn=acl-test,dc=example,dc=com",
            attributes={
                "objectClass": ["top", "subentry", "aci"],
                "cn": ["acl-test"],
                "aci": [
                    '(targetattr="cn||sn")(version 3.0; acl "default-name"; '
                    'allow(read,search) userdn="ldap:///self";)',
                ],
            },
            metadata=metadata,
        )

    @staticmethod
    def _create_entry(
        dn: str,
        attributes: dict[str, list[str]],
        metadata: FlextLdifModels.QuirkMetadata | None = None,
    ) -> FlextLdifModels.Entry:
        """Factory method to create Entry with reduced boilerplate."""
        entry_kwargs: dict[str, Any] = {
            "dn": FlextLdifModels.DistinguishedName(value=dn),
            "attributes": FlextLdifModels.LdifAttributes(attributes=attributes),
        }
        if metadata is not None:
            entry_kwargs["metadata"] = metadata
        return FlextLdifModels.Entry(**entry_kwargs)

    def _write_with_config(
        self,
        writer: FlextLdifWriter,
        entries: list[FlextLdifModels.Entry],
        config_overrides: dict[str, Any],
        target_server: str = "rfc",
        output_target: str = "string",
        output_path: Path | None = None,
    ) -> str:
        """Helper to write entries with config overrides and return output string."""
        # Convert config field overrides to WriteFormatOptions parameters
        model_kwargs: dict[str, Any] = {}
        for config_field, value in config_overrides.items():
            if config_field in CONFIG_TO_MODEL_FIELD_MAP:
                model_field = CONFIG_TO_MODEL_FIELD_MAP[config_field]
                model_kwargs[model_field] = value

        # Create WriteFormatOptions with override values
        options = FlextLdifModels.WriteFormatOptions(**model_kwargs)

        result = writer.write(
            entries=entries,
            target_server_type=target_server,
            output_target=output_target,
            output_path=output_path,
            format_options=options,
        )

        assert result.is_success, f"Write failed: {result.error}"
        output = result.unwrap()
        assert isinstance(output, str), "Expected string output"
        return output

    # =========================================================================
    # PARAMETRIZED TESTS - Boolean Options (Enabled/Disabled)
    # =========================================================================

    @pytest.mark.parametrize(
        ("option_field", "test_value", "expected_pattern", "check_absence"),
        [
            # Version header
            (WriterOption.INCLUDE_VERSION_HEADER, True, "version: 1", False),
            (WriterOption.INCLUDE_VERSION_HEADER, False, "version: 1", True),
            # Timestamps
            (
                WriterOption.INCLUDE_TIMESTAMPS,
                True,
                r"# Generated on: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}",
                False,
            ),
            (WriterOption.INCLUDE_TIMESTAMPS, False, "# Generated on:", True),
            # Write hidden attrs as comments
            (
                WriterOption.WRITE_HIDDEN_ATTRS_AS_COMMENTS,
                True,
                "# telephoneNumber:",
                False,
            ),
            # Write empty values
            (WriterOption.WRITE_EMPTY_VALUES, True, "emptyAttr:", False),
            (WriterOption.WRITE_EMPTY_VALUES, False, "emptyAttr:", True),
            # Include DN comments
            (WriterOption.INCLUDE_DN_COMMENTS, True, "# Complex DN:", False),
            (WriterOption.INCLUDE_DN_COMMENTS, False, "# Complex DN:", True),
        ],
    )
    def test_boolean_option(
        self,
        writer_service: FlextLdifWriter,
        option_field: WriterOption,
        test_value: bool,
        expected_pattern: str,
        check_absence: bool,
        sample_entry: FlextLdifModels.Entry,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test boolean options with parametrized enabled/disabled values."""
        # Use appropriate entry based on option
        entry = (
            entry_with_metadata
            if option_field
            in {
                WriterOption.WRITE_HIDDEN_ATTRS_AS_COMMENTS,
                WriterOption.WRITE_EMPTY_VALUES,
            }
            else sample_entry
        )

        # Special DN for DN comments test
        if option_field == WriterOption.INCLUDE_DN_COMMENTS:
            long_dn = (
                "cn=Very Long Common Name That Exceeds Normal Length,"
                "ou=Very Long Organizational Unit Name,"
                "o=Very Long Organization Name,dc=example,dc=com"
            )
            entry = self._create_entry(
                dn=long_dn,
                attributes={"objectClass": ["person"], "cn": ["Test"]},
            )

        output = self._write_with_config(
            writer_service,
            [entry],
            {option_field: test_value},
        )

        # Check pattern presence or absence
        if check_absence:
            assert expected_pattern not in output, (
                f"Pattern should be absent when {option_field}={test_value}"
            )
        elif expected_pattern.startswith("#"):
            assert expected_pattern in output, (
                f"Pattern should be present when {option_field}={test_value}"
            )
        else:
            # For regex patterns
            assert re.search(expected_pattern, output), (
                f"Pattern should match when {option_field}={test_value}"
            )

    # =========================================================================
    # Line Width and Folding Tests
    # =========================================================================

    @pytest.mark.parametrize("line_width", [50, 76, 120])
    def test_line_width(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
        line_width: int,
    ) -> None:
        """Test various line_width settings."""
        output = self._write_with_config(
            writer_service,
            [sample_entry],
            {WriterOption.LINE_WIDTH: line_width},
        )

        lines = output.split("\n")
        long_lines = [
            line
            for line in lines
            if len(line) > line_width and not line.startswith(" ")
        ]
        assert len(long_lines) == 0, f"Found unfolded lines longer than {line_width}"

    def test_fold_long_lines_rfc_compliance(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that RFC 2849 compliance is maintained even with fold_long_lines=False."""
        output = self._write_with_config(
            writer_service,
            [sample_entry],
            {WriterOption.FOLD_LONG_LINES: False},
        )

        # Verify RFC 2849 compliance: all lines must be ≤ 76 bytes
        for line in output.split("\n"):
            if line and not line.startswith("#"):
                byte_len = len(line.encode("utf-8"))
                assert byte_len <= 76, f"Line exceeds RFC 2849 limit: {byte_len} > 76"

    # =========================================================================
    # Attribute Ordering Tests
    # =========================================================================

    def test_respect_attribute_order(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test respect_attribute_order preserves metadata order."""
        output = self._write_with_config(
            writer_service,
            [entry_with_metadata],
            {WriterOption.RESPECT_ATTRIBUTE_ORDER: True},
        )

        # Extract attribute order
        lines = [
            line.strip()
            for line in output.split("\n")
            if line.strip()
            and ":" in line
            and not line.startswith(("dn:", "version:", "changetype:", "#"))
        ]

        actual_order = []
        for line in lines:
            attr_name = line.split(":")[0]
            if attr_name not in actual_order:
                actual_order.append(attr_name)

        expected_order = ["objectClass", "cn", "sn", "mail", "telephoneNumber"]
        for i, expected_attr in enumerate(expected_order):
            if i < len(actual_order):
                assert actual_order[i] == expected_attr

    def test_sort_attributes(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test sort_attributes alphabetically orders attributes."""
        output = self._write_with_config(
            writer_service,
            [sample_entry],
            {
                WriterOption.RESPECT_ATTRIBUTE_ORDER: False,
                WriterOption.SORT_ATTRIBUTES: True,
            },
        )

        # Extract attribute names
        attribute_names: list[str] = []
        for line in output.split("\n"):
            if ":" in line and not line.startswith(("dn:", "version:", "#")):
                attr_name = line.split(":")[0].strip()
                if attr_name not in attribute_names:
                    attribute_names.append(attr_name)

        sorted_names = sorted(attribute_names, key=str.lower)
        assert attribute_names == sorted_names

    # =========================================================================
    # Base64 Encoding Tests
    # =========================================================================

    @pytest.mark.parametrize("encode_binary", [True, False])
    def test_base64_encode_binary(
        self,
        writer_service: FlextLdifWriter,
        entry_with_binary_data: FlextLdifModels.Entry,
        encode_binary: bool,
    ) -> None:
        """Test base64_encode_binary option."""
        output = self._write_with_config(
            writer_service,
            [entry_with_binary_data],
            {WriterOption.BASE64_ENCODE_BINARY: encode_binary},
        )

        double_colon_count = output.count("::")
        if encode_binary:
            # Should have base64-encoded values (indicated by ::)
            assert double_colon_count > 0, "Expected base64-encoded attributes"
            assert "jpegPhoto::" in output
            assert "description::" in output
        else:
            assert double_colon_count == 0, "Should not have base64-encoded attributes"

    # =========================================================================
    # Attribute Name Normalization Tests
    # =========================================================================

    @pytest.mark.parametrize("normalize", [True, False])
    def test_normalize_attribute_names(
        self,
        writer_service: FlextLdifWriter,
        normalize: bool,
    ) -> None:
        """Test normalize_attribute_names option."""
        entry = self._create_entry(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "ObjectClass": ["person"],
                "CN": ["Test User"],
                "SN": ["User"],
                "GivenName": ["Test"],
            },
        )

        output = self._write_with_config(
            writer_service,
            [entry],
            {WriterOption.NORMALIZE_ATTRIBUTE_NAMES: normalize},
        )

        if normalize:
            assert "objectclass:" in output
            assert "cn:" in output
            assert "sn:" in output
            assert "givenname:" in output
            # Uppercase should not be present
            assert "ObjectClass:" not in output
            assert "CN:" not in output
        else:
            # Original case preserved
            assert "ObjectClass:" in output
            assert "CN:" in output
            assert "SN:" in output

    # =========================================================================
    # ACL Original Format Tests
    # =========================================================================

    @pytest.mark.parametrize("use_original", [True, False])
    def test_use_original_acl_format_as_name(
        self,
        writer_service: FlextLdifWriter,
        entry_with_aci_and_acl_metadata: FlextLdifModels.Entry,
        use_original: bool,
    ) -> None:
        """Test use_original_acl_format_as_name option."""
        output = self._write_with_config(
            writer_service,
            [entry_with_aci_and_acl_metadata],
            {WriterOption.USE_ORIGINAL_ACL_FORMAT_AS_NAME: use_original},
            target_server="oud",
        )

        # Unfold LDIF lines
        unfolded = output.replace("\n ", "")

        if use_original:
            assert "access to attr=(cn,sn) by self (read) by * (search)" in unfolded
            assert 'acl "default-name"' not in unfolded
        else:
            assert 'acl "default-name"' in output

    # =========================================================================
    # Combined Options Test
    # =========================================================================

    def test_combined_options(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test combination of multiple write options."""
        output = self._write_with_config(
            writer_service,
            [entry_with_metadata],
            {
                WriterOption.LINE_WIDTH: 60,
                WriterOption.RESPECT_ATTRIBUTE_ORDER: True,
                WriterOption.WRITE_METADATA_AS_COMMENTS: True,
                WriterOption.INCLUDE_VERSION_HEADER: True,
                WriterOption.INCLUDE_TIMESTAMPS: True,
                WriterOption.BASE64_ENCODE_BINARY: True,
                WriterOption.FOLD_LONG_LINES: True,
                WriterOption.WRITE_EMPTY_VALUES: False,
                WriterOption.NORMALIZE_ATTRIBUTE_NAMES: False,
            },
        )

        # Verify multiple options working together
        assert "version: 1" in output
        assert "# Generated on:" in output
        assert "# Entry Metadata:" in output
        assert "emptyAttr:" not in output

        # Check line folding
        lines = output.split("\n")
        long_lines = [
            line
            for line in lines
            if len(line) > 60 and not line.startswith(" ") and not line.startswith("#")
        ]
        assert len(long_lines) == 0

    # =========================================================================
    # Output Target Tests
    # =========================================================================

    def test_file_output_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
        tmp_path: Path,
    ) -> None:
        """Test writing to file with options."""
        output_file = tmp_path / "test_output.ldif"

        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif", FlextLdifConfig,
        )
        config.ldif_write_include_version_header = True
        config.ldif_write_include_timestamps = True
        config.ldif_max_line_length = 50
        options = config_to_write_options(config)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
            format_options=options,
        )

        assert result.is_success
        assert output_file.exists()

        content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in content
        assert "# Generated on:" in content

    @pytest.mark.parametrize(
        ("output_target", "expected_type"),
        [
            ("ldap3", list),
            ("model", list),
        ],
    )
    def test_non_string_output_targets(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
        output_target: str,
        expected_type: type,
    ) -> None:
        """Test ldap3 and model output formats."""
        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif", FlextLdifConfig,
        )
        config.ldif_write_normalize_attribute_names = True
        options = config_to_write_options(config)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target=output_target,
            format_options=options,
        )

        assert result.is_success
        output_data = result.unwrap()
        assert isinstance(output_data, expected_type)
        # Type narrow for len() call
        if isinstance(output_data, list):
            assert len(output_data) == 1

    # =========================================================================
    # Edge Cases and Validation
    # =========================================================================

    def test_minimal_line_width(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test edge case with minimal line width."""
        output = self._write_with_config(
            writer_service,
            [sample_entry],
            {
                WriterOption.LINE_WIDTH: 10,
                WriterOption.FOLD_LONG_LINES: True,
            },
        )

        # Verify all lines respect the 10-byte width
        for line in output.split("\n"):
            if line and not line.startswith("#"):
                byte_len = len(line.encode("utf-8"))
                assert byte_len <= 10, f"Line exceeds 10-byte limit: {byte_len} > 10"

    def test_empty_entries_list(self, writer_service: FlextLdifWriter) -> None:
        """Test writing empty entries list with options."""
        output = self._write_with_config(
            writer_service,
            [],
            {
                WriterOption.INCLUDE_VERSION_HEADER: True,
                WriterOption.INCLUDE_TIMESTAMPS: True,
            },
        )

        assert "version: 1" in output
        assert "# Generated on:" in output
        assert "# Total entries: 0" in output

    def test_invalid_server_type_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that options don't interfere with server type validation."""
        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif", FlextLdifConfig,
        )
        config.ldif_write_include_version_header = True
        options = config_to_write_options(config)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="nonexistent_server_type",
            output_target="string",
            format_options=options,
        )

        assert result.is_failure
        error_msg = result.error or ""
        assert "server type" in error_msg.lower()

    def test_default_options_behavior(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that default options produce expected output."""
        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=None,
        )

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, str), "Expected string output"

        # With defaults: include_version_header=True
        assert "version: 1" in unwrapped
        assert "dn:" in unwrapped
        assert "objectClass:" in unwrapped


class TestSanitizeAclName:
    """Unit tests for FlextLdifUtilitiesACL.sanitize_acl_name function."""

    @pytest.mark.parametrize(
        ("input_str", "expected", "should_sanitize"),
        [
            # No change needed
            (
                "access to attr=(cn) by self (read)",
                "access to attr=(cn) by self (read)",
                False,
            ),
            # Null character
            ("access to\x00attr=(cn)", "access to attr=(cn)", True),
            # Multiple control chars
            ("access\x00to\x01attr\x02=(cn)\x03", "access to attr =(cn)", True),
            # Double quotes
            ('access to "attr"=(cn)', None, True),  # None = check absence of "
            # Empty string
            ("", "", False),
        ],
    )
    def test_sanitize_acl_name(
        self,
        input_str: str,
        expected: str | None,
        should_sanitize: bool,
    ) -> None:
        """Test sanitize_acl_name with various inputs."""
        sanitized, was_sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(input_str)

        assert was_sanitized == should_sanitize

        if expected is not None:
            assert sanitized == expected
        else:
            # Check absence of double quotes
            assert '"' not in sanitized

    def test_sanitize_acl_name_truncation(self) -> None:
        """Test truncation of long strings."""
        input_str = "a" * 300
        sanitized, was_sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(
            input_str, max_length=50,
        )

        assert len(sanitized) == 50
        assert sanitized.endswith("...")
        assert was_sanitized

    def test_sanitize_acl_name_collapses_spaces(self) -> None:
        """Test that multiple spaces are collapsed."""
        input_str = "access\x00\x01\x02to attr"
        sanitized, was_sanitized = FlextLdifUtilities.ACL.sanitize_acl_name(input_str)

        assert "  " not in sanitized
        assert was_sanitized
