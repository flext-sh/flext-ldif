"""Comprehensive unit tests for FlextLdifWriter WriteFormatOptions.

Tests all writer format options with real Entry models and edge cases.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.services.writer import FlextLdifWriter


class TestWriterFormatOptions:
    """Test all WriteFormatOptions functionality."""

    @pytest.fixture
    def writer_service(self) -> FlextLdifWriter:
        """Create writer service instance."""
        return FlextLdifWriter()

    @pytest.fixture
    def sample_entry(self) -> FlextLdifModels.Entry:
        """Create a sample entry for testing."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=John Doe,ou=people,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person", "organizationalPerson"],
                    "cn": ["John Doe"],
                    "sn": ["Doe"],
                    "givenName": ["John"],
                    "mail": ["john.doe@example.com"],
                    "telephoneNumber": ["+1-555-123-4567"],
                    "description": [
                        "A very long description that should definitely exceed the normal line width limit for LDIF formatting and trigger line folding behavior according to RFC 2849 specifications",
                    ],
                },
            ),
        )

    @pytest.fixture
    def entry_with_metadata(self) -> FlextLdifModels.Entry:
        """Create an entry with metadata for testing."""
        metadata = FlextLdifModels.QuirkMetadata(
            server_type="rfc",
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

        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=Jane Smith,ou=people,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["Jane Smith"],
                    "sn": ["Smith"],
                    "mail": ["jane.smith@example.com"],
                    "telephoneNumber": ["+1-555-987-6543"],
                    "emptyAttr": [""],
                    "description": [""],
                },
            ),
            metadata=metadata,
        )

    @pytest.fixture
    def entry_with_binary_data(self) -> FlextLdifModels.Entry:
        """Create an entry with binary/special data for base64 testing."""
        return FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(
                value="cn=binary-test,dc=example,dc=com",
            ),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "objectClass": ["person"],
                    "cn": ["binary-test"],
                    "sn": ["Test"],
                    "userPassword": [
                        "{SSHA}abcdefghijklmnopqrstuvwxyz0123456789==",
                    ],  # Base64-like
                    "jpegPhoto": [
                        "binary data with \x00 null bytes and \x01 control chars",
                    ],
                    "description": [" starts with space"],
                    "comment": ["ends with space "],
                    "specialChars": [": colon at start"],
                },
            ),
        )

    def test_line_width_default(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test default line_width (76 characters)."""
        options = FlextLdifModels.WriteFormatOptions()  # Default line_width=76

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        lines = output.split("\n")
        # Check that long lines are folded
        long_lines = [
            line for line in lines if len(line) > 76 and not line.startswith(" ")
        ]
        assert len(long_lines) == 0, (
            f"Found unfolded lines longer than 76 chars: {long_lines}"
        )

        # Check for folded line continuations (should start with space)
        folded_lines = [line for line in lines if line.startswith(" ")]
        assert len(folded_lines) > 0, "Expected to find folded line continuations"

    def test_line_width_custom(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test custom line_width setting."""
        options = FlextLdifModels.WriteFormatOptions(line_width=50)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        lines = output.split("\n")
        # Check that lines are folded at 50 characters
        long_lines = [
            line for line in lines if len(line) > 50 and not line.startswith(" ")
        ]
        assert len(long_lines) == 0, (
            f"Found unfolded lines longer than 50 chars: {long_lines}"
        )

    def test_respect_attribute_order_enabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test respect_attribute_order=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(respect_attribute_order=True)

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Extract attribute lines (skip dn, version, changetype, and empty lines)
        lines = [
            line.strip()
            for line in output.split("\n")
            if line.strip()
            and not line.startswith("dn:")
            and not line.startswith("version:")
            and not line.startswith("changetype:")
        ]
        attribute_lines = [
            line for line in lines if ":" in line and not line.startswith("#")
        ]

        # Expected order from metadata: objectClass, cn, sn, mail, telephoneNumber
        expected_order = ["objectClass", "cn", "sn", "mail", "telephoneNumber"]
        actual_order = []

        for line in attribute_lines:
            attr_name = line.split(":")[0]
            if attr_name not in actual_order:
                actual_order.append(attr_name)

        # The first few attributes should match the expected order
        for i, expected_attr in enumerate(expected_order):
            if i < len(actual_order):
                assert actual_order[i] == expected_attr, (
                    f"Expected {expected_attr} at position {i}, got {actual_order[i]}"
                )

    def test_respect_attribute_order_disabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test respect_attribute_order=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(
            respect_attribute_order=False,
            sort_attributes=False,
        )

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should contain all attributes but not necessarily in metadata order
        assert "objectClass:" in output
        assert "cn:" in output
        assert "sn:" in output

    def test_sort_attributes_enabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test sort_attributes=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(
            respect_attribute_order=False,  # Must be False for sorting to take effect
            sort_attributes=True,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Extract attribute names in order they appear
        lines = output.split("\n")
        attribute_lines = [
            line
            for line in lines
            if ":" in line
            and not line.startswith("dn:")
            and not line.startswith("version:")
            and not line.startswith("#")
        ]

        attribute_names = []
        for line in attribute_lines:
            attr_name = line.split(":")[0].strip()
            if attr_name not in attribute_names:
                attribute_names.append(attr_name)

        # Should be sorted alphabetically (case-insensitive)
        sorted_names = sorted(attribute_names, key=str.lower)
        assert attribute_names == sorted_names, (
            f"Attributes not sorted: {attribute_names} vs {sorted_names}"
        )

    def test_write_hidden_attributes_as_comments(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test write_hidden_attributes_as_comments=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(
            write_hidden_attributes_as_comments=True,
        )

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # telephoneNumber should be written as a comment (it's in hidden_attributes)
        assert "# telephoneNumber:" in output
        # Regular attributes should still be written normally
        assert "cn: Jane Smith" in output

    def test_write_metadata_as_comments_enabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test write_metadata_as_comments=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(write_metadata_as_comments=True)

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should contain metadata comments
        assert "# Entry Metadata:" in output
        assert "# Server Type: rfc" in output
        assert "# Source File: test.ldif" in output

    def test_write_metadata_as_comments_disabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test write_metadata_as_comments=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(write_metadata_as_comments=False)

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not contain metadata comments
        assert "# Entry Metadata:" not in output
        assert "# Server Type:" not in output

    def test_include_version_header_enabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test include_version_header=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(include_version_header=True)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should start with version header
        lines = output.strip().split("\n")
        assert lines[0] == "version: 1"

    def test_include_version_header_disabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test include_version_header=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(include_version_header=False)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not contain version header
        assert "version: 1" not in output

    def test_include_timestamps_enabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test include_timestamps=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(include_timestamps=True)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should contain timestamp comments
        assert "# Generated on:" in output
        assert "# Total entries: 1" in output

        # Check that timestamp is in ISO format
        timestamp_pattern = r"# Generated on: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        assert re.search(timestamp_pattern, output), (
            "Timestamp not found in expected format"
        )

    def test_include_timestamps_disabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test include_timestamps=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(include_timestamps=False)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not contain timestamp comments
        assert "# Generated on:" not in output
        assert "# Total entries:" not in output

    def test_base64_encode_binary_enabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_binary_data: FlextLdifModels.Entry,
    ) -> None:
        """Test base64_encode_binary=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=True)

        result = writer_service.write(
            entries=[entry_with_binary_data],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should have base64-encoded values (indicated by ::)
        assert "jpegPhoto::" in output  # Binary data should be base64 encoded
        assert "description::" in output  # Starts with space, should be base64 encoded
        assert "comment::" in output  # Ends with space, should be base64 encoded
        assert "specialChars::" in output  # Starts with colon, should be base64 encoded

    def test_base64_encode_binary_disabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_binary_data: FlextLdifModels.Entry,
    ) -> None:
        """Test base64_encode_binary=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(base64_encode_binary=False)

        result = writer_service.write(
            entries=[entry_with_binary_data],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not have base64-encoded values (no ::)
        double_colon_count = output.count("::")
        assert double_colon_count == 0, (
            f"Found {double_colon_count} base64-encoded attributes when disabled"
        )

    def test_fold_long_lines_enabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test fold_long_lines=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(
            fold_long_lines=True,
            line_width=50,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        lines = output.split("\n")
        # Should have folded lines (starting with space)
        folded_lines = [line for line in lines if line.startswith(" ")]
        assert len(folded_lines) > 0, "Expected folded lines when fold_long_lines=True"

    def test_fold_long_lines_disabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test fold_long_lines=False with RFC 2849 compliance.

        When fold_long_lines=False but lines exceed 76 bytes, RFC 2849 requires folding.
        This ensures RFC compliance even with fold_long_lines=False.
        """
        options = FlextLdifModels.WriteFormatOptions(fold_long_lines=False)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        lines = output.split("\n")
        # With fold_long_lines=False, lines exceeding 76 bytes MUST still be folded per RFC 2849
        folded_lines = [line for line in lines if line.startswith(" ")]

        # Verify RFC 2849 compliance: all lines (including continuations) must be ≤ 76 bytes
        all_lines = output.split("\n")
        for line in all_lines:
            if line and not line.startswith("#"):  # Skip comments
                byte_len = len(line.encode("utf-8"))
                assert byte_len <= 76, (
                    f"Line exceeds RFC 2849 limit ({byte_len} > 76): {line[:80]}"
                )

        # Should have folded lines for the long description attribute
        assert len(folded_lines) > 0, (
            "Long description should trigger folding per RFC 2849"
        )

    def test_write_empty_values_enabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test write_empty_values=True functionality."""
        options = FlextLdifModels.WriteFormatOptions(write_empty_values=True)

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should contain empty attributes
        assert "emptyAttr:" in output
        assert "description:" in output

    def test_write_empty_values_disabled(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test write_empty_values=False functionality."""
        options = FlextLdifModels.WriteFormatOptions(write_empty_values=False)

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not contain empty attributes
        assert "emptyAttr:" not in output

    def test_normalize_attribute_names_enabled(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test normalize_attribute_names=True functionality."""
        # Create entry with mixed-case attribute names
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "ObjectClass": ["person"],
                    "CN": ["Test User"],
                    "SN": ["User"],
                    "GivenName": ["Test"],
                },
            ),
        )

        options = FlextLdifModels.WriteFormatOptions(normalize_attribute_names=True)

        result = writer_service.write(
            entries=[entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # All attribute names should be lowercase
        assert "objectclass:" in output
        assert "cn:" in output
        assert "sn:" in output
        assert "givenname:" in output

        # Should not contain uppercase versions
        assert "ObjectClass:" not in output
        assert "CN:" not in output
        assert "GivenName:" not in output

    def test_normalize_attribute_names_disabled(
        self,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test normalize_attribute_names=False functionality."""
        # Create entry with mixed-case attribute names
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value="cn=test,dc=example,dc=com"),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={
                    "ObjectClass": ["person"],
                    "CN": ["Test User"],
                    "SN": ["User"],
                },
            ),
        )

        options = FlextLdifModels.WriteFormatOptions(normalize_attribute_names=False)

        result = writer_service.write(
            entries=[entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Attribute names should preserve original case
        assert "ObjectClass:" in output
        assert "CN:" in output
        assert "SN:" in output

    def test_include_dn_comments_enabled(self, writer_service: FlextLdifWriter) -> None:
        """Test include_dn_comments=True functionality."""
        # Create entry with very long DN
        long_dn = "cn=Very Long Common Name That Exceeds Normal Length,ou=Very Long Organizational Unit Name,o=Very Long Organization Name,dc=example,dc=com"
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=long_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["person"], "cn": ["Test"]},
            ),
        )

        options = FlextLdifModels.WriteFormatOptions(include_dn_comments=True)

        result = writer_service.write(
            entries=[entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should include DN comment for complex DN
        assert "# Complex DN:" in output

    def test_include_dn_comments_disabled(
        self,
        writer_service: FlextLdifWriter,
    ) -> None:
        """Test include_dn_comments=False functionality."""
        long_dn = "cn=Very Long Common Name That Exceeds Normal Length,ou=people,dc=example,dc=com"
        entry = FlextLdifModels.Entry(
            dn=FlextLdifModels.DistinguishedName(value=long_dn),
            attributes=FlextLdifModels.LdifAttributes(
                attributes={"objectClass": ["person"], "cn": ["Test"]},
            ),
        )

        options = FlextLdifModels.WriteFormatOptions(include_dn_comments=False)

        result = writer_service.write(
            entries=[entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should not include DN comments
        assert "# Complex DN:" not in output

    def test_combined_options(
        self,
        writer_service: FlextLdifWriter,
        entry_with_metadata: FlextLdifModels.Entry,
    ) -> None:
        """Test combination of multiple write options."""
        options = FlextLdifModels.WriteFormatOptions(
            line_width=60,
            respect_attribute_order=True,
            write_metadata_as_comments=True,
            include_version_header=True,
            include_timestamps=True,
            base64_encode_binary=True,
            fold_long_lines=True,
            write_empty_values=False,
            normalize_attribute_names=False,
        )

        result = writer_service.write(
            entries=[entry_with_metadata],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Verify multiple options working together
        assert "version: 1" in output  # include_version_header
        assert "# Generated on:" in output  # include_timestamps
        assert "# Entry Metadata:" in output  # write_metadata_as_comments
        assert "emptyAttr:" not in output  # write_empty_values=False

        # Check line folding at custom width
        # Note: Comments (starting with #) may exceed width, but data lines should be folded
        lines = output.split("\n")
        long_lines = [
            line
            for line in lines
            if len(line) > 60 and not line.startswith(" ") and not line.startswith("#")
        ]
        assert len(long_lines) == 0, f"Data lines exceed width: {long_lines}"

    def test_file_output_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
        tmp_path: Path,
    ) -> None:
        """Test writing to file with options."""
        output_file = tmp_path / "test_output.ldif"

        options = FlextLdifModels.WriteFormatOptions(
            include_version_header=True,
            include_timestamps=True,
            line_width=50,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="file",
            output_path=output_file,
            format_options=options,
        )

        assert result.is_success
        assert output_file.exists()

        # Verify file content has options applied
        content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in content
        assert "# Generated on:" in content

    def test_ldap3_output_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test ldap3 output format (options shouldn't affect ldap3 format)."""
        options = FlextLdifModels.WriteFormatOptions(
            include_version_header=True,
            include_timestamps=True,
            normalize_attribute_names=True,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="ldap3",
            format_options=options,
        )

        assert result.is_success
        ldap3_data = result.unwrap()

        # Should be list of tuples: (dn, attributes_dict)
        assert isinstance(ldap3_data, list)
        assert len(ldap3_data) == 1

        dn, attrs = ldap3_data[0]
        assert dn == "cn=John Doe,ou=people,dc=example,dc=com"
        assert isinstance(attrs, dict)
        assert "objectClass" in attrs
        assert isinstance(attrs["objectClass"], list)

    def test_model_output_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test model output format (options shouldn't affect model format)."""
        options = FlextLdifModels.WriteFormatOptions(
            normalize_attribute_names=True,
            sort_attributes=True,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="model",
            format_options=options,
        )

        assert result.is_success
        models = result.unwrap()

        # Should return the original Entry models
        assert isinstance(models, list)
        assert len(models) == 1
        assert isinstance(models[0], FlextLdifModels.Entry)
        assert models[0].dn.value == sample_entry.dn.value

    def test_options_validation_edge_cases(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test edge cases and validation for write options.

        With very narrow line widths, attributes may be folded mid-name,
        but the content should still be valid and parseable.
        """
        # Test with minimal line width
        options = FlextLdifModels.WriteFormatOptions(
            line_width=10,
            fold_long_lines=True,
        )

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should still produce valid LDIF even with very narrow line width
        # Check that key attributes are present (may be folded)
        assert "dn:" in output
        # objectClass may be folded (e.g., "objectClas" on one line, "s:" on next)
        # So check for the pieces that make up the attribute
        assert "objectClas" in output and "s:" in output

        # Verify all lines respect the 10-byte width (RFC 2849 compliance)
        lines = output.split("\n")
        for line in lines:
            if line and not line.startswith("#"):  # Skip comments
                byte_len = len(line.encode("utf-8"))
                assert byte_len <= 10, (
                    f"Line exceeds 10-byte limit ({byte_len} > 10): {line[:30]}"
                )

    def test_empty_entries_list(self, writer_service: FlextLdifWriter) -> None:
        """Test writing empty entries list with options."""
        options = FlextLdifModels.WriteFormatOptions(
            include_version_header=True,
            include_timestamps=True,
        )

        result = writer_service.write(
            entries=[],
            target_server_type="rfc",
            output_target="string",
            format_options=options,
        )

        assert result.is_success
        output = result.unwrap()

        # Should still include headers if requested
        assert "version: 1" in output
        assert "# Generated on:" in output
        assert "# Total entries: 0" in output

    def test_invalid_server_type_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that options don't interfere with server type validation."""
        options = FlextLdifModels.WriteFormatOptions(include_version_header=True)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="nonexistent_server_type",
            output_target="string",
            format_options=options,
        )

        # Should fail due to invalid server type, regardless of options
        assert result.is_failure
        error_msg = result.error or ""
        assert "server type" in error_msg.lower()

    def test_default_options_behavior(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: FlextLdifModels.Entry,
    ) -> None:
        """Test that default options produce expected output."""
        # Use default options (None should create default WriteFormatOptions)
        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            output_target="string",
            format_options=None,
        )

        assert result.is_success
        output = result.unwrap()

        # With defaults:
        # - include_version_header=True
        # - respect_attribute_order=True
        # - base64_encode_binary=True
        # - fold_long_lines=True
        # etc.
        assert "version: 1" in output
        assert "dn:" in output
        assert "objectClass:" in output
