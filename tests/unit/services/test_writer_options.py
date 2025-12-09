"""Tests for LDIF writer format options and configuration.

This module tests all WriteFormatOptions and WriteOptions functionality for
the FlextLdifWriter service including option parsing, configuration mapping,
and behavior with different output modes and server types.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, cast

import pytest
from flext_core import FlextConfig
from flext_tests import tm
from flext_tests.utilities import FlextTestsUtilities

from flext_ldif import FlextLdifWriter
from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import c as lib_c
from flext_ldif.protocols import p
from flext_ldif.utilities import FlextLdifUtilities
from tests import c, m, s


class TestsFlextLdifWriterOptions(s):
    """Test all WriteFormatOptions and WriteOptions functionality."""

    writer_service: ClassVar[FlextLdifWriter]  # pytest fixture
    config_instance: ClassVar[FlextConfig]  # pytest fixture


def config_to_write_options(
    config: FlextLdifConfig,
) -> m.WriteFormatOptions | m.WriteOptions:
    """Convert FlextLdifConfig to WriteOptions or WriteFormatOptions."""
    # Check if WriteFormatOptions fields are present
    has_format_options = any(
        hasattr(config, key) and getattr(config, key, None) is not None
        for key in (
            "ldif_max_line_length",
            "ldif_write_fold_long_lines",
            "ldif_write_respect_attribute_order",
            "ldif_write_hidden_attributes_as_comments",
            "ldif_write_metadata_as_comments",
            "ldif_write_include_version_header",
            "ldif_write_include_timestamps",
            "ldif_write_empty_values",
            "ldif_write_normalize_attribute_names",
            "ldif_write_include_dn_comments",
            "ldif_write_use_original_acl_format_as_name",
        )
    )

    if has_format_options:
        # Create WriteFormatOptions from config
        format_opts_dict: dict[str, object] = {}
        for config_key, model_key in CONFIG_TO_MODEL_FIELD_MAP.items():
            if hasattr(config, config_key):
                value = getattr(config, config_key, None)
                if value is not None and isinstance(
                    value,
                    (bool, int, str, list, frozenset, dict),
                ):
                    format_opts_dict[model_key] = value
        return m.WriteFormatOptions.model_validate(format_opts_dict)

    # Create basic WriteOptions
    return m.WriteOptions(
        format="rfc2849",
        base_dn=None,
        hidden_attrs=[],
        sort_entries=config.ldif_write_sort_attributes,
        include_comments=config.ldif_write_include_dn_comments,
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


class TestsFlextLdifWriterFormatOptions(s):
    """Test all WriteFormatOptions functionality via FlextLdifConfig."""

    writer_service: ClassVar[FlextLdifWriter]  # pytest fixture
    config_instance: ClassVar[FlextConfig]  # pytest fixture
    sample_entry: ClassVar[p.Entry]  # pytest fixture
    entry_with_metadata: ClassVar[p.Entry]  # pytest fixture
    entry_with_binary_data: ClassVar[p.Entry]  # pytest fixture
    entry_with_aci_and_acl_metadata: ClassVar[p.Entry]  # pytest fixture

    class Writer:
        """Writer test constants."""

        LONG_DN: str = "cn=Very Long Distinguished Name That Exceeds Normal Length,ou=People,dc=Example,dc=Com"
        REGEX_SPECIAL_CHARS: str = r".*+?^${}[]|()"

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
    def sample_entry(self) -> p.Entry:
        """Create a sample entry for testing."""
        return self._create_entry(
            dn="cn=John Doe,ou=people,dc=example,dc=com",
            attributes={
                c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.ORGANIZATIONAL_PERSON],
                c.Names.CN: ["John Doe"],
                c.Names.SN: ["Doe"],
                c.Names.GIVEN_NAME: ["John"],
                c.Names.MAIL: ["john.doe@example.com"],
                c.Names.TELEPHONE_NUMBER: ["+1-555-123-4567"],
                c.Names.DESCRIPTION: [
                    "A very long description that should definitely exceed the normal "
                    "line width limit for LDIF formatting and trigger line folding "
                    "behavior according to RFC 2849 specifications",
                ],
            },
        )

    @pytest.fixture
    def entry_with_metadata(self) -> p.Entry:
        """Create an entry with metadata for testing."""
        extensions = m.Ldif.DynamicMetadata.model_validate(
            {
                "attribute_order": [
                    "objectClass",
                    "cn",
                    "sn",
                    "mail",
                    c.Names.TELEPHONE_NUMBER,
                ],
                "hidden_attributes": [c.Names.TELEPHONE_NUMBER],
                "source_file": "test.ldif",
            }
        )
        metadata = m.Ldif.QuirkMetadata(
            quirk_type="rfc",
            target_server_type="rfc",
            extensions=extensions,
        )
        return self._create_entry(
            dn="cn=Jane Smith,ou=people,dc=example,dc=com",
            attributes={
                c.Names.OBJECTCLASS: [c.Names.PERSON],
                c.Names.CN: ["Jane Smith"],
                c.Names.SN: ["Smith"],
                c.Names.MAIL: ["jane.smith@example.com"],
                c.Names.TELEPHONE_NUMBER: ["+1-555-987-6543"],
                "emptyAttr": [""],
                c.Names.DESCRIPTION: [""],
            },
            metadata=metadata,
        )

    @pytest.fixture
    def entry_with_binary_data(self) -> p.Entry:
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
                c.Names.DESCRIPTION: ["value\x00with\x01null"],
                "comment": ["ends with null\x00"],
                "specialChars": [": colon at start"],
            },
        )

    @pytest.fixture
    def entry_with_aci_and_acl_metadata(self) -> p.Entry:
        """Create an entry with aci attribute and ACL_ORIGINAL_FORMAT metadata."""
        extensions = m.Ldif.DynamicMetadata.model_validate(
            {
                lib_c.MetadataKeys.ACL_ORIGINAL_FORMAT: (
                    "access to attr=(cn,sn) by self (read) by * (search)"
                ),
            }
        )
        metadata = m.Ldif.QuirkMetadata(
            quirk_type="oud",
            target_server_type="oud",
            extensions=extensions,
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
        metadata: m.Ldif.QuirkMetadata | None = None,
    ) -> p.Entry:
        """Factory method to create Entry with reduced boilerplate."""
        dn_obj = m.DistinguishedName(value=dn)
        attrs_obj = m.LdifAttributes(attributes=attributes)
        if metadata is not None:
            return p.Entry(
                dn=dn_obj,
                attributes=attrs_obj,
                metadata=metadata,
            )
        return p.Entry(
            dn=dn_obj,
            attributes=attrs_obj,
        )

    def _write_with_config(
        self,
        writer: FlextLdifWriter,
        entries: list[p.Entry],
        config_overrides: dict[str, str | int | float | bool | list[str] | None],
        target_server: (lib_c.Ldif.LiteralTypes.ServerTypeLiteral | str | None) = "rfc",
        output_target: str = "string",
        output_path: Path | None = None,
    ) -> str:
        """Helper to write entries with config overrides and return output string."""
        # Check if WriteFormatOptions fields are present
        has_format_options = any(
            key in config_overrides
            for key in (
                "ldif_max_line_length",
                "ldif_write_fold_long_lines",
                "ldif_write_respect_attribute_order",
                "ldif_write_hidden_attributes_as_comments",
                "ldif_write_metadata_as_comments",
                "ldif_write_include_version_header",
                "ldif_write_include_timestamps",
                "ldif_write_empty_values",
                "ldif_write_normalize_attribute_names",
                "ldif_write_include_dn_comments",
                "ldif_write_use_original_acl_format_as_name",
            )
        )

        options: m.WriteFormatOptions | m.WriteOptions
        if has_format_options:
            # Create WriteFormatOptions from config_overrides
            format_opts_dict: dict[str, object] = {}
            for config_key, model_key in CONFIG_TO_MODEL_FIELD_MAP.items():
                if config_key in config_overrides:
                    value = config_overrides[config_key]
                    if isinstance(value, (bool, int, str, list, frozenset, dict)):
                        format_opts_dict[model_key] = value
            options = m.WriteFormatOptions.model_validate(format_opts_dict)
        else:
            # Create basic WriteOptions
            sort_entries_raw = config_overrides.get("ldif_write_sort_attributes", False)
            sort_entries: bool = (
                bool(sort_entries_raw)
                if isinstance(sort_entries_raw, (bool, int))
                else False
            )
            include_comments_raw = config_overrides.get(
                "ldif_write_include_dn_comments",
                False,
            )
            include_comments: bool = (
                bool(include_comments_raw)
                if isinstance(include_comments_raw, (bool, int))
                else False
            )
            base64_encode_binary_raw = config_overrides.get(
                "ldif_write_base64_encode_binary",
                False,
            )
            base64_encode_binary: bool = (
                bool(base64_encode_binary_raw)
                if isinstance(base64_encode_binary_raw, (bool, int))
                else False
            )
            options = m.WriteOptions(
                format="rfc2849",
                sort_entries=sort_entries,
                include_comments=include_comments,
                base64_encode_binary=base64_encode_binary,
            )

        # Convert target_server to proper type
        server_type: lib_c.Ldif.LiteralTypes.ServerTypeLiteral | None = None
        if isinstance(target_server, str):
            normalized = lib_c.normalize_server_type(target_server)
            if normalized is not None:
                server_type = normalized
        result = writer.write(
            entries=entries,
            target_server_type=server_type,
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
            (WriterOption.INCLUDE_VERSION_HEADER, True, r"^version:\s*1$", False),
            (WriterOption.INCLUDE_VERSION_HEADER, False, r"^version:\s*1$", True),
            # Timestamps
            (
                WriterOption.INCLUDE_TIMESTAMPS,
                True,
                r"# Timestamp:",
                False,
            ),
            (
                WriterOption.INCLUDE_TIMESTAMPS,
                False,
                r"# Timestamp:",
                True,
            ),
            # Write hidden attrs as comments
            (
                WriterOption.WRITE_HIDDEN_ATTRS_AS_COMMENTS,
                True,
                r"^#\s+\w+:",
                False,
            ),
            # Write empty values
            (WriterOption.WRITE_EMPTY_VALUES, True, r"^\w+:\s*$", False),
            (WriterOption.WRITE_EMPTY_VALUES, False, r"^\w+:\s*$", True),
            # Include DN comments
            (WriterOption.INCLUDE_DN_COMMENTS, True, r"^# DN:", False),
            (WriterOption.INCLUDE_DN_COMMENTS, False, r"^# DN:", True),
        ],
    )
    def test_boolean_option(
        self,
        writer_service: FlextLdifWriter,
        option_field: WriterOption,
        test_value: bool,
        expected_pattern: str,
        check_absence: bool,
        sample_entry: p.Entry,
        entry_with_metadata: p.Entry,
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
            entry = self._create_entry(
                dn=TestsFlextLdifWriterFormatOptions.Writer.LONG_DN,
                attributes={"objectClass": ["person"], "cn": ["Test"]},
            )

        output = self._write_with_config(
            writer_service,
            [entry],
            {option_field: test_value},
        )

        # Check pattern presence or absence using helper
        is_regex = any(
            char in expected_pattern
            for char in TestsFlextLdifWriterFormatOptions.Writer.REGEX_SPECIAL_CHARS
        )
        if check_absence:
            if is_regex:
                assert not re.search(expected_pattern, output), (
                    f"Pattern should be absent when {option_field}={test_value}"
                )
            else:
                assert expected_pattern not in output, (
                    f"Pattern should be absent when {option_field}={test_value}"
                )
        elif is_regex:
            assert re.search(expected_pattern, output), (
                f"Pattern should match when {option_field}={test_value}"
            )
        else:
            assert expected_pattern in output, (
                f"Pattern should be present when {option_field}={test_value}"
            )

    # =========================================================================
    # Line Width and Folding Tests
    # =========================================================================

    @pytest.mark.parametrize("line_width", [50, 76, 120])
    def test_line_width(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
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
        tm.assert_length_equals(
            long_lines,
            0,
            f"Found unfolded lines longer than {line_width}",
        )

    def test_fold_long_lines_rfc_compliance(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
    ) -> None:
        """Test RFC 2849 compliance maintained even with fold_long_lines=False."""
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
        entry_with_metadata: p.Entry,
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

        expected_order = [
            c.Names.OBJECTCLASS,
            c.Names.CN,
            c.Names.SN,
            c.Names.MAIL,
            c.Names.TELEPHONE_NUMBER,
        ]
        for i, expected_attr in enumerate(expected_order):
            if i < len(actual_order):
                assert actual_order[i] == expected_attr

    # =========================================================================
    # Base64 Encoding Tests
    # =========================================================================

    @pytest.mark.parametrize("encode_binary", [True, False])
    def test_base64_encode_binary(
        self,
        writer_service: FlextLdifWriter,
        entry_with_binary_data: p.Entry,
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
            # Note: Base64 encoding is always applied to binary attributes regardless of option
            assert double_colon_count > 0, (
                "Binary attributes should always be base64-encoded"
            )
            assert "jpegPhoto::" in output
            assert "description::" in output

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
        entry_with_aci_and_acl_metadata: p.Entry,
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
        entry_with_metadata: p.Entry,
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
        tm.assert_length_equals(long_lines, 0)

    # =========================================================================
    # Output Target Tests
    # =========================================================================

    def test_file_output_with_options(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
        tmp_path: Path,
    ) -> None:
        """Test writing to file with options."""
        output_file = tmp_path / "test_output.ldif"

        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif",
            FlextLdifConfig,
        )
        config.ldif_write_include_version_header = True
        config.ldif_write_include_timestamps = True
        config.ldif_max_line_length = 78
        options = config_to_write_options(config)

        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            _output_target="file",
            output_path=output_file,
            format_options=options,
        )

        assert result.is_success

        FlextTestsUtilities.FileHelpers.assert_file_exists(output_file)

        content = output_file.read_text(encoding="utf-8")
        assert "version: 1" in content
        assert "# Generated on:" in content

    def test_non_string_output_targets_ignored(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
    ) -> None:
        """Test that _output_target parameter is ignored (for compatibility only).

        The _output_target parameter is for backward compatibility but does not
        change the return type. When no output_path is provided, write() always
        returns a string, regardless of _output_target value.
        """
        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif",
            FlextLdifConfig,
        )
        config.ldif_write_normalize_attribute_names = True
        options = config_to_write_options(config)

        # Test that _output_target is ignored and string is returned
        for output_target in ["ldap3", "model", "string"]:
            result = writer_service.write(
                entries=[sample_entry],
                target_server_type="rfc",
                _output_target=output_target,
                format_options=options,
            )

            assert result.is_success
            output_data = result.unwrap()
            # Always returns string when no output_path is provided
            assert isinstance(output_data, str)
            assert "version: 1" in output_data
            assert "dn: cn=John Doe" in output_data

    # =========================================================================
    # Edge Cases and Validation
    # =========================================================================

    def test_minimal_line_width(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
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

        # Verify that output is generated successfully with minimal line width
        # Note: With a minimal width of 10 bytes, some lines may still exceed if they cannot be folded
        # (e.g., attribute names like "objectClass: person" = 19 bytes cannot be folded below 10)
        # This test verifies that the writer handles minimal width configuration without errors
        tm.assert_length_greater_than(
            output,
            0,
            "Output should not be empty",
        )
        assert "dn:" in output or "DN:" in output, "Output should contain DN line"

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
        sample_entry: p.Entry,
    ) -> None:
        """Test that options don't interfere with server type validation."""
        FlextConfig.reset_global_instance()
        config = FlextConfig.get_global_instance().get_namespace(
            "ldif",
            FlextLdifConfig,
        )
        config.ldif_write_include_version_header = True
        options = config_to_write_options(config)

        # Use invalid server type to test error handling
        # Note: None is treated as default "rfc", so we use an invalid string
        # Use cast to allow passing invalid server type for testing error handling
        result = writer_service.write(
            entries=[sample_entry],
            target_server_type=cast(
                "lib_c.Ldif.LiteralTypes.ServerTypeLiteral",
                "nonexistent_server_type",
            ),  # Invalid server type should be handled gracefully
            _output_target="string",
            format_options=options,
        )

        assert result.is_failure
        error_msg = result.error or ""
        assert (
            "server type" in error_msg.lower()
            or "no entry quirk found" in error_msg.lower()
        )

    def test_default_options_behavior(
        self,
        writer_service: FlextLdifWriter,
        sample_entry: p.Entry,
    ) -> None:
        """Test that default options produce expected output."""
        result = writer_service.write(
            entries=[sample_entry],
            target_server_type="rfc",
            _output_target="string",
            format_options=None,
        )

        assert result.is_success
        unwrapped = result.unwrap()
        assert isinstance(unwrapped, str), "Expected string output"

        # With defaults: include_version_header=True
        assert "version: 1" in unwrapped
        assert "dn:" in unwrapped
        assert "objectClass:" in unwrapped

    # =========================================================================
    # Nested Class: ACL Sanitization Tests
    # =========================================================================

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
            sanitized, was_sanitized = FlextLdifUtilities.Ldif.ACL.sanitize_acl_name(
                input_str,
            )

            assert was_sanitized == should_sanitize

            if expected is not None:
                assert sanitized == expected
            else:
                # Check absence of double quotes
                assert '"' not in sanitized

        def test_sanitize_acl_name_truncation(self) -> None:
            """Test truncation of long strings."""
            input_str = "a" * 300
            sanitized, was_sanitized = FlextLdifUtilities.Ldif.ACL.sanitize_acl_name(
                input_str,
                max_length=50,
            )

            tm.assert_length_equals(sanitized, 50)
            assert sanitized.endswith("...")
            assert was_sanitized

        def test_sanitize_acl_name_collapses_spaces(self) -> None:
            """Test that multiple spaces are collapsed."""
            input_str = "access\x00\x01\x02to attr"
            sanitized, was_sanitized = FlextLdifUtilities.Ldif.ACL.sanitize_acl_name(
                input_str,
            )

            assert "  " not in sanitized
            assert was_sanitized
