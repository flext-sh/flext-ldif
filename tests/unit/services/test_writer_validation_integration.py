from __future__ import annotations

from typing import Literal

import pytest

from flext_ldif import FlextLdifTypes, FlextLdifWriter
from flext_ldif.models import m
from flext_ldif.services.validation import FlextLdifValidation
from tests import c, m, s

# FlextLdifFixtures and TypedDicts are available from conftest.py (pytest auto-imports)


class TestsFlextLdifWriterValidationIntegration(s):
    """Test Writer integration with ValidationService for entry validation.

    Tests real validation of entries before writing, using actual ValidationService.
    Uses factories, helpers, and constants to reduce code duplication.
    """

    @pytest.fixture
    def writer(self) -> FlextLdifWriter:
        """Initialize real writer service."""
        return FlextLdifWriter()

    @pytest.fixture
    def validation_service(self) -> FlextLdifValidation:
        """Initialize real validation service."""
        return FlextLdifValidation()

    @pytest.fixture
    def valid_entry(self) -> m.Entry:
        """Create a valid LDAP entry with RFC-compliant attributes."""
        return self.create_entry(
            dn="cn=John Doe,ou=people,dc=example,dc=com",
            attributes={
                c.Names.CN: ["John Doe"],
                c.Names.SN: ["Doe"],
                c.Names.MAIL: ["john@example.com"],
                c.Names.OBJECTCLASS: [c.Names.PERSON, c.Names.INET_ORG_PERSON],
            },
        )

    class Constants:
        """Test constants organized as nested class."""

        VALID_ATTR_NAMES: tuple[str, ...] = (
            c.Names.CN,
            c.Names.MAIL,
            c.Names.OBJECTCLASS,
        )
        INVALID_ATTR_NAME: str = "invalid attr"
        DN_COMPONENTS: tuple[str, ...] = ("cn=", "ou=", "dc=")
        TEST_USER_PREFIX: str = "User"
        BATCH_COUNT: int = 3
        SERVER_TYPE: Literal["rfc"] = "rfc"

    class Helpers:
        """Helper methods organized as nested class."""

        @staticmethod
        def validate_all_attributes(
            validation_service: FlextLdifValidation,
            entry: m.Entry,
        ) -> bool:
            """Validate all attribute names in entry."""
            for attr_name in entry.attributes.attributes:
                result = validation_service.validate_attribute_name(attr_name)
                if not result.is_success:
                    return False
                if not result.unwrap():
                    return False
            return True

        @staticmethod
        def assert_dn_components(dn_value: str) -> None:
            """Assert DN contains required components."""
            assert dn_value, "DN should exist"
            for component in TestWriterValidationIntegration.Constants.DN_COMPONENTS:
                assert component in dn_value, f"DN should contain {component} component"

        @staticmethod
        def assert_ldif_output_contains(
            output: str,
            expected_dn: str,
            *expected_attrs: str,
        ) -> None:
            """Assert LDIF output contains expected DN and attributes."""
            assert expected_dn in output, f"Expected DN '{expected_dn}' in output"
            for attr in expected_attrs:
                assert (
                    attr in output or f"{attr}:" in output or f"{attr}::" in output
                ), f"Expected attribute '{attr}' in output"

    def test_valid_entry_validates_successfully(
        self,
        validation_service: FlextLdifValidation,
        valid_entry: m.Entry,
    ) -> None:
        """Test that valid entry attributes pass RFC validation."""
        is_valid = self.Helpers.validate_all_attributes(
            validation_service,
            valid_entry,
        )
        assert is_valid, "All attributes should be valid RFC attribute names"

    @pytest.mark.parametrize(
        ("attr_name", "expected_valid"),
        [
            ("invalid attr", False),
            (c.Names.CN, True),
            (c.Names.MAIL, True),
            (c.Names.OBJECTCLASS, True),
        ],
    )
    def test_attribute_name_validation(
        self,
        validation_service: FlextLdifValidation,
        attr_name: str,
        expected_valid: bool,
    ) -> None:
        """Test attribute name validation with parameterized test cases."""
        result = validation_service.validate_attribute_name(attr_name)
        self.assert_success(
            result,
            f"Validation should succeed for '{attr_name}'",
        )
        is_valid = result.unwrap()
        assert is_valid == expected_valid, (
            f"Expected '{attr_name}' to be {'valid' if expected_valid else 'invalid'}"
        )

    def test_validate_dn_components_with_valid_entry(
        self,
        valid_entry: m.Entry,
    ) -> None:
        """Test DN component validation on valid entry."""
        dn_value = valid_entry.dn.value if valid_entry.dn else ""
        self.Helpers.assert_dn_components(dn_value)

    def test_write_valid_entry_to_string(
        self,
        writer: FlextLdifWriter,
        valid_entry: m.Entry,
    ) -> None:
        """Test writing valid entry to LDIF string format."""
        result = writer.write(
            entries=[valid_entry],
            target_server_type=self.Constants.SERVER_TYPE,
            format_options=m.WriteFormatOptions(
                include_version_header=True,
                fold_long_lines=False,
            ),
        )

        unwrapped = self.assert_success(result, "Write should succeed")
        output = FlextLdifTypes.ResultExtractors.extract_content(unwrapped)
        self.Helpers.assert_ldif_output_contains(
            output,
            "dn: cn=John Doe,ou=people,dc=example,dc=com",
            "cn: John Doe",
            "objectClass: person",
        )

    def test_write_entry_with_base64_encoding(
        self,
        writer: FlextLdifWriter,
        valid_entry: m.Entry,
    ) -> None:
        """Test writing entry with base64 encoding for binary values."""
        result = writer.write(
            entries=[valid_entry],
            target_server_type=self.Constants.SERVER_TYPE,
            format_options=m.WriteFormatOptions(
                base64_encode_binary=True,
                fold_long_lines=False,
            ),
        )

        unwrapped = self.assert_success(result, "Write should succeed")
        output = FlextLdifTypes.ResultExtractors.extract_content(unwrapped)
        assert "dn: cn=John Doe,ou=people,dc=example,dc=com" in output

    def test_validate_multiple_entries_in_batch(
        self,
        writer: FlextLdifWriter,
        validation_service: FlextLdifValidation,
    ) -> None:
        """Test validation of multiple entries before writing."""
        entries = [
            self.create_entry(
                dn=f"cn={self.Constants.TEST_USER_PREFIX}{i},ou=people,dc=example,dc=com",
                attributes={
                    c.Names.CN: [f"{self.Constants.TEST_USER_PREFIX}{i}"],
                    c.Names.OBJECTCLASS: [c.Names.PERSON],
                    c.Names.MAIL: [f"user{i}@example.com"],
                },
            )
            for i in range(1, self.Constants.BATCH_COUNT + 1)
        ]

        # Validate all attributes using helper
        for entry in entries:
            is_valid = self.Helpers.validate_all_attributes(validation_service, entry)
            assert is_valid, (
                f"Entry {entry.dn.value if entry.dn else 'unknown'} should have valid attribute names"
            )

        # Write them
        result = writer.write(
            entries=entries,
            target_server_type=self.Constants.SERVER_TYPE,
            format_options=m.WriteFormatOptions(fold_long_lines=False),
        )

        unwrapped = self.assert_success(result, "Write should succeed")
        output = FlextLdifTypes.ResultExtractors.extract_content(unwrapped)
        for i in range(1, self.Constants.BATCH_COUNT + 1):
            assert f"{self.Constants.TEST_USER_PREFIX}{i}" in output
