"""Advanced tests for FLEXT-LDIF services - Real functionality testing.

Focus on covering untested service functionality with real tests,
following FLEXT patterns and achieving high coverage.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from flext_ldif import FlextLDIFModels
from flext_ldif.constants import FlextLDIFConstants
from flext_ldif.services import FlextLDIFServices


class TestFlextLDIFServicesAdvanced:
    """Advanced tests for FlextLDIFServices functionality."""

    def test_repository_service_initialization_and_execution(self) -> None:
        """Test RepositoryService initialization and execute method."""
        entries = [
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=user1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 1"]},
                }
            ),
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=user2,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["User 2"]},
                }
            ),
        ]

        # Test with real entries and config
        service = FlextLDIFServices.RepositoryService(entries=entries, config={})

        # Test properties
        assert len(service.entries) == 2
        assert service.config is not None  # Config object created

        # Test execute method (FlextDomainService requirement)
        result = service.execute()
        assert result.is_success
        assert result.value["total_entries"] == 2

    def test_repository_service_find_entry_by_dn(self) -> None:
        """Test find_entry_by_dn method with real entries."""
        entries = [
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=john,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson"],
                        "cn": ["John Doe"],
                        "mail": ["john@example.com"],
                    },
                }
            ),
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=jane,ou=people,dc=example,dc=com",
                    "attributes": {
                        "objectClass": ["inetOrgPerson"],
                        "cn": ["Jane Smith"],
                        "mail": ["jane@example.com"],
                    },
                }
            ),
        ]

        service = FlextLDIFServices.RepositoryService(entries=entries, config={})

        # Test finding existing entry
        result = service.find_entry_by_dn(
            entries, "uid=john,ou=people,dc=example,dc=com"
        )
        assert result.is_success
        assert result.value is not None
        assert result.value.dn.value == "uid=john,ou=people,dc=example,dc=com"

        # Test finding non-existent entry
        result = service.find_entry_by_dn(
            entries, "uid=notfound,ou=people,dc=example,dc=com"
        )
        assert result.is_success
        assert result.value is None

    def test_writer_service_format_entry_for_display(self) -> None:
        """Test format_entry_for_display method with real entry."""
        entry = FlextLDIFModels.Entry.model_validate(
            {
                "dn": "cn=John Doe,ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person"],
                    "cn": ["John Doe"],
                    "sn": ["Doe"],
                    "givenName": ["John"],
                    "mail": ["john.doe@example.com"],
                },
            }
        )

        service = FlextLDIFServices.WriterService()
        result = service.format_entry_for_display(entry)

        assert result.is_success
        formatted = result.value
        assert "DN: cn=John Doe,ou=people,dc=example,dc=com" in formatted
        assert "cn: John Doe" in formatted
        assert "mail: john.doe@example.com" in formatted
        assert "objectClass: inetOrgPerson" in formatted
        assert "objectClass: person" in formatted

    def test_writer_service_write_entries_to_file_real_file(self) -> None:
        """Test write_entries_to_file with real file operations."""
        entries = [
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=test1,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Test User 1"]},
                }
            ),
            FlextLDIFModels.Entry.model_validate(
                {
                    "dn": "uid=test2,ou=people,dc=example,dc=com",
                    "attributes": {"objectClass": ["person"], "cn": ["Test User 2"]},
                }
            ),
        ]

        service = FlextLDIFServices.WriterService()

        with TemporaryDirectory() as tmp_dir:
            file_path = f"{tmp_dir}/test_output.ldif"

            # Test successful file write
            result = service.write_entries_to_file(entries, file_path)
            assert result.is_success
            # Writer service returns success message, not True
            assert result.value is True or isinstance(result.value, str)

            # Verify file was created and contains expected content
            with Path(file_path).open(encoding="utf-8") as f:
                content = f.read()
                assert "uid=test1,ou=people,dc=example,dc=com" in content
                assert "uid=test2,ou=people,dc=example,dc=com" in content
                assert "Test User 1" in content
                assert "Test User 2" in content

    def test_writer_service_write_entry_single(self) -> None:
        """Test write_entry method for single entry."""
        entry = FlextLDIFModels.Entry.model_validate(
            {
                "dn": "cn=Single Entry,ou=test,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["organizationalUnit"],
                    "cn": ["Single Entry"],
                    "description": ["Test single entry"],
                },
            }
        )

        service = FlextLDIFServices.WriterService()
        result = service.write_entry(entry)

        assert result.is_success
        ldif_content = result.value
        assert "cn=Single Entry,ou=test,dc=example,dc=com" in ldif_content
        assert "objectClass: organizationalUnit" in ldif_content
        assert "description: Test single entry" in ldif_content

    def test_writer_service_write_empty_entries(self) -> None:
        """Test write_entries_to_string with empty list."""
        service = FlextLDIFServices.WriterService()
        result = service.write_entries_to_string([])

        assert result.is_success
        assert result.value == ""

    def test_field_defaults_constants(self) -> None:
        """Test field defaults constants are properly defined in FlextLDIFConstants."""
        constants = FlextLDIFConstants

        # Test all required constants exist
        assert hasattr(constants, "MIN_DN_COMPONENTS")
        assert hasattr(constants, "LDAP_PERSON_CLASSES")
        assert hasattr(constants, "LDAP_GROUP_CLASSES")

        # Test that constants have reasonable values
        assert constants.MIN_DN_COMPONENTS > 0
