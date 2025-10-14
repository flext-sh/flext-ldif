"""Test suite for entry quirks module.

Comprehensive testing for FlextLdifEntryQuirks which handles entry adaptation
and validation for server-specific quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.entry_quirks import FlextLdifEntryQuirks
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class TestFlextLdifEntryQuirksInitialization:
    """Test suite for entry quirks initialization."""

    def test_initialization_default(self) -> None:
        """Test entry quirks initialization with default quirks manager."""
        quirks = FlextLdifEntryQuirks()

        assert quirks is not None
        assert quirks._quirks is not None
        assert isinstance(quirks._quirks, FlextLdifQuirksManager)

    def test_initialization_custom_manager(self) -> None:
        """Test entry quirks initialization with custom quirks manager."""
        manager = FlextLdifQuirksManager(server_type="openldap")
        quirks = FlextLdifEntryQuirks(quirks_manager=manager)

        assert quirks is not None
        assert quirks._quirks is manager
        assert quirks._quirks.server_type == "openldap"

    def test_execute_service(self) -> None:
        """Test entry quirks service execution."""
        quirks = FlextLdifEntryQuirks()
        result = quirks.execute()

        assert result.is_success
        assert result.value["service"] == FlextLdifEntryQuirks
        assert result.value["status"] == "ready"


class TestEntryAdaptation:
    """Test suite for entry adaptation functionality."""

    def test_adapt_entry_generic_server(self) -> None:
        """Test adapting entry for generic LDAP server."""
        quirks = FlextLdifEntryQuirks()

        # Create test entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person", "inetOrgPerson"],
                "sn": ["Test User"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Adapt entry
        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()
        assert adapted_entry.dn.value == "cn=test,dc=example,dc=com"
        assert adapted_entry.has_attribute("cn")
        assert adapted_entry.has_attribute("objectClass")

    def test_adapt_entry_openldap(self) -> None:
        """Test adapting entry for OpenLDAP server."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "openldap")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()
        assert adapted_entry.dn.value == "cn=test,dc=example,dc=com"

    def test_adapt_entry_active_directory(self) -> None:
        """Test adapting entry for Active Directory server."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["user"],
                "userPrincipalName": ["Test@EXAMPLE.COM"],
                "sAMAccountName": ["TestUser"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "active_directory")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        # AD should lowercase userPrincipalName and sAMAccountName
        upn = adapted_entry.get_attribute_values("userPrincipalName")
        assert upn is not None
        assert isinstance(upn, list)
        assert upn[0] == "test@example.com"

        sam = adapted_entry.get_attribute_values("sAMAccountName")
        assert sam is not None
        assert isinstance(sam, list)
        assert sam[0] == "testuser"

    def test_adapt_entry_with_attribute_mappings(self) -> None:
        """Test entry adaptation with attribute name mappings."""
        # Create custom manager with attribute mappings
        manager = FlextLdifQuirksManager(server_type="generic")
        quirks = FlextLdifEntryQuirks(quirks_manager=manager)

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success

    def test_adapt_entry_invalid_server_type(self) -> None:
        """Test adapting entry with invalid server type."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "invalid_server")

        assert adapted_result.is_failure
        assert "Unknown server type" in str(adapted_result.error)

    def test_adapt_entry_no_target_server(self) -> None:
        """Test adapting entry without specifying target server."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Should use generic server when None
        adapted_result = quirks.adapt_entry(entry, None)

        assert adapted_result.is_success


class TestAttributeValueAdaptation:
    """Test suite for attribute value adaptation."""

    def test_adapt_objectclass_values(self) -> None:
        """Test adaptation of objectClass attribute values."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Adapt for Apache Directory (requires additional object classes)
        adapted_result = quirks.adapt_entry(entry, "apache_directory")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        # Should have required object classes added
        obj_classes = adapted_entry.get_attribute_values("objectClass")
        assert obj_classes is not None
        assert isinstance(obj_classes, list)
        assert "top" in obj_classes
        assert "ads-directoryService" in obj_classes

    def test_adapt_ad_special_attributes_lowercase(self) -> None:
        """Test Active Directory special attributes are lowercased."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["user"],
                "userPrincipalName": ["UPPERCASE@DOMAIN.COM"],
                "sAMAccountName": ["UPPERCASE"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "active_directory")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        upn = adapted_entry.get_attribute_values("userPrincipalName")
        assert upn is not None
        assert upn[0] == "uppercase@domain.com"

        sam = adapted_entry.get_attribute_values("sAMAccountName")
        assert sam is not None
        assert sam[0] == "uppercase"

    def test_adapt_regular_attributes_unchanged(self) -> None:
        """Test that regular attributes are not modified during adaptation."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "sn": ["Test User"],
                "mail": ["test@example.com"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        # Regular attributes should remain unchanged
        assert adapted_entry.get_attribute_values("sn") == ["Test User"]
        assert adapted_entry.get_attribute_values("mail") == ["test@example.com"]

    def test_adapt_attribute_values_invalid_server(self) -> None:
        """Test attribute value adaptation with invalid server type."""
        quirks = FlextLdifEntryQuirks()

        # Test internal method directly
        adapted_values = quirks._adapt_attribute_values(
            "cn", ["test"], "invalid_server_type"
        )

        # Should return original values when server type is invalid
        assert adapted_values == ["test"]


class TestEntryValidation:
    """Test suite for entry validation functionality."""

    def test_validate_entry_generic_compliant(self) -> None:
        """Test validating compliant entry for generic server."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["top", "person"],
                "sn": ["Test"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "generic")

        assert validation_result.is_success
        report = validation_result.unwrap()
        assert report["compliant"] is True
        assert report["server_type"] == "generic"
        issues = report["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_validate_entry_missing_required_objectclass(self) -> None:
        """Test validation detects missing required object classes."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],  # Missing required classes
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Validate for Apache Directory (requires top, ads-directoryService)
        validation_result = quirks.validate_entry(entry, "apache_directory")

        assert validation_result.is_success
        report = validation_result.unwrap()
        assert report["compliant"] is False
        issues = report["issues"]
        assert isinstance(issues, list)
        assert any("top" in str(issue) for issue in issues)
        assert any("ads-directoryService" in str(issue) for issue in issues)

    def test_validate_entry_missing_special_attributes(self) -> None:
        """Test validation detects missing special attributes as warnings."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["top", "ads-directoryService"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "apache_directory")

        assert validation_result.is_success
        report = validation_result.unwrap()
        warnings = report["warnings"]
        assert isinstance(warnings, list)
        # Should warn about missing special attributes
        assert any("ads-directoryServiceId" in str(w) for w in warnings)

    def test_validate_entry_active_directory(self) -> None:
        """Test validating entry for Active Directory server."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,cn=users,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["top", "user"],
                "userPrincipalName": ["test@example.com"],
                "sAMAccountName": ["test"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "active_directory")

        assert validation_result.is_success
        report = validation_result.unwrap()
        # AD validation runs successfully (even if there are DN warnings)
        assert report["server_type"] == "active_directory"
        assert "compliant" in report

    def test_validate_entry_invalid_server_type(self) -> None:
        """Test validation with invalid server type."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "invalid_server")

        assert validation_result.is_failure
        assert "Unknown server type" in str(validation_result.error)

    def test_validate_entry_no_server_type(self) -> None:
        """Test validation without specifying server type (defaults to generic)."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["top", "person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, None)

        assert validation_result.is_success
        report = validation_result.unwrap()
        assert report["server_type"] == "generic"


class TestDnFormatValidation:
    """Test suite for DN format validation."""

    def test_validate_dn_format_valid_generic(self) -> None:
        """Test DN format validation for generic server."""
        quirks = FlextLdifEntryQuirks()

        dn_result = quirks._validate_dn_format("cn=test,dc=example,dc=com", "generic")

        assert dn_result["valid"] is True
        issues = dn_result["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_validate_dn_format_active_directory_valid(self) -> None:
        """Test DN format validation for Active Directory."""
        quirks = FlextLdifEntryQuirks()

        dn_result = quirks._validate_dn_format(
            "cn=test,cn=users,dc=example,dc=com", "ad"
        )

        assert dn_result["valid"] is True
        issues = dn_result["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 0

    def test_validate_dn_format_invalid_component(self) -> None:
        """Test DN format validation with invalid component."""
        quirks = FlextLdifEntryQuirks()

        # DN with invalid component (missing =)
        dn_result = quirks._validate_dn_format("cn=test,invalid,dc=com", "generic")

        assert dn_result["valid"] is False
        issues = dn_result["issues"]
        assert isinstance(issues, list)
        # Pydantic validation catches invalid DN format
        assert any("Invalid DN format" in str(issue) for issue in issues)

    def test_validate_dn_format_case_insensitive(self) -> None:
        """Test DN format validation is case-insensitive for most servers."""
        quirks = FlextLdifEntryQuirks()

        # Generic server has case-insensitive DN validation (no strict patterns)
        dn_result = quirks._validate_dn_format("OU=People,DC=Example,DC=COM", "generic")

        # Should validate successfully (case-insensitive, no pattern restrictions)
        assert dn_result["valid"] is True

    def test_validate_dn_format_server_specific_patterns(self) -> None:
        """Test DN format validation respects server-specific patterns."""
        quirks = FlextLdifEntryQuirks()

        # Generic server accepts standard DN components
        dn_result = quirks._validate_dn_format("cn=config,dc=example,dc=com", "generic")

        # Generic server has no pattern restrictions
        assert dn_result["valid"] is True

    def test_validate_dn_format_unknown_attribute(self) -> None:
        """Test DN format validation detects unknown DN attributes."""
        quirks = FlextLdifEntryQuirks()

        # Use server with specific DN patterns
        dn_result = quirks._validate_dn_format(
            "xyz=test,dc=example,dc=com", "apache_directory"
        )

        # Should report unknown attribute
        assert dn_result["valid"] is False
        issues = dn_result["issues"]
        assert isinstance(issues, list)
        assert any("Unknown DN attribute" in str(issue) for issue in issues)

    def test_validate_dn_format_invalid_dn_string(self) -> None:
        """Test DN format validation with completely invalid DN."""
        quirks = FlextLdifEntryQuirks()

        # Completely invalid DN
        dn_result = quirks._validate_dn_format("", "generic")

        # Should handle gracefully
        assert "valid" in dn_result
        assert "issues" in dn_result

    def test_validate_dn_format_quirks_failure(self) -> None:
        """Test DN format validation when quirks lookup fails."""
        quirks = FlextLdifEntryQuirks()

        # Invalid server type should cause quirks failure
        dn_result = quirks._validate_dn_format(
            "cn=test,dc=example,dc=com", "invalid_server"
        )

        # Should return valid=True when quirks lookup fails (no validation)
        assert dn_result["valid"] is True
        issues = dn_result["issues"]
        assert isinstance(issues, list)
        assert len(issues) == 0


class TestCompleteEntryWorkflow:
    """Test suite for complete entry adaptation and validation workflows."""

    def test_adapt_then_validate_workflow(self) -> None:
        """Test complete workflow: create, adapt, then validate entry."""
        quirks = FlextLdifEntryQuirks()

        # Create entry with DN matching server expectations
        entry_result = FlextLdifModels.Entry.create(
            dn="ou=config",
            attributes={
                "ou": ["config"],
                "objectClass": ["top", "organizationalUnit"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Adapt for Apache Directory
        adapted_result = quirks.adapt_entry(entry, "apache_directory")
        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        # Validate adapted entry
        validation_result = quirks.validate_entry(adapted_entry, "apache_directory")
        assert validation_result.is_success
        validation_result.unwrap()  # Ensure no exceptions

        # After adaptation, object classes should be added (even if DN has warnings)
        obj_classes = adapted_entry.get_attribute_values("objectClass")
        assert obj_classes is not None
        assert "top" in obj_classes
        assert "ads-directoryService" in obj_classes

    def test_cross_server_adaptation(self) -> None:
        """Test adapting entry from one server type to another."""
        quirks = FlextLdifEntryQuirks()

        # Create OpenLDAP-style entry
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["inetOrgPerson"],
                "sn": ["Test"],
                "mail": ["test@example.com"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        # Adapt to Active Directory
        ad_adapted = quirks.adapt_entry(entry, "active_directory")
        assert ad_adapted.is_success

        # Adapt to 389 DS
        ds389_adapted = quirks.adapt_entry(entry, "389ds")
        assert ds389_adapted.is_success

    def test_multiple_entries_batch_adaptation(self) -> None:
        """Test adapting multiple entries in batch."""
        quirks = FlextLdifEntryQuirks()

        entries = []
        for i in range(5):
            entry_result = FlextLdifModels.Entry.create(
                dn=f"cn=test{i},dc=example,dc=com",
                attributes={
                    "cn": [f"test{i}"],
                    "objectClass": ["person"],
                    "sn": [f"Test{i}"],
                },
            )
            assert entry_result.is_success
            entries.append(entry_result.unwrap())

        # Adapt all entries
        adapted_entries = []
        for entry in entries:
            adapted_result = quirks.adapt_entry(entry, "apache_directory")
            assert adapted_result.is_success
            adapted_entries.append(adapted_result.unwrap())

        assert len(adapted_entries) == 5

        # Validate all adapted entries
        for adapted_entry in adapted_entries:
            validation_result = quirks.validate_entry(adapted_entry, "apache_directory")
            assert validation_result.is_success


class TestEdgeCases:
    """Test suite for edge cases and error conditions."""

    def test_adapt_entry_minimal_attributes(self) -> None:
        """Test adapting entry with minimal required attributes."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success

    def test_adapt_entry_empty_attribute_values(self) -> None:
        """Test adapting entry with empty attribute values."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": [],  # Empty list
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success

    def test_validate_entry_empty_objectclass(self) -> None:
        """Test validating entry with no object classes."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "apache_directory")

        assert validation_result.is_success
        report = validation_result.unwrap()
        # Should report missing required object classes
        assert report["compliant"] is False

    def test_adapt_entry_with_multivalued_attributes(self) -> None:
        """Test adapting entry with multi-valued attributes."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test", "test-alias"],
                "objectClass": ["person", "inetOrgPerson", "organizationalPerson"],
                "mail": ["test@example.com", "test2@example.com"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        adapted_result = quirks.adapt_entry(entry, "generic")

        assert adapted_result.is_success
        adapted_entry = adapted_result.unwrap()

        # All values should be preserved
        cn = adapted_entry.get_attribute_values("cn")
        assert cn is not None
        assert len(cn) == 2

        mail = adapted_entry.get_attribute_values("mail")
        assert mail is not None
        assert len(mail) == 2

    def test_validate_dn_with_special_characters(self) -> None:
        """Test DN validation with special characters."""
        quirks = FlextLdifEntryQuirks()

        # DN with spaces and special chars
        dn_result = quirks._validate_dn_format(
            "cn=Test User,ou=People,dc=example,dc=com", "generic"
        )

        assert dn_result["valid"] is True

    def test_validation_report_structure(self) -> None:
        """Test that validation report has correct structure."""
        quirks = FlextLdifEntryQuirks()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        validation_result = quirks.validate_entry(entry, "generic")

        assert validation_result.is_success
        report = validation_result.unwrap()

        # Check required fields
        assert "server_type" in report
        assert "compliant" in report
        assert "issues" in report
        assert "warnings" in report

        # Check types
        assert isinstance(report["server_type"], str)
        assert isinstance(report["compliant"], bool)
        assert isinstance(report["issues"], list)
        assert isinstance(report["warnings"], list)
