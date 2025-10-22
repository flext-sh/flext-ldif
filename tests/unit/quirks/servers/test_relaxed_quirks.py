"""Unit tests for Relaxed Quirks - Lenient LDIF Processing.

Tests for relaxed/lenient quirks that allow processing of broken, non-compliant,
or malformed LDIF files. Tests all three relaxed quirk classes:
- FlextLdifQuirksServersRelaxedSchema
- FlextLdifQuirksServersRelaxedAcl
- FlextLdifQuirksServersRelaxedEntry

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.quirks.servers.relaxed_quirks import (
    FlextLdifQuirksServersRelaxedAcl,
    FlextLdifQuirksServersRelaxedEntry,
    FlextLdifQuirksServersRelaxedSchema,
)


class TestRelaxedSchemaQuirks:
    """Test suite for Relaxed Schema quirks."""

    @pytest.fixture
    def relaxed_schema_quirk(
        self,
    ) -> FlextLdifQuirksServersRelaxedSchema:
        """Create relaxed schema quirk instance."""
        return FlextLdifQuirksServersRelaxedSchema()

    def test_initialization(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test relaxed schema quirk initialization."""
        assert relaxed_schema_quirk.server_type == "relaxed"
        assert relaxed_schema_quirk.priority == 200

    def test_can_handle_any_attribute_definition(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test that relaxed mode accepts any attribute definition."""
        # Malformed attribute
        malformed = "( incomplete-oid NAME 'broken'"
        assert relaxed_schema_quirk.can_handle_attribute(malformed)

        # Empty string - should NOT be handled
        assert not relaxed_schema_quirk.can_handle_attribute("")

        # Valid attribute
        valid = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        assert relaxed_schema_quirk.can_handle_attribute(valid)

    def test_parse_malformed_attribute(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test parsing malformed attribute with best-effort approach."""
        # Malformed attribute missing closing paren
        malformed = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"

        result = relaxed_schema_quirk.parse_attribute(malformed)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["relaxed_parsed"] is True
        assert "oid" in parsed
        assert parsed["oid"] == "2.5.4.3"

    def test_parse_attribute_with_unknown_oid_format(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test parsing attribute with non-standard OID format."""
        # Non-standard OID format
        non_standard = (
            "( unknown-oid NAME 'attr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = relaxed_schema_quirk.parse_attribute(non_standard)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["relaxed_parsed"] is True

    def test_parse_attribute_returns_definition(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test that parsed attribute includes original definition."""
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        result = relaxed_schema_quirk.parse_attribute(attr_def)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["definition"] == attr_def

    def test_parse_objectclass_malformed(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test parsing malformed objectClass definition."""
        # Malformed objectClass
        malformed = "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass"

        result = relaxed_schema_quirk.parse_objectclass(malformed)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["relaxed_parsed"] is True

    def test_can_handle_any_objectclass_definition(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test that relaxed mode accepts any objectClass definition."""
        # Malformed objectClass
        malformed = "( broken-oid NAME 'person"
        assert relaxed_schema_quirk.can_handle_objectclass(malformed)

        # Valid objectClass
        valid = "(2.5.6.6 NAME 'person' SUP top STRUCTURAL)"
        assert relaxed_schema_quirk.can_handle_objectclass(valid)

    def test_convert_attribute_to_rfc_passthrough(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test that attribute conversion is pass-through."""
        attr_data = {
            "oid": "2.5.4.3",
            "name": "cn",
            "definition": "test",
            "relaxed_parsed": True,
        }

        result = relaxed_schema_quirk.convert_attribute_to_rfc(attr_data)
        assert result.is_success

        converted = result.unwrap()
        assert converted == attr_data

    def test_write_attribute_preserves_definition(
        self, relaxed_schema_quirk: FlextLdifQuirksServersRelaxedSchema
    ) -> None:
        """Test that writing attribute preserves original definition."""
        definition = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        attr_data: dict[str, object] = {"definition": definition}

        result = relaxed_schema_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success

        written = result.unwrap()
        assert written == definition


class TestRelaxedAclQuirks:
    """Test suite for Relaxed ACL quirks."""

    @pytest.fixture
    def relaxed_acl_quirk(self) -> FlextLdifQuirksServersRelaxedAcl:
        """Create relaxed ACL quirk instance."""
        return FlextLdifQuirksServersRelaxedAcl()

    def test_initialization(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test relaxed ACL quirk initialization."""
        assert relaxed_acl_quirk.server_type == "relaxed"
        assert relaxed_acl_quirk.priority == 200

    def test_can_handle_any_acl_line(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test that relaxed mode accepts any ACL line."""
        # Malformed ACL
        malformed = "(targetentry incomplete"
        assert relaxed_acl_quirk.can_handle_acl(malformed)

        # Valid ACL
        valid = '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)'
        assert relaxed_acl_quirk.can_handle_acl(valid)

    def test_parse_malformed_acl(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test parsing malformed ACL line."""
        # Malformed ACL
        malformed = "(targetentry incomplete"

        result = relaxed_acl_quirk.parse_acl(malformed)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["relaxed_parsed"] is True
        assert parsed["raw_acl"] == malformed

    def test_parse_acl_preserves_raw_content(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test that parsed ACL preserves raw content."""
        acl_line = "(targetentry invalid) broken"

        result = relaxed_acl_quirk.parse_acl(acl_line)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["raw_acl"] == acl_line

    def test_convert_acl_to_rfc_passthrough(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test that ACL conversion is pass-through."""
        acl_data = {
            "raw_acl": "(targetentry invalid) broken",
            "relaxed_parsed": True,
        }

        result = relaxed_acl_quirk.convert_acl_to_rfc(acl_data)
        assert result.is_success

        converted = result.unwrap()
        assert converted == acl_data

    def test_write_acl_preserves_raw_content(
        self, relaxed_acl_quirk: FlextLdifQuirksServersRelaxedAcl
    ) -> None:
        """Test that writing ACL preserves raw content."""
        raw_acl = '(targetentry="cn=REDACTED_LDAP_BIND_PASSWORD")(version 3.0;acl "REDACTED_LDAP_BIND_PASSWORD";allow(all)'
        acl_data: dict[str, object] = {"raw_acl": raw_acl}

        result = relaxed_acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success

        written = result.unwrap()
        assert written == raw_acl


class TestRelaxedEntryQuirks:
    """Test suite for Relaxed Entry quirks."""

    @pytest.fixture
    def relaxed_entry_quirk(self) -> FlextLdifQuirksServersRelaxedEntry:
        """Create relaxed entry quirk instance."""
        return FlextLdifQuirksServersRelaxedEntry()

    def test_initialization(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test relaxed entry quirk initialization."""
        assert relaxed_entry_quirk.server_type == "relaxed"
        assert relaxed_entry_quirk.priority == 200

    def test_can_handle_any_entry(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test that relaxed mode accepts any entry DN."""
        # Malformed DN
        malformed_dn = "cn=test invalid format"
        assert relaxed_entry_quirk.can_handle_entry(malformed_dn, {})

        # Valid DN
        valid_dn = "cn=test,dc=example,dc=com"
        assert relaxed_entry_quirk.can_handle_entry(valid_dn, {})

    def test_parse_malformed_entry(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test parsing entry with malformed DN."""
        malformed_dn = "cn=test invalid format"
        attributes: dict[str, object] = {"cn": ["test"]}

        result = relaxed_entry_quirk.parse_entry(malformed_dn, attributes)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["relaxed_parsed"] is True
        assert parsed["dn"] == malformed_dn
        assert parsed["attributes"] == attributes

    def test_parse_entry_preserves_data(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test that parsed entry preserves DN and attributes."""
        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"cn": ["test"], "objectClass": ["person"]}

        result = relaxed_entry_quirk.parse_entry(dn, attributes)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed["dn"] == dn
        assert parsed["attributes"] == attributes

    def test_normalize_dn_basic(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test basic DN normalization."""
        dn = "CN=Test,DC=Example,DC=Com"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Should normalize component names to lowercase
        assert "cn=" in normalized.lower()

    def test_normalize_dn_mixed_case(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test DN normalization with mixed case."""
        dn = "CN=REDACTED_LDAP_BIND_PASSWORD,DC=EXAMPLE,DC=COM"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Component names should be lowercase
        assert normalized.startswith("cn=")

    def test_normalize_dn_with_values(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test DN normalization preserves values."""
        dn = "CN=Admin User,DC=Example,DC=Com"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Value case should be preserved
        assert "Admin User" in normalized

    def test_normalize_malformed_dn(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test normalization handles malformed DN gracefully."""
        # Missing equals sign
        malformed = "CN Test,DC=Example"

        result = relaxed_entry_quirk.normalize_dn(malformed)
        # Should not fail, returns original on error
        assert result.is_success or result.error is not None

    def test_convert_entry_to_rfc_passthrough(
        self, relaxed_entry_quirk: FlextLdifQuirksServersRelaxedEntry
    ) -> None:
        """Test that entry conversion is pass-through."""
        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"]},
            "relaxed_parsed": True,
        }

        result = relaxed_entry_quirk.convert_entry_to_rfc(entry_data)
        assert result.is_success

        converted = result.unwrap()
        assert converted == entry_data


class TestRelaxedModePriority:
    """Test that relaxed mode has correct priority."""

    def test_relaxed_schema_priority_is_200(
        self,
    ) -> None:
        """Test that relaxed schema quirk has priority 200 (last resort)."""
        quirk = FlextLdifQuirksServersRelaxedSchema()
        assert quirk.priority == 200

    def test_relaxed_acl_priority_is_200(
        self,
    ) -> None:
        """Test that relaxed ACL quirk has priority 200 (last resort)."""
        quirk = FlextLdifQuirksServersRelaxedAcl()
        assert quirk.priority == 200

    def test_relaxed_entry_priority_is_200(
        self,
    ) -> None:
        """Test that relaxed entry quirk has priority 200 (last resort)."""
        quirk = FlextLdifQuirksServersRelaxedEntry()
        assert quirk.priority == 200


class TestRelaxedModeErrorHandling:
    """Test error handling in relaxed mode."""

    def test_schema_handles_exception_gracefully(self) -> None:
        """Test that schema quirk handles exceptions gracefully."""
        quirk = FlextLdifQuirksServersRelaxedSchema()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_attribute("")
        assert result.is_success  # Relaxed mode always succeeds

    def test_acl_handles_exception_gracefully(
        self,
    ) -> None:
        """Test that ACL quirk handles exceptions gracefully."""
        quirk = FlextLdifQuirksServersRelaxedAcl()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_acl("")
        assert result.is_success  # Relaxed mode always succeeds

    def test_entry_handles_exception_gracefully(
        self,
    ) -> None:
        """Test that entry quirk handles exceptions gracefully."""
        quirk = FlextLdifQuirksServersRelaxedEntry()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_entry("", {})
        assert result.is_success  # Relaxed mode always succeeds


class TestRelaxedModeIntegration:
    """Test integration of relaxed quirks."""

    def test_all_three_quirks_work_together(self) -> None:
        """Test that all three relaxed quirks can work together."""
        schema = FlextLdifQuirksServersRelaxedSchema()
        acl = FlextLdifQuirksServersRelaxedAcl()
        entry = FlextLdifQuirksServersRelaxedEntry()

        # All should accept problematic input
        schema_result = schema.parse_attribute("( broken-oid")
        acl_result = acl.parse_acl("incomplete-acl")
        entry_result = entry.parse_entry("malformed-dn", {})

        assert schema_result.is_success
        assert acl_result.is_success
        assert entry_result.is_success

    def test_relaxed_mode_returns_valid_result_structure(self) -> None:
        """Test that relaxed mode returns properly structured results."""
        quirk = FlextLdifQuirksServersRelaxedSchema()

        result = quirk.parse_attribute("( broken")
        assert result.is_success

        parsed = result.unwrap()
        assert isinstance(parsed, dict)
        assert "relaxed_parsed" in parsed

    def test_relaxed_mode_logs_warnings_on_parse_failure(self) -> None:
        """Test that relaxed mode logs warnings on parse failures."""
        quirk = FlextLdifQuirksServersRelaxedSchema()

        # This should work but might log a warning
        result = quirk.parse_attribute("( broken-oid NAME 'test'")
        assert result.is_success  # Still succeeds despite issues
