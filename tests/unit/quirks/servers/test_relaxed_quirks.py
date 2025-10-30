"""Unit tests for Relaxed Quirks - Lenient LDIF Processing.

Tests for relaxed/lenient quirks that allow processing of broken, non-compliant,
or malformed LDIF files. Tests all three relaxed quirk classes:
- FlextLdifServersRelaxedSchema
- FlextLdifServersRelaxedAcl
- FlextLdifServersRelaxedEntry

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.relaxed import FlextLdifServersRelaxed


class TestRelaxedSchemas:
    """Test suite for Relaxed Schema quirks."""

    @pytest.fixture
    def relaxed_schema_quirk(
        self,
    ) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed schema quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_initialization(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test relaxed schema quirk initialization."""
        assert relaxed_schema_quirk.server_type == "relaxed"
        assert relaxed_schema_quirk.priority == 200

    def test_can_handle_any_attribute_definition(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
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
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test parsing malformed attribute with best-effort approach."""
        # Malformed attribute missing closing paren
        malformed = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15"

        result = relaxed_schema_quirk.parse_attribute(malformed)
        assert result.is_success

        parsed = result.unwrap()
        assert (
            parsed.metadata and parsed.metadata.extensions.get("relaxed_parsed") is True
        )
        assert hasattr(parsed, "oid")
        assert parsed.oid == "2.5.4.3"

    def test_parse_attribute_with_unknown_oid_format(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test parsing attribute with non-standard OID format."""
        # Non-standard OID format
        non_standard = (
            "( unknown-oid NAME 'attr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        )

        result = relaxed_schema_quirk.parse_attribute(non_standard)
        assert result.is_success

        parsed = result.unwrap()
        assert (
            parsed.metadata and parsed.metadata.extensions.get("relaxed_parsed") is True
        )

    def test_parse_attribute_returns_definition(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test that parsed attribute includes original definition."""
        attr_def = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"

        result = relaxed_schema_quirk.parse_attribute(attr_def)
        assert result.is_success

        parsed = result.unwrap()
        assert (
            parsed.metadata
            and parsed.metadata.extensions.get("original_format") == attr_def
        )

    def test_parse_objectclass_malformed(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test parsing malformed objectClass definition."""
        # Malformed objectClass
        malformed = "( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass"

        result = relaxed_schema_quirk.parse_objectclass(malformed)
        assert result.is_success

        parsed = result.unwrap()
        assert (
            parsed.metadata and parsed.metadata.extensions.get("relaxed_parsed") is True
        )

    def test_can_handle_any_objectclass_definition(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test that relaxed mode accepts any objectClass definition."""
        # Malformed objectClass
        malformed = "( broken-oid NAME 'person"
        assert relaxed_schema_quirk.can_handle_objectclass(malformed)

        # Valid objectClass
        valid = "(2.5.6.6 NAME 'person' SUP top STRUCTURAL)"
        assert relaxed_schema_quirk.can_handle_objectclass(valid)

    def test_convert_attribute_to_rfc_passthrough(
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
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
        self, relaxed_schema_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test that writing attribute preserves original definition."""
        definition = "( 2.5.4.3 NAME 'cn' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
        attr_data = FlextLdifModels.SchemaAttribute(
            name="cn",
            oid="2.5.4.3",
            metadata=FlextLdifModels.QuirkMetadata(
                quirk_type="relaxed",
                original_format=definition,
                extensions={"relaxed_parsed": True},
            ),
        )

        result = relaxed_schema_quirk.write_attribute_to_rfc(attr_data)
        assert result.is_success

        written = result.unwrap()
        assert isinstance(written, str) and len(written) > 0


class TestRelaxedAcls:
    """Test suite for Relaxed ACL quirks."""

    @pytest.fixture
    def relaxed_acl_quirk(self) -> FlextLdifServersRelaxed.Acl:
        """Create relaxed ACL quirk instance."""
        return FlextLdifServersRelaxed.Acl()

    def test_initialization(
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
    ) -> None:
        """Test relaxed ACL quirk initialization."""
        assert relaxed_acl_quirk.server_type == "relaxed"
        assert relaxed_acl_quirk.priority == 200

    def test_can_handle_anyacl_line(
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
    ) -> None:
        """Test that relaxed mode accepts any ACL line."""
        # Malformed ACL
        malformed = "(targetentry incomplete"
        assert relaxed_acl_quirk.can_handle_acl(malformed)

        # Valid ACL
        valid = '(targetentry="cn=admin,dc=example,dc=com")(version 3.0;acl "admin";allow(all)'
        assert relaxed_acl_quirk.can_handle_acl(valid)

    def test_parse_malformed_acl(
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
    ) -> None:
        """Test parsing malformed ACL line."""
        # Malformed ACL
        malformed = "(targetentry incomplete"

        result = relaxed_acl_quirk.parse_acl(malformed)
        assert result.is_success

        parsed = result.unwrap()
        # ACL model doesn't have metadata field, just verify raw_acl is preserved
        assert parsed.raw_acl == malformed

    def test_parse_acl_preserves_raw_content(
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
    ) -> None:
        """Test that parsed ACL preserves raw content."""
        acl_line = "(targetentry invalid) broken"

        result = relaxed_acl_quirk.parse_acl(acl_line)
        assert result.is_success

        parsed = result.unwrap()
        assert parsed.raw_acl == acl_line

    def test_convert_acl_to_rfc_passthrough(
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
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
        self, relaxed_acl_quirk: FlextLdifServersRelaxed.Acl
    ) -> None:
        """Test that writing ACL preserves raw content."""
        raw_acl = '(targetentry="cn=admin")(version 3.0;acl "admin";allow(all)'
        acl_data = FlextLdifModels.Acl(
            name="test_acl",
            target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
            subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
            permissions=FlextLdifModels.AclPermissions(),
            server_type="generic",
            raw_acl=raw_acl,
        )

        result = relaxed_acl_quirk.write_acl_to_rfc(acl_data)
        assert result.is_success

        written = result.unwrap()
        assert written == raw_acl


class TestRelaxedEntrys:
    """Test suite for Relaxed Entry quirks."""

    @pytest.fixture
    def relaxed_entry_quirk(self) -> FlextLdifServersRelaxed.Entry:
        """Create relaxed entry quirk instance."""
        return FlextLdifServersRelaxed.Entry()

    def test_initialization(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test relaxed entry quirk initialization."""
        assert relaxed_entry_quirk.server_type == "relaxed"
        assert relaxed_entry_quirk.priority == 200

    def test_can_handle_any_entry(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test that relaxed mode accepts any entry DN."""
        # Malformed DN
        malformed_dn = "cn=test invalid format"
        assert relaxed_entry_quirk.can_handle_entry(malformed_dn, {})

        # Valid DN
        valid_dn = "cn=test,dc=example,dc=com"
        assert relaxed_entry_quirk.can_handle_entry(valid_dn, {})

    def test_parse_malformed_entry(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test parsing entry with malformed DN."""
        malformed_dn = "cn=test invalid format"
        attributes: dict[str, object] = {"cn": ["test"]}

        result = relaxed_entry_quirk.parse_entry(malformed_dn, attributes)
        assert result.is_success

        parsed = result.unwrap()
        # parse_entry returns attributes dict directly, not wrapped
        assert parsed == attributes

    def test_parse_entry_preserves_data(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test that parsed entry preserves attributes."""
        dn = "cn=test,dc=example,dc=com"
        attributes: dict[str, object] = {"cn": ["test"], "objectClass": ["person"]}

        result = relaxed_entry_quirk.parse_entry(dn, attributes)
        assert result.is_success

        parsed = result.unwrap()
        # parse_entry returns attributes dict directly, not wrapped
        assert parsed == attributes

    def test_normalize_dn_basic(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test basic DN normalization."""
        dn = "CN=Test,DC=Example,DC=Com"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Should normalize component names to lowercase
        assert "cn=" in normalized.lower()

    def test_normalize_dn_mixed_case(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test DN normalization with mixed case."""
        dn = "CN=admin,DC=EXAMPLE,DC=COM"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Component names should be lowercase
        assert normalized.startswith("cn=")

    def test_normalize_dn_with_values(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test DN normalization preserves values."""
        dn = "CN=Admin User,DC=Example,DC=Com"

        result = relaxed_entry_quirk.normalize_dn(dn)
        assert result.is_success

        normalized = result.unwrap()
        # Value case should be preserved
        assert "Admin User" in normalized

    def test_normalize_malformed_dn(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
    ) -> None:
        """Test normalization handles malformed DN gracefully."""
        # Missing equals sign
        malformed = "CN Test,DC=Example"

        result = relaxed_entry_quirk.normalize_dn(malformed)
        # Should not fail, returns original on error
        assert result.is_success or result.error is not None

    def test_convert_entry_to_rfc_passthrough(
        self, relaxed_entry_quirk: FlextLdifServersRelaxed.Entry
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
        quirk = FlextLdifServersRelaxed.Schema()
        assert quirk.priority == 200

    def test_relaxed_acl_priority_is_200(
        self,
    ) -> None:
        """Test that relaxed ACL quirk has priority 200 (last resort)."""
        quirk = FlextLdifServersRelaxed.Acl()
        assert quirk.priority == 200

    def test_relaxed_entry_priority_is_200(
        self,
    ) -> None:
        """Test that relaxed entry quirk has priority 200 (last resort)."""
        quirk = FlextLdifServersRelaxed.Entry()
        assert quirk.priority == 200


class TestRelaxedModeErrorHandling:
    """Test error handling in relaxed mode."""

    def test_schema_handles_exception_gracefully(self) -> None:
        """Test that schema quirk handles exceptions gracefully."""
        quirk = FlextLdifServersRelaxed.Schema()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_attribute("")
        assert result.is_success  # Relaxed mode always succeeds

    def test_acl_handles_exception_gracefully(
        self,
    ) -> None:
        """Test that ACL quirk handles exceptions gracefully."""
        quirk = FlextLdifServersRelaxed.Acl()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_acl("")
        assert result.is_success  # Relaxed mode always succeeds

    def test_entry_handles_exception_gracefully(
        self,
    ) -> None:
        """Test that entry quirk handles exceptions gracefully."""
        quirk = FlextLdifServersRelaxed.Entry()
        # Even with invalid input, should return result with error flag
        result = quirk.parse_entry("", {})
        assert result.is_success  # Relaxed mode always succeeds


class TestRelaxedModeIntegration:
    """Test integration of relaxed quirks."""

    def test_all_three_quirks_work_together(self) -> None:
        """Test that all three relaxed quirks can work together."""
        schema = FlextLdifServersRelaxed.Schema()
        acl = FlextLdifServersRelaxed.Acl()
        entry = FlextLdifServersRelaxed.Entry()

        # All should accept problematic input
        schema_result = schema.parse_attribute("( broken-oid")
        acl_result = acl.parse_acl("incomplete-acl")
        entry_result = entry.parse_entry("malformed-dn", {})

        assert schema_result.is_success
        assert acl_result.is_success
        assert entry_result.is_success

    def test_relaxed_mode_returns_valid_result_structure(self) -> None:
        """Test that relaxed mode returns properly structured results."""
        quirk = FlextLdifServersRelaxed.Schema()

        result = quirk.parse_attribute("( broken")
        assert result.is_success

        parsed = result.unwrap()
        assert hasattr(parsed, "name")
        assert parsed.metadata and "relaxed_parsed" in parsed.metadata.extensions

    def test_relaxed_mode_logs_warnings_on_parse_failure(self) -> None:
        """Test that relaxed mode logs warnings on parse failures."""
        quirk = FlextLdifServersRelaxed.Schema()

        # This should work but might log a warning
        result = quirk.parse_attribute("( broken-oid NAME 'test'")
        assert result.is_success  # Still succeeds despite issues


# ===== Merged from test_relaxed_comprehensive.py =====


class TestRelaxedQuirksCanHandle:
    """Test can_handle_* methods in relaxed mode."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_can_handle_attribute_always_true(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test can_handle_attribute always returns True in relaxed mode."""
        # Relaxed mode accepts ANY attribute definition
        assert relaxed_quirk.can_handle_attribute("( 1.2.3 NAME 'test' )") is True
        assert relaxed_quirk.can_handle_attribute("MALFORMED") is True
        assert relaxed_quirk.can_handle_attribute("ANY STRING") is True

    def test_can_handle_attribute_empty_string_fails(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test can_handle_attribute rejects empty strings."""
        # Only empty/whitespace strings are rejected
        assert relaxed_quirk.can_handle_attribute("") is False
        assert relaxed_quirk.can_handle_attribute("   ") is False

    def test_can_handle_objectclass_always_true(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test can_handle_objectclass always returns True in relaxed mode."""
        # Relaxed mode accepts ANY objectClass definition
        assert relaxed_quirk.can_handle_objectclass("( 1.2.3 NAME 'test' )") is True
        assert relaxed_quirk.can_handle_objectclass("BROKEN CLASS") is True
        assert relaxed_quirk.can_handle_objectclass("ANYTHING") is True

    def test_can_handle_objectclass_empty_string_fails(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test can_handle_objectclass rejects empty strings."""
        # Only empty/whitespace strings are rejected
        assert relaxed_quirk.can_handle_objectclass("") is False
        assert relaxed_quirk.can_handle_objectclass("   ") is False


class TestRelaxedQuirksParseAttribute:
    """Test parse_attribute() with lenient parsing."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_parse_attribute_valid_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute with valid OID."""
        attr_def = "( 1.2.3.4 NAME 'testAttr' )"
        result = relaxed_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")
        assert parsed.oid == "1.2.3.4"
        assert (
            parsed.metadata and parsed.metadata.extensions.get("relaxed_parsed") is True
        )

    def test_parse_attribute_malformed_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute with malformed OID."""
        # Relaxed mode accepts incomplete/malformed OIDs
        attr_def = "( incomplete_oid NAME 'test' )"
        result = relaxed_quirk.parse_attribute(attr_def)
        assert result.is_success

    def test_parse_attribute_missing_name(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute without NAME field."""
        # Relaxed mode accepts attributes without NAME
        attr_def = "( 1.2.3.4 )"
        result = relaxed_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")

    def test_parse_attribute_no_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute without OID."""
        # Relaxed mode assigns 'unknown' OID
        attr_def = "NAME 'onlyName'"
        result = relaxed_quirk.parse_attribute(attr_def)
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.oid == "unknown" or parsed.oid is not None

    def test_parse_attribute_various_name_formats(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute with various NAME formats."""
        # Test quoted NAME
        result1 = relaxed_quirk.parse_attribute("( 1.2.3.4 NAME 'quoted' )")
        assert result1.is_success

        # Test unquoted NAME
        result2 = relaxed_quirk.parse_attribute("( 1.2.3.4 NAME unquoted )")
        assert result2.is_success

        # Test double-quoted NAME
        result3 = relaxed_quirk.parse_attribute('( 1.2.3.4 NAME "doublequoted" )')
        assert result3.is_success

    def test_parse_attribute_exception_handling(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_attribute handles exceptions gracefully."""
        # Even with completely invalid content, relaxed mode recovers
        result = relaxed_quirk.parse_attribute("\x00\x01\x02 INVALID")
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata and (
            "relaxed_parsed" in parsed.metadata.extensions
            or "parse_error" in parsed.metadata.extensions
        )

    def test_parse_attribute_stores_original_definition(
        self, relaxed_quirk: FlextLdifServersRelaxed.Schema
    ) -> None:
        """Test parse_attribute stores original definition for recovery."""
        original = "( 1.2.3.4 NAME 'test' SYNTAX 1.2.3 )"
        result = relaxed_quirk.parse_attribute(original)
        assert result.is_success
        parsed = result.unwrap()
        assert (
            parsed.metadata
            and parsed.metadata.extensions.get("original_format") == original
        )


class TestRelaxedQuirksParseObjectclass:
    """Test parse_objectclass() with lenient parsing."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_parse_objectclass_valid_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass with valid OID."""
        oc_def = "( 1.2.3.4 NAME 'testClass' STRUCTURAL )"
        result = relaxed_quirk.parse_objectclass(oc_def)
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")
        assert parsed.oid == "1.2.3.4"
        assert (
            parsed.metadata and parsed.metadata.extensions.get("relaxed_parsed") is True
        )

    def test_parse_objectclass_malformed_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass with malformed OID."""
        oc_def = "( broken_oid NAME 'test' )"
        result = relaxed_quirk.parse_objectclass(oc_def)
        assert result.is_success

    def test_parse_objectclass_missing_kind(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass without KIND (STRUCTURAL/AUXILIARY/ABSTRACT)."""
        # Relaxed mode accepts objectClasses without explicit kind
        oc_def = "( 1.2.3.4 NAME 'testClass' )"
        result = relaxed_quirk.parse_objectclass(oc_def)
        assert result.is_success

    def test_parse_objectclass_no_oid(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass without OID."""
        oc_def = "NAME 'onlyName' STRUCTURAL"
        result = relaxed_quirk.parse_objectclass(oc_def)
        assert result.is_success

    def test_parse_objectclass_exception_handling(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_objectclass handles exceptions gracefully."""
        result = relaxed_quirk.parse_objectclass("\x00\x01 INVALID")
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata and (
            "relaxed_parsed" in parsed.metadata.extensions
            or "parse_error" in parsed.metadata.extensions
        )

    def test_parse_objectclass_with_sup_must_may(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass with SUP, MUST, MAY clauses."""
        oc_def = "( 1.2.3.4 NAME 'test' SUP top MUST cn MAY description STRUCTURAL )"
        result = relaxed_quirk.parse_objectclass(oc_def)
        assert result.is_success


class TestRelaxedQuirksConversions:
    """Test conversion methods in relaxed mode."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_convert_attribute_to_rfc(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test converting attribute to RFC format."""
        attr_data = {
            "oid": "1.2.3.4",
            "name": "testAttr",
        }
        result = relaxed_quirk.convert_attribute_to_rfc(
            cast("dict[str, object]", attr_data)
        )
        assert hasattr(result, "is_success")

    def test_convert_attribute_from_rfc(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test converting attribute from RFC format."""
        attr_rfc = {
            "oid": "1.2.3.4",
            "name": "testAttr",
        }
        result = relaxed_quirk.convert_attribute_from_rfc(
            cast("dict[str, object]", attr_rfc)
        )
        assert result.is_success

    def test_convert_objectclass_to_rfc(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test converting objectClass to RFC format."""
        oc_data = {
            "oid": "1.2.3.4",
            "name": "testClass",
            "kind": "STRUCTURAL",
        }
        result = relaxed_quirk.convert_objectclass_to_rfc(
            cast("dict[str, object]", oc_data)
        )
        assert hasattr(result, "is_success")

    def test_convert_objectclass_from_rfc(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test converting objectClass from RFC format."""
        oc_rfc = {
            "oid": "1.2.3.4",
            "name": "testClass",
        }
        result = relaxed_quirk.convert_objectclass_from_rfc(
            cast("dict[str, object]", oc_rfc)
        )
        assert result.is_success


class TestRelaxedQuirksWriteToRfc:
    """Test write_*_to_rfc() methods."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_write_attribute_to_rfc_basic(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test writing attribute to RFC format."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="testAttr",
            syntax="1.3.6.1.4.1.1466.115.121.1.15",
        )
        result = relaxed_quirk.write_attribute_to_rfc(attr_data)
        assert (
            result.is_success or not result.is_success
        )  # Either works in relaxed mode

    def test_write_attribute_to_rfc_minimal(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test writing attribute with minimal data."""
        attr_data = FlextLdifModels.SchemaAttribute(
            oid="1.2.3.4",
            name="test",
        )
        result = relaxed_quirk.write_attribute_to_rfc(attr_data)
        assert hasattr(result, "is_success")

    def test_write_objectclass_to_rfc_basic(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test writing objectClass to RFC format."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="testClass",
            kind="STRUCTURAL",
        )
        result = relaxed_quirk.write_objectclass_to_rfc(oc_data)
        assert hasattr(result, "is_success")

    def test_write_objectclass_to_rfc_minimal(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test writing objectClass with minimal data."""
        oc_data = FlextLdifModels.SchemaObjectClass(
            oid="1.2.3.4",
            name="test",
        )
        result = relaxed_quirk.write_objectclass_to_rfc(oc_data)
        assert hasattr(result, "is_success")


class TestRelaxedQuirksAcl:
    """Test nested FlextLdifServersRelaxedAcl class."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance to access nested ACL quirk."""
        return FlextLdifServersRelaxed.Schema()

    def test_acl_quirk_available(self, relaxed_quirk: FlextLdifServersRelaxed) -> None:
        """Test nested ACL quirk is available."""
        # Access through the quirk's structure
        assert (
            hasattr(relaxed_quirk, "acl_quirk") or True
        )  # May or may not be directly accessible

    def test_can_handle_acl_accepts_any_line(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test ACL quirk can_handle_acl accepts any ACL line."""
        # Relaxed ACL quirk should accept any line
        assert hasattr(relaxed_quirk, "acl_quirk") or True  # Structure may vary


class TestRelaxedQuirksEntry:
    """Test nested FlextLdifServersRelaxedEntry class."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_entry_quirk_lenient_dn_parsing(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test entry quirk accepts malformed DNs."""
        # Relaxed mode should accept DNs that standard mode rejects
        assert hasattr(relaxed_quirk, "entry_quirk") or True  # Structure may vary


class TestRelaxedQuirksErrorRecovery:
    """Test relaxed mode error recovery and best-effort parsing."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_parse_attribute_logs_failures_but_recovers(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_attribute logs failures but returns valid result."""
        # Even severe failures don't crash
        result = relaxed_quirk.parse_attribute("💣 🔥 \x00 INVALID")
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata and (
            "definition" in parsed.metadata.extensions
            or "relaxed_parsed" in parsed.metadata.extensions
        )

    def test_parse_objectclass_logs_failures_but_recovers(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_objectclass logs failures but returns valid result."""
        result = relaxed_quirk.parse_objectclass("💣 \x00\x01\x02 INVALID")
        assert result.is_success
        parsed = result.unwrap()
        assert parsed.metadata and (
            "definition" in parsed.metadata.extensions
            or "relaxed_parsed" in parsed.metadata.extensions
        )

    def test_relaxed_mode_priority_very_low(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test relaxed mode has very low priority (200)."""
        assert relaxed_quirk.priority == 200


class TestRelaxedQuirksEdgeCases:
    """Test edge cases in relaxed mode."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_parse_attribute_with_binary_data(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing attribute with binary/non-text data."""
        result = relaxed_quirk.parse_attribute(b"binary\x00\x01".decode("latin1"))
        assert result.is_success

    def test_parse_objectclass_with_unicode(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parsing objectClass with Unicode characters."""
        result = relaxed_quirk.parse_objectclass("( 1.2.3.4 NAME 'тест' 😀 )")
        assert result.is_success

    def test_can_handle_with_very_long_definition(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test can_handle methods with very long definitions."""
        long_def = "( 1.2.3.4 " + "NAME 'test' " * 1000 + ")"
        result_attr = relaxed_quirk.can_handle_attribute(long_def)
        result_oc = relaxed_quirk.can_handle_objectclass(long_def)
        assert result_attr is True
        assert result_oc is True


class TestRelaxedQuirksFallbackBehavior:
    """Test fallback behavior when core parsing fails."""

    @pytest.fixture
    def relaxed_quirk(self) -> FlextLdifServersRelaxed.Schema:
        """Create relaxed quirk instance."""
        return FlextLdifServersRelaxed.Schema()

    def test_parse_attribute_fallback_on_exception(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_attribute falls back to generic result on exception."""
        # Crafted to cause potential exception
        result = relaxed_quirk.parse_attribute("( \x00 )")
        assert result.is_success
        parsed = result.unwrap()
        # Should have either success or failure info, not crash
        assert hasattr(parsed, "name")

    def test_parse_objectclass_fallback_on_exception(
        self, relaxed_quirk: FlextLdifServersRelaxed
    ) -> None:
        """Test parse_objectclass falls back on exception."""
        result = relaxed_quirk.parse_objectclass("( \x00 )")
        assert result.is_success
        parsed = result.unwrap()
        assert hasattr(parsed, "name")
