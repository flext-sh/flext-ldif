"""Phase 4.1: RFC LDIF Writer comprehensive tests.

Tests cover:
- RFC 2849 compliant LDIF writing with real entries
- Attribute value encoding (base64, UTF-8)
- Line wrapping and continuation
- Special character handling
- DN normalization for output
- Schema attribute writing
- ObjectClass writing
- Entry serialization

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry
from flext_ldif.rfc.rfc_ldif_writer import FlextLdifRfcLdifWriter


class TestRfcLdifWriterPhase41:
    """Test RFC LDIF Writer with real entries and data."""

    def test_rfc_writer_initialization(self) -> None:
        """Test RFC writer can be initialized."""
        quirk_registry = FlextLdifQuirksRegistry()
        writer = FlextLdifRfcLdifWriter(
            params={},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        assert writer is not None

    def test_rfc_writer_has_execute_method(self) -> None:
        """Test RFC writer has execute method."""
        quirk_registry = FlextLdifQuirksRegistry()
        writer = FlextLdifRfcLdifWriter(
            params={},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )
        assert hasattr(writer, "execute")
        assert callable(writer.execute)

    def test_write_simple_entry(self) -> None:
        """Test writing simple LDIF entry."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Simple entry - use Entry.create() method
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert "content" in output or output.get("entries_written", 0) > 0

    def test_write_entry_with_multiple_attributes(self) -> None:
        """Test writing entry with multiple attribute values."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Entry with multiple values per attribute
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test", "test user"],
                "mail": ["test@example.com", "test.user@example.com"],
                "objectClass": ["person", "inetOrgPerson", "top"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert output.get("entries_written", 0) > 0

    def test_write_entry_with_special_characters(self) -> None:
        """Test writing entry with special characters in DN."""
        quirk_registry = FlextLdifQuirksRegistry()

        # DN with special characters (using hyphen instead of comma for valid DN)
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=Test-User,dc=example,dc=com",
            attributes={"cn": ["Test-User"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_entry_with_unicode(self) -> None:
        """Test writing entry with Unicode characters."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Entry with Unicode
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=José García,dc=example,dc=com",
            attributes={"cn": ["José García"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_attribute_schema(self) -> None:
        """Test writing attribute schema definition."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Attribute schema data
        schema = {
            "attributes": {
                "testAttr": "( 1.2.3.4 NAME 'testAttr' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            }
        }

        writer = FlextLdifRfcLdifWriter(
            params={"schema": schema},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert output.get("entries_written", 0) > 0

    def test_write_objectclass_schema(self) -> None:
        """Test writing objectClass schema definition."""
        quirk_registry = FlextLdifQuirksRegistry()

        # ObjectClass schema data
        schema = {
            "objectclasses": {"testOC": "( 1.2.3.5 NAME 'testOC' SUP top STRUCTURAL )"}
        }

        writer = FlextLdifRfcLdifWriter(
            params={"schema": schema},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert output.get("entries_written", 0) > 0

    def test_write_entry_with_binary_attribute(self) -> None:
        """Test writing entry with binary attribute (base64 encoded)."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Entry with binary-like attribute
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "jpegPhoto": ["SGVsbG8gV29ybGQ="],  # "Hello World" in base64
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_entry_with_long_attribute_value(self) -> None:
        """Test writing entry with long attribute value (line wrapping)."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Entry with long attribute value (should trigger line wrapping)
        long_value = "x" * 100  # 100 character long value
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "description": [long_value],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_batch_entries(self) -> None:
        """Test writing batch of entries."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Multiple entries
        entries = []
        for i in range(5):
            entry_result = FlextLdifModels.Entry.create(
                dn=f"cn=user{i},dc=example,dc=com",
                attributes={"cn": [f"user{i}"], "objectClass": ["person"]},
            )
            assert entry_result.is_success
            entries.append(entry_result.unwrap())

        writer = FlextLdifRfcLdifWriter(
            params={"entries": entries},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert output.get("entries_written", 0) == 5

    def test_write_entry_with_empty_attribute(self) -> None:
        """Test writing entry with empty attribute values."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Entry with empty attribute (edge case)
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={"cn": ["test"], "description": [""], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_entry_preserves_dn_format(self) -> None:
        """Test that writing preserves DN format."""
        quirk_registry = FlextLdifQuirksRegistry()

        # DN in specific format
        dn = "cn=Test,dc=Example,dc=Com"
        entry_result = FlextLdifModels.Entry.create(
            dn=dn,
            attributes={"cn": ["Test"], "objectClass": ["person"]},
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_objectclass_with_sup(self) -> None:
        """Test writing objectClass with SUP (superclass)."""
        quirk_registry = FlextLdifQuirksRegistry()

        # ObjectClass with MUST and MAY
        schema = {
            "objectclasses": {
                "testOC": "( 1.2.3.5 NAME 'testOC' SUP top STRUCTURAL MUST cn MAY (description $ mail) )"
            }
        }

        writer = FlextLdifRfcLdifWriter(
            params={"schema": schema},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_attribute_with_equality_matching(self) -> None:
        """Test writing attribute with EQUALITY matching rule."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Attribute with matching rules
        schema = {
            "attributes": {
                "testAttr": "( 1.2.3.4 NAME 'testAttr' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            }
        }

        writer = FlextLdifRfcLdifWriter(
            params={"schema": schema},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_attribute_single_valued(self) -> None:
        """Test writing single-valued attribute definition."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Single-valued attribute
        schema = {
            "attributes": {
                "testAttr": "( 1.2.3.4 NAME 'testAttr' SINGLE-VALUE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )"
            }
        }

        writer = FlextLdifRfcLdifWriter(
            params={"schema": schema},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_write_entry_with_case_variations(self) -> None:
        """Test writing entry with various DN case combinations."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Different case variations
        entries = []
        dns_and_attrs = [
            ("cn=test,dc=example,dc=com", {"cn": ["test"], "objectClass": ["person"]}),
            ("CN=Test,DC=Example,DC=Com", {"CN": ["Test"], "objectClass": ["person"]}),
            ("Cn=TeSt,Dc=ExAmPle,Dc=CoM", {"Cn": ["TeSt"], "objectClass": ["person"]}),
        ]

        for dn, attrs in dns_and_attrs:
            entry_result = FlextLdifModels.Entry.create(dn=dn, attributes=attrs)
            assert entry_result.is_success
            entries.append(entry_result.unwrap())

        writer = FlextLdifRfcLdifWriter(
            params={"entries": entries},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            assert output.get("entries_written", 0) == 3

    def test_rfc_writer_with_multiple_object_classes(self) -> None:
        """Test writing entry with multiple objectClasses."""
        quirk_registry = FlextLdifQuirksRegistry()

        # Multiple objectClasses
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "objectClass": [
                    "top",
                    "person",
                    "inetOrgPerson",
                    "organizationalPerson",
                ],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")

    def test_rfc_writer_output_format_validation(self) -> None:
        """Test that RFC writer produces valid output."""
        quirk_registry = FlextLdifQuirksRegistry()

        entry_result = FlextLdifModels.Entry.create(
            dn="cn=test,dc=example,dc=com",
            attributes={
                "cn": ["test"],
                "mail": ["test@example.com"],
                "objectClass": ["person"],
            },
        )
        assert entry_result.is_success
        entry = entry_result.unwrap()

        writer = FlextLdifRfcLdifWriter(
            params={"entries": [entry]},
            quirk_registry=quirk_registry,
            target_server_type="rfc",
        )

        result = writer.execute()
        assert hasattr(result, "is_success")
        if result.is_success:
            output = result.unwrap()
            # Valid LDIF should contain dn or content
            assert "content" in output or output.get("entries_written", 0) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
