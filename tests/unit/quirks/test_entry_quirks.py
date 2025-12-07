"""Tests for entry-level quirks and server-specific transformations.

This module tests the entry quirks that apply server-specific transformations
and enhancements to LDIF entries during parsing and writing operations.
"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif.services.dn import FlextLdifDn
from flext_ldif.services.entries import FlextLdifEntries
from tests import m, s


class TestsTestFlextLdifEntriesInitialization(s):
    """Test suite for entry quirks initialization."""

    def test_initialization_default(self) -> None:
        """Test entry service initialization."""
        service = FlextLdifEntries()

        assert service is not None
        # FlextLdifEntries doesn't expose operation or entries as public attributes
        # It uses private _operation and _entries
        assert hasattr(service, "execute")
        assert hasattr(service, "remove_operational_attributes")

    def test_initialization_has_execute_method(self) -> None:
        """Test entry service execute method exists."""
        service = FlextLdifEntries()
        result = service.execute()

        assert result is not None
        assert isinstance(result, FlextResult)


class TestDnCleaning:
    """Test suite for DN cleaning functionality."""

    def test_clean_dn_simple(self) -> None:
        """Test cleaning a simple DN."""
        dn = "cn=test,dc=example,dc=com"
        cleaned = FlextLdifDn.Normalizer.clean_dn(dn)

        assert isinstance(cleaned, str)
        assert "cn=" in cleaned
        assert "dc=" in cleaned

    def test_clean_dn_with_spaces(self) -> None:
        """Test cleaning DN with spaces around equals."""
        dn = "cn = test , dc = example , dc = com"
        cleaned = FlextLdifDn.Normalizer.clean_dn(dn)

        # Should normalize spaces
        assert isinstance(cleaned, str)
        # Should contain the RDN components
        assert "cn" in cleaned.lower()
        assert "dc" in cleaned.lower()

    def test_clean_dn_preserves_value(self) -> None:
        """Test that cleaning preserves DN values."""
        dn = "cn=John Doe,ou=Users,dc=example,dc=com"
        cleaned = FlextLdifDn.Normalizer.clean_dn(dn)

        assert "john" in cleaned.lower()
        assert "doe" in cleaned.lower()
        assert "users" in cleaned.lower()


class TestEntryAdaptation:
    """Test suite for entry adaptation functionality."""

    def _create_entry(
        self,
        dn_string: str,
        attributes: dict[str, list[str]],
    ) -> m.Entry:
        """Helper to create entry with DN and attributes."""
        dn = m.DistinguishedName(value=dn_string)
        ldif_attributes = m.LdifAttributes(attributes=attributes)
        entry_result = m.Entry.create(dn=dn, attributes=ldif_attributes)
        assert entry_result.is_success
        return entry_result.unwrap()

    def test_adapt_entry_generic_server(self) -> None:
        """Test adapting entry for generic LDAP server."""
        quirks = FlextLdifEntries()

        # Create test entry
        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["person", "top"],
                "mail": ["test@example.com"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("objectClass")

    def test_adapt_entry_oid_server(self) -> None:
        """Test adapting entry for OID server."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["person", "top"],
                "sn": ["Test"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("sn")

    def test_adapt_entry_oud_server(self) -> None:
        """Test adapting entry for OUD server."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["person"],
                "uid": ["testuser"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("uid")

    def test_adapt_entry_openldap_server(self) -> None:
        """Test adapting entry for OpenLDAP server."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "objectClass": ["inetOrgPerson"],
                "mail": ["test@example.com"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("mail")

    def test_adapt_entry_with_operational_attrs(self) -> None:
        """Test that adapt_entry handles operational attributes."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "mail": ["test@example.com"],
                "createTimestamp": ["20250113100000Z"],
                "modifyTimestamp": ["20250113100000Z"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        # User attributes preserved
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("mail")
        # COMMON operational attributes stripped
        assert not adapted.has_attribute("createTimestamp")
        assert not adapted.has_attribute("modifyTimestamp")

    def test_adapt_entry_case_insensitive_operational_attrs(self) -> None:
        """Test case-insensitive operational attribute stripping."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {
                "cn": ["test"],
                "CreateTimestamp": ["20250113100000Z"],
                "MODIFYTIMESTAMP": ["20250113100000Z"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        # User attributes preserved
        assert adapted.has_attribute("cn")
        # Case-insensitive stripping of operational attributes
        assert not adapted.has_attribute("CreateTimestamp")
        assert not adapted.has_attribute("MODIFYTIMESTAMP")

    def test_adapt_entry_returns_flext_result(self) -> None:
        """Test that adapt_entry returns proper FlextResult."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=test,dc=example,dc=com",
            {"cn": ["test"]},
        )

        result = quirks.remove_operational_attributes(entry)

        # Should return FlextResult
        assert hasattr(result, "is_success")
        assert hasattr(result, "is_failure")
        assert hasattr(result, "value")
        assert hasattr(result, "error")
        assert hasattr(result, "unwrap")

    def test_adapt_entry_preserves_user_attributes(self) -> None:
        """Test that all user attributes are preserved."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=John Doe,ou=Users,dc=example,dc=com",
            {
                "cn": ["John Doe"],
                "sn": ["Doe"],
                "givenName": ["John"],
                "mail": ["john@example.com"],
                "uid": ["jdoe"],
                "userPassword": ["{SSHA}base64data"],
                "objectClass": ["inetOrgPerson", "person", "top"],
                "telephoneNumber": ["+1-555-1234"],
                "title": ["Engineer"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()

        # All user attributes should be preserved
        for attr in [
            "cn",
            "sn",
            "givenName",
            "mail",
            "uid",
            "userPassword",
            "objectClass",
            "telephoneNumber",
            "title",
        ]:
            assert adapted.has_attribute(attr), f"User attribute {attr} was stripped"

    def test_adapt_entry_empty_entry(self) -> None:
        """Test adapting an entry with minimal attributes."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=minimal,dc=example,dc=com",
            {
                "cn": ["minimal"],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")

    def test_adapt_entry_multiple_values(self) -> None:
        """Test adapting entry with multi-valued attributes."""
        quirks = FlextLdifEntries()

        entry = self._create_entry(
            "cn=user,dc=example,dc=com",
            {
                "cn": ["user"],
                "mail": ["user@example.com", "user.work@example.com"],
                "objectClass": [
                    "inetOrgPerson",
                    "organizationalPerson",
                    "person",
                    "top",
                ],
            },
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.has_attribute("cn")
        assert adapted.has_attribute("mail")
        assert adapted.has_attribute("objectClass")

    def test_adapt_entry_preserves_dn(self) -> None:
        """Test that adaptation preserves the DN."""
        quirks = FlextLdifEntries()

        original_dn = "cn=test,ou=Users,dc=example,dc=com"
        entry = self._create_entry(
            original_dn,
            {"cn": ["test"]},
        )

        result = quirks.remove_operational_attributes(entry)

        assert result.is_success
        adapted = result.unwrap()
        assert adapted.dn.value.lower() == original_dn.lower()
