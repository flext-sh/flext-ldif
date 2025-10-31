"""Unit tests for Operational Attributes Service - RFC 4512 Validation and Filtering.

Comprehensive testing of FlextLdifOperationalService for operational attribute
identification, server-specific filtering, and RFC 4512 compliance.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_ldif.services.operational import FlextLdifOperationalService


class TestOperationalServiceInitialization:
    """Test Operational service initialization and status checking."""

    def test_service_initialization(self) -> None:
        """Test Operational service can be instantiated."""
        service = FlextLdifOperationalService()
        assert service is not None

    def test_execute_returns_status(self) -> None:
        """Test execute returns service status."""
        service = FlextLdifOperationalService()
        result = service.execute()

        assert result.is_success
        status = result.unwrap()
        assert status["service"] == "OperationalService"
        assert status["status"] == "operational"
        assert status["rfc_compliance"] == "RFC 4512"
        assert status["common_operational_attributes"] > 0
        assert status["oid_specific_attributes"] > 0
        assert status["oud_specific_attributes"] > 0


class TestCommonOperationalAttributes:
    """Test RFC 4512 common operational attributes."""

    def test_common_operational_attributes_accessible(self) -> None:
        """Test common operational attributes can be retrieved."""
        service = FlextLdifOperationalService()
        result = service.get_common_operational_attributes()

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, frozenset)
        assert len(attrs) > 0

    def test_create_timestamp_is_operational(self) -> None:
        """Test that createTimestamp is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("createTimestamp")

        assert result.is_success
        assert result.unwrap() is True

    def test_creators_name_is_operational(self) -> None:
        """Test that creatorsName is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("creatorsName")

        assert result.is_success
        assert result.unwrap() is True

    def test_modify_timestamp_is_operational(self) -> None:
        """Test that modifyTimestamp is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("modifyTimestamp")

        assert result.is_success
        assert result.unwrap() is True

    def test_modifiers_name_is_operational(self) -> None:
        """Test that modifiersName is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("modifiersName")

        assert result.is_success
        assert result.unwrap() is True

    def test_entry_uuid_is_operational(self) -> None:
        """Test that entryUUID is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("entryUUID")

        assert result.is_success
        assert result.unwrap() is True

    def test_entry_csn_is_operational(self) -> None:
        """Test that entryCSN is recognized as operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("entryCSN")

        assert result.is_success
        assert result.unwrap() is True

    def test_regular_attribute_not_operational(self) -> None:
        """Test that regular user attributes are not operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("cn")

        assert result.is_success
        assert result.unwrap() is False

    def test_mail_not_operational(self) -> None:
        """Test that mail attribute is not operational."""
        service = FlextLdifOperationalService()
        result = service.is_operational("mail")

        assert result.is_success
        assert result.unwrap() is False

    def test_empty_attribute_name_not_operational(self) -> None:
        """Test that empty attribute name returns False."""
        service = FlextLdifOperationalService()
        result = service.is_operational("")

        assert result.is_success
        assert result.unwrap() is False


class TestServerSpecificOperationalAttributes:
    """Test server-specific operational attribute detection."""

    def test_oid_specific_attributes(self) -> None:
        """Test OID-specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("orclGUID", "oid")

        assert result.is_success
        assert result.unwrap() is True

    def test_oud_specific_attributes(self) -> None:
        """Test OUD-specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("ds-sync-hist", "oud")

        assert result.is_success
        assert result.unwrap() is True

    def test_openldap_specific_attributes(self) -> None:
        """Test OpenLDAP-specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("contextCSN", "openldap")

        assert result.is_success
        assert result.unwrap() is True

    def test_ds389_specific_attributes(self) -> None:
        """Test 389 Directory Server specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("nsUniqueId", "ds389")

        assert result.is_success
        assert result.unwrap() is True

    def test_ad_specific_attributes(self) -> None:
        """Test Active Directory specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("objectGUID", "ad")

        assert result.is_success
        assert result.unwrap() is True

    def test_novell_specific_attributes(self) -> None:
        """Test Novell eDirectory specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("GUID", "novell")

        assert result.is_success
        assert result.unwrap() is True

    def test_tivoli_specific_attributes(self) -> None:
        """Test IBM Tivoli specific operational attributes."""
        service = FlextLdifOperationalService()
        result = service.is_operational_for_server("ibm-entryUUID", "tivoli")

        assert result.is_success
        assert result.unwrap() is True

    def test_common_attributes_operational_for_all_servers(self) -> None:
        """Test that common operational attributes work for all servers."""
        service = FlextLdifOperationalService()
        servers = ["oid", "oud", "openldap", "ds389", "ad", "novell", "tivoli", "rfc"]

        for server in servers:
            result = service.is_operational_for_server("createTimestamp", server)
            assert result.is_success
            assert result.unwrap() is True

    def test_server_type_case_insensitive(self) -> None:
        """Test that server type matching is case-insensitive."""
        service = FlextLdifOperationalService()
        result_lower = service.is_operational_for_server("createTimestamp", "oud")
        result_upper = service.is_operational_for_server("createTimestamp", "OUD")

        assert result_lower.is_success
        assert result_upper.is_success
        assert result_lower.unwrap() == result_upper.unwrap()


class TestServerOperationalAttributesList:
    """Test retrieving all operational attributes for specific servers."""

    def test_get_common_operational_attributes_list(self) -> None:
        """Test getting list of common operational attributes."""
        service = FlextLdifOperationalService()
        result = service.get_common_operational_attributes()

        assert result.is_success
        attrs = result.unwrap()
        assert isinstance(attrs, frozenset)
        assert "createTimestamp" in attrs
        assert "modifyTimestamp" in attrs
        assert "creatorsName" in attrs
        assert "modifiersName" in attrs

    def test_get_oid_server_operational_attributes(self) -> None:
        """Test getting OID server operational attributes."""
        service = FlextLdifOperationalService()
        result = service.get_server_operational_attributes("oid")

        assert result.is_success
        attrs = result.unwrap()
        # Should include both common and OID-specific
        assert "createTimestamp" in attrs
        assert "orclGUID" in attrs

    def test_get_oud_server_operational_attributes(self) -> None:
        """Test getting OUD server operational attributes."""
        service = FlextLdifOperationalService()
        result = service.get_server_operational_attributes("oud")

        assert result.is_success
        attrs = result.unwrap()
        # Should include both common and OUD-specific
        assert "createTimestamp" in attrs
        assert "ds-sync-hist" in attrs

    def test_get_openldap_server_operational_attributes(self) -> None:
        """Test getting OpenLDAP server operational attributes."""
        service = FlextLdifOperationalService()
        result = service.get_server_operational_attributes("openldap")

        assert result.is_success
        attrs = result.unwrap()
        # Should include both common and OpenLDAP-specific
        assert "createTimestamp" in attrs
        assert "contextCSN" in attrs

    def test_rfc_mode_has_only_common(self) -> None:
        """Test that RFC mode includes only common operational attributes."""
        service = FlextLdifOperationalService()
        result = service.get_server_operational_attributes("rfc")

        assert result.is_success
        attrs = result.unwrap()
        # Should include common
        assert "createTimestamp" in attrs
        # Should NOT include server-specific
        assert "orclGUID" not in attrs
        assert "ds-sync-hist" not in attrs


class TestAttributeFiltering:
    """Test filtering operational attributes from entry attributes."""

    def test_filter_empty_attributes(self) -> None:
        """Test filtering empty attribute dictionary."""
        service = FlextLdifOperationalService()
        result = service.filter_operational_attributes({})

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == 0

    def test_filter_removes_create_timestamp(self) -> None:
        """Test that createTimestamp is filtered out."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["John Doe"],
            "mail": ["john@example.com"],
            "createTimestamp": ["20250101120000Z"],
        }
        result = service.filter_operational_attributes(attrs)

        assert result.is_success
        filtered = result.unwrap()
        assert "cn" in filtered
        assert "mail" in filtered
        assert "createTimestamp" not in filtered

    def test_filter_removes_multiple_operational(self) -> None:
        """Test that multiple operational attributes are filtered."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["John Doe"],
            "createTimestamp": ["20250101120000Z"],
            "modifyTimestamp": ["20250102120000Z"],
            "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            "modifiersName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
        }
        result = service.filter_operational_attributes(attrs)

        assert result.is_success
        filtered = result.unwrap()
        assert "cn" in filtered
        assert "createTimestamp" not in filtered
        assert "modifyTimestamp" not in filtered
        assert "creatorsName" not in filtered
        assert "modifiersName" not in filtered

    def test_filter_preserves_user_attributes(self) -> None:
        """Test that user attributes are preserved."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["Test User"],
            "sn": ["User"],
            "givenName": ["Test"],
            "mail": ["test@example.com"],
            "telephoneNumber": ["+1234567890"],
        }
        result = service.filter_operational_attributes(attrs)

        assert result.is_success
        filtered = result.unwrap()
        assert len(filtered) == len(attrs)
        assert filtered == attrs

    def test_filter_with_oud_server_type(self) -> None:
        """Test filtering with OUD server-specific operational attributes."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["Test"],
            "ds-sync-hist": ["some-history"],
            "ds-pwp-account-disabled": ["FALSE"],
            "createTimestamp": ["20250101120000Z"],
        }
        result = service.filter_operational_attributes(attrs, "oud")

        assert result.is_success
        filtered = result.unwrap()
        assert "cn" in filtered
        assert "ds-sync-hist" not in filtered
        assert "ds-pwp-account-disabled" not in filtered
        assert "createTimestamp" not in filtered

    def test_filter_with_oid_server_type(self) -> None:
        """Test filtering with OID server-specific operational attributes."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["Test"],
            "orclGUID": ["some-guid"],
            "createTimestamp": ["20250101120000Z"],
        }
        result = service.filter_operational_attributes(attrs, "oid")

        assert result.is_success
        filtered = result.unwrap()
        assert "cn" in filtered
        assert "orclGUID" not in filtered
        assert "createTimestamp" not in filtered


class TestOperationalAttributeCount:
    """Test counting operational attributes in entries."""

    def test_count_no_operational_attributes(self) -> None:
        """Test counting when no operational attributes present."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["John Doe"],
            "mail": ["john@example.com"],
        }
        result = service.get_operational_attribute_count(attrs)

        assert result.is_success
        assert result.unwrap() == 0

    def test_count_single_operational_attribute(self) -> None:
        """Test counting single operational attribute."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["John Doe"],
            "createTimestamp": ["20250101120000Z"],
        }
        result = service.get_operational_attribute_count(attrs)

        assert result.is_success
        assert result.unwrap() == 1

    def test_count_multiple_operational_attributes(self) -> None:
        """Test counting multiple operational attributes."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["John Doe"],
            "createTimestamp": ["20250101120000Z"],
            "modifyTimestamp": ["20250102120000Z"],
            "creatorsName": ["cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"],
            "entryUUID": ["some-uuid"],
        }
        result = service.get_operational_attribute_count(attrs)

        assert result.is_success
        assert result.unwrap() == 4

    def test_count_with_server_type(self) -> None:
        """Test counting with OUD server-specific attributes."""
        service = FlextLdifOperationalService()
        attrs = {
            "cn": ["Test"],
            "ds-sync-hist": ["some-history"],
            "ds-pwp-account-disabled": ["FALSE"],
            "createTimestamp": ["20250101120000Z"],
        }
        result = service.get_operational_attribute_count(attrs, "oud")

        assert result.is_success
        # Should count: ds-sync-hist, ds-pwp-account-disabled, createTimestamp
        assert result.unwrap() == 3

    def test_count_empty_attributes(self) -> None:
        """Test counting operational attributes in empty dictionary."""
        service = FlextLdifOperationalService()
        result = service.get_operational_attribute_count({})

        assert result.is_success
        assert result.unwrap() == 0


class TestMultipleServices:
    """Test multiple service instances are independent."""

    def test_multiple_service_instances(self) -> None:
        """Test that multiple service instances don't interfere."""
        service1 = FlextLdifOperationalService()
        service2 = FlextLdifOperationalService()

        result1 = service1.is_operational("createTimestamp")
        result2 = service2.is_operational("createTimestamp")

        assert result1.is_success
        assert result2.is_success
        assert result1.unwrap() is True
        assert result2.unwrap() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
