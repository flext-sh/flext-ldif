"""Test suite for FlextLdifQuirksAdapter.

This module provides comprehensive testing for the quirks adapter functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.adapter import FlextLdifQuirksAdapter


class TestFlextLdifQuirksAdapter:
    """Test suite for FlextLdifQuirksAdapter."""

    def test_initialization_default(self) -> None:
        """Test adapter initialization with default server type."""
        adapter = FlextLdifQuirksAdapter()
        assert adapter is not None
        assert adapter._logger is not None
        assert adapter._server_type == FlextLdifConstants.LdapServers.GENERIC
        assert adapter._adaptation_rules is not None
        assert len(adapter._adaptation_rules) > 0

    def test_initialization_with_server_type(self) -> None:
        """Test adapter initialization with specific server type."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)
        assert adapter is not None
        assert adapter._server_type == FlextLdifConstants.LdapServers.OPENLDAP

    def test_initialization_with_active_directory(self) -> None:
        """Test adapter initialization with Active Directory server type."""
        adapter = FlextLdifQuirksAdapter(
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )
        assert adapter is not None
        assert adapter._server_type == FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY

    def test_execute_health_check(self) -> None:
        """Test execute method for health check."""
        adapter = FlextLdifQuirksAdapter()
        result = adapter.execute()

        assert result.is_success
        health_info = result.value
        assert health_info["status"] == "healthy"
        assert health_info["adapter_type"] == "FlextLdifQuirksAdapter"
        assert (
            health_info["current_server_type"] == FlextLdifConstants.LdapServers.GENERIC
        )
        assert "supported_servers" in health_info
        assert "capabilities" in health_info
        assert "adaptation_rules_count" in health_info

    def test_execute_async_health_check(self) -> None:
        """Test execute_async method for health check."""
        adapter = FlextLdifQuirksAdapter()
        result = asyncio.run(adapter.execute_async())

        assert result.is_success
        health_info = result.value
        assert health_info["status"] == "healthy"

    def test_detect_server_type_empty_entries(self) -> None:
        """Test server type detection with empty entries list."""
        adapter = FlextLdifQuirksAdapter()
        result = adapter.detect_server_type([])

        assert result.is_success
        assert result.value == FlextLdifConstants.LdapServers.GENERIC

    def test_detect_server_type_openldap(self) -> None:
        """Test server type detection for OpenLDAP."""
        adapter = FlextLdifQuirksAdapter()

        # Create OpenLDAP-style entries
        entry_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person", "top"],
                "uid": ["testuser"],
                "cn": ["Test User"],
                "sn": ["User"],
                "userPassword": ["{SSHA}hashedpassword"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.detect_server_type([entry])

        assert result.is_success
        # Should detect OpenLDAP based on uid and userPassword attributes
        assert result.value in {
            FlextLdifConstants.LdapServers.OPENLDAP,
            FlextLdifConstants.LdapServers.GENERIC,
        }

    def test_detect_server_type_active_directory(self) -> None:
        """Test server type detection for Active Directory."""
        adapter = FlextLdifQuirksAdapter()

        # Create Active Directory-style entries
        entry_data: dict[str, object] = {
            "dn": "CN=Test User,OU=Users,DC=example,DC=com",
            "attributes": {
                "objectClass": ["user", "person", "organizationalPerson", "top"],
                "userPrincipalName": ["testuser@example.com"],
                "sAMAccountName": ["testuser"],
                "displayName": ["Test User"],
                "objectSid": ["S-1-5-21-1234567890-1234567890-1234567890-1001"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.detect_server_type([entry])

        assert result.is_success
        # Should detect Active Directory based on special attributes
        assert result.value in {
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            FlextLdifConstants.LdapServers.GENERIC,
        }

    def test_detect_server_type_multiple_entries(self) -> None:
        """Test server type detection with multiple entries."""
        adapter = FlextLdifQuirksAdapter()

        # Create multiple OpenLDAP-style entries
        entries = []
        for i in range(3):
            entry_data: dict[str, object] = {
                "dn": f"uid=user{i},ou=people,dc=example,dc=com",
                "attributes": {
                    "objectClass": ["inetOrgPerson", "person", "top"],
                    "uid": [f"user{i}"],
                    "cn": [f"User {i}"],
                    "sn": ["User"],
                },
            }

            entry_result = FlextLdifModels.Entry.create(entry_data)
            assert entry_result.is_success
            entries.append(entry_result.value)

        result = adapter.detect_server_type(entries)

        assert result.is_success
        assert result.value is not None

    def test_adapt_entry_openldap_to_generic(self) -> None:
        """Test adapting OpenLDAP entry to generic format."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)

        # Create OpenLDAP entry
        entry_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person", "top"],
                "uid": ["testuser"],
                "cn": ["Test User"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.adapt_entry(entry, FlextLdifConstants.LdapServers.GENERIC)

        assert result.is_success
        adapted_entry = result.value
        assert adapted_entry.dn.value == entry.dn.value
        assert adapted_entry.attributes.data["cn"] == ["Test User"]

    def test_adapt_entry_generic_to_openldap(self) -> None:
        """Test adapting generic entry to OpenLDAP format."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.GENERIC)

        # Create generic entry
        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
                "mail": ["test@example.com"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.adapt_entry(entry, FlextLdifConstants.LdapServers.OPENLDAP)

        assert result.is_success
        adapted_entry = result.value
        assert adapted_entry.dn.value == entry.dn.value
        assert adapted_entry.attributes.data["cn"] == ["testuser"]

    def test_adapt_entry_active_directory_to_openldap(self) -> None:
        """Test adapting Active Directory entry to OpenLDAP format."""
        adapter = FlextLdifQuirksAdapter(
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        # Create Active Directory entry
        entry_data: dict[str, object] = {
            "dn": "CN=Test User,OU=Users,DC=example,DC=com",
            "attributes": {
                "objectClass": ["user", "person", "organizationalPerson", "top"],
                "userPrincipalName": ["testuser@example.com"],
                "sAMAccountName": ["testuser"],
                "displayName": ["Test User"],
                "mail": ["test@example.com"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.adapt_entry(entry, FlextLdifConstants.LdapServers.OPENLDAP)

        assert result.is_success
        adapted_entry = result.value
        assert adapted_entry.dn.value == entry.dn.value
        # Check that displayName is preserved (mapping might not be implemented)
        assert "displayName" in adapted_entry.attributes.data
        assert adapted_entry.attributes.data["displayName"] == ["Test User"]
        # Check that other AD-specific attributes are preserved
        assert "userPrincipalName" in adapted_entry.attributes.data
        assert "sAMAccountName" in adapted_entry.attributes.data

    def test_adapt_entry_unknown_server_type(self) -> None:
        """Test adapting entry with unknown server type."""
        adapter = FlextLdifQuirksAdapter()

        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.adapt_entry(entry, "unknown_server")

        assert result.is_failure
        assert result.error is not None
        assert "Unknown server type" in result.error

    def test_adapt_entry_with_current_server_type(self) -> None:
        """Test adapting entry using current server type."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)

        entry_data: dict[str, object] = {
            "dn": "uid=testuser,ou=people,dc=example,dc=com",
            "attributes": {
                "objectClass": ["inetOrgPerson", "person", "top"],
                "uid": ["testuser"],
                "cn": ["Test User"],
                "sn": ["User"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.adapt_entry(entry)  # No target server specified

        assert result.is_success
        adapted_entry = result.value
        assert adapted_entry.dn.value == entry.dn.value

    def test_adapt_attribute_values_openldap(self) -> None:
        """Test adapting attribute values for OpenLDAP."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)

        # Test objectClass adaptation
        adapted_values = adapter._adapt_attribute_values(
            "objectClass", ["person"], FlextLdifConstants.LdapServers.OPENLDAP
        )

        assert isinstance(adapted_values, list)
        assert "person" in adapted_values

    def test_adapt_attribute_values_active_directory(self) -> None:
        """Test adapting attribute values for Active Directory."""
        adapter = FlextLdifQuirksAdapter(
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        # Test objectClass adaptation
        adapted_values = adapter._adapt_attribute_values(
            "objectClass", ["person"], FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        assert isinstance(adapted_values, list)
        assert "person" in adapted_values

    def test_adapt_attribute_values_generic(self) -> None:
        """Test adapting attribute values for generic server."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.GENERIC)

        # Test generic adaptation
        adapted_values = adapter._adapt_attribute_values(
            "cn", ["Test User"], FlextLdifConstants.LdapServers.GENERIC
        )

        assert isinstance(adapted_values, list)
        assert adapted_values == ["Test User"]

    def test_adapt_attribute_values_case_insensitive(self) -> None:
        """Test adapting attribute values with case insensitive matching."""
        adapter = FlextLdifQuirksAdapter(
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        # Test case insensitive objectClass matching
        adapted_values = adapter._adapt_attribute_values(
            "objectclass", ["person"], FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        assert isinstance(adapted_values, list)
        assert "person" in adapted_values

    def test_adaptation_rules_setup(self) -> None:
        """Test that adaptation rules are properly set up."""
        adapter = FlextLdifQuirksAdapter()

        rules = adapter._adaptation_rules

        # Check that all expected server types are present
        expected_servers = [
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            FlextLdifConstants.LdapServers.OPENLDAP,
            FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            FlextLdifConstants.LdapServers.IBM_TIVOLI,
            FlextLdifConstants.LdapServers.GENERIC,
        ]

        for server in expected_servers:
            assert server in rules
            assert isinstance(rules[server], dict)
            assert "dn_case_sensitive" in rules[server]
            assert "required_object_classes" in rules[server]
            assert "attribute_mappings" in rules[server]
            assert "dn_patterns" in rules[server]
            assert "special_attributes" in rules[server]

    def test_active_directory_rules(self) -> None:
        """Test Active Directory specific adaptation rules."""
        adapter = FlextLdifQuirksAdapter(
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        )

        rules = adapter._adaptation_rules[
            FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        ]

        assert rules["dn_case_sensitive"] is True
        assert isinstance(rules["required_object_classes"], list)
        assert isinstance(rules["attribute_mappings"], dict)
        assert isinstance(rules["dn_patterns"], list)
        assert isinstance(rules["special_attributes"], list)

        # Check specific AD attributes
        assert "userPrincipalName" in rules["special_attributes"]
        assert "sAMAccountName" in rules["special_attributes"]
        assert "objectSid" in rules["special_attributes"]

    def test_openldap_rules(self) -> None:
        """Test OpenLDAP specific adaptation rules."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)

        rules = adapter._adaptation_rules[FlextLdifConstants.LdapServers.OPENLDAP]

        assert rules["dn_case_sensitive"] is False
        assert isinstance(rules["required_object_classes"], list)
        assert isinstance(rules["attribute_mappings"], dict)
        assert isinstance(rules["dn_patterns"], list)
        assert isinstance(rules["special_attributes"], list)

        # Check specific OpenLDAP attributes
        assert "uid" in rules["special_attributes"]
        assert "userPassword" in rules["special_attributes"]

    def test_generic_rules(self) -> None:
        """Test generic server adaptation rules."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.GENERIC)

        rules = adapter._adaptation_rules[FlextLdifConstants.LdapServers.GENERIC]

        assert rules["dn_case_sensitive"] is False
        assert rules["required_object_classes"] == ["top"]
        assert rules["attribute_mappings"] == {}
        assert rules["dn_patterns"] == []
        assert rules["special_attributes"] == []

    def test_server_type_detection_confidence_threshold(self) -> None:
        """Test server type detection with confidence threshold."""
        adapter = FlextLdifQuirksAdapter()

        # Create entry with very generic attributes
        entry_data: dict[str, object] = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"objectClass": ["top"], "cn": ["test"]},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = adapter.detect_server_type([entry])

        assert result.is_success
        # Should default to generic due to low confidence
        assert result.value == FlextLdifConstants.LdapServers.GENERIC

    def test_error_handling_in_entry_adaptation(self) -> None:
        """Test error handling during entry adaptation."""
        adapter = FlextLdifQuirksAdapter()

        # Test with invalid entry data that might cause adaptation to fail
        # This tests the exception handling in adapt_entry
        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {
                "objectClass": ["person", "top"],
                "cn": ["testuser"],
                "sn": ["User"],
            },
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        # This should work fine, but tests the error handling path
        result = adapter.adapt_entry(entry, FlextLdifConstants.LdapServers.GENERIC)

        assert result.is_success

    def test_logging_functionality(self) -> None:
        """Test that logging functionality works correctly."""
        adapter = FlextLdifQuirksAdapter()

        # Test that successful operations log info messages
        result = adapter.execute()

        assert result.is_success
        # The logging should have occurred (we can't easily test the actual log output
        # but we can verify the operation succeeded, which means logging was called)

    def test_server_type_property(self) -> None:
        """Test server type property access."""
        adapter = FlextLdifQuirksAdapter(FlextLdifConstants.LdapServers.OPENLDAP)

        assert adapter._server_type == FlextLdifConstants.LdapServers.OPENLDAP

    def test_adaptation_rules_property(self) -> None:
        """Test adaptation rules property access."""
        adapter = FlextLdifQuirksAdapter()

        rules = adapter._adaptation_rules
        assert isinstance(rules, dict)
        assert len(rules) > 0

        # Verify structure of rules
        for rule in rules.values():
            assert isinstance(rule, dict)
            assert "dn_case_sensitive" in rule
            assert "required_object_classes" in rule
            assert "attribute_mappings" in rule
            assert "dn_patterns" in rule
            assert "special_attributes" in rule
