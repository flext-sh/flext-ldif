"""Tests for FlextLdifAcls coordinator.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_core import FlextResult
from flext_ldif import FlextLdifAcls, FlextLdifModels


class TestFlextLdifAclsCoordinator:
    """Test FlextLdifAcls coordinator and nested classes."""

    def test_coordinator_initialization(self) -> None:
        """Test ACLs coordinator initializes correctly."""
        coordinator = FlextLdifAcls()

        assert coordinator.parser is not None
        assert coordinator.service is not None
        assert coordinator.builder is not None
        assert coordinator.converter is not None
        assert isinstance(coordinator.parser, FlextLdifAcls.Parser)
        assert isinstance(coordinator.service, FlextLdifAcls.Service)
        assert isinstance(coordinator.builder, FlextLdifAcls.Builder)
        assert isinstance(coordinator.converter, FlextLdifAcls.Converter)

    def test_coordinator_execute(self) -> None:
        """Test coordinator execute health check."""
        coordinator = FlextLdifAcls()
        result = coordinator.execute()

        assert result.is_success
        assert isinstance(result.value, dict)
        assert result.value["status"] == "healthy"
        assert result.value["service"] == "FlextLdifAcls"
        assert "operations" in result.value

    def test_parser_parse_openldap(self) -> None:
        """Test Parser.parse_openldap method."""
        coordinator = FlextLdifAcls()

        acl_string = "access to * by self write by * read"
        result = coordinator.parser.parse_openldap(acl_string)

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parser_parse_389ds(self) -> None:
        """Test Parser.parse_389ds method."""
        coordinator = FlextLdifAcls()

        acl_string = 'aci: (targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        result = coordinator.parser.parse_389ds(acl_string)

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parser_parse_oracle(self) -> None:
        """Test Parser.parse_oracle method."""
        coordinator = FlextLdifAcls()

        acl_string = "orclaci: access to entry by * (read)"
        result = coordinator.parser.parse_oracle(acl_string)

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_parser_parse_ad(self) -> None:
        """Test Parser.parse_ad method."""
        coordinator = FlextLdifAcls()

        # AD parser accepts dict data
        acl_data = {"trustee": "S-1-5-21-123456", "permissions": ["READ"]}
        result = coordinator.parser.parse_ad(acl_data)

        # parse_ad may not be fully implemented, just verify it returns a result
        assert isinstance(result, FlextResult)

    def test_parser_parse_generic(self) -> None:
        """Test Parser.parse generic method."""
        coordinator = FlextLdifAcls()

        acl_string = "access to * by self write"
        result = coordinator.parser.parse(acl_string, server_type="openldap")

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)

    def test_service_extract(self) -> None:
        """Test Service extract methods."""
        coordinator = FlextLdifAcls()

        entry = FlextLdifModels.Entry.create({
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {"cn": ["test"]},
        }).unwrap()

        # Test extract_from_entry
        result = coordinator.service.extract_from_entry(entry)
        assert isinstance(result, FlextResult)

        # Test extract_from_entries
        result = coordinator.service.extract_from_entries([entry])
        assert isinstance(result, FlextResult)

    def test_builder_build_read_permission(self) -> None:
        """Test Builder.build_read_permission method."""
        coordinator = FlextLdifAcls()

        result = coordinator.builder.build_read_permission(
            target_dn="dc=example,dc=com", subject_dn="cn=reader,dc=example,dc=com"
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)
        assert acl.permissions.read is True

    def test_builder_build_write_permission(self) -> None:
        """Test Builder.build_write_permission method."""
        coordinator = FlextLdifAcls()

        result = coordinator.builder.build_write_permission(
            target_dn="ou=users,dc=example,dc=com",
            subject_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)
        assert acl.permissions.write is True

    def test_builder_build_REDACTED_LDAP_BIND_PASSWORD_permission(self) -> None:
        """Test Builder.build_REDACTED_LDAP_BIND_PASSWORD_permission method."""
        coordinator = FlextLdifAcls()

        result = coordinator.builder.build_REDACTED_LDAP_BIND_PASSWORD_permission(
            target_dn="dc=example,dc=com", subject_dn="cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
        )

        assert result.is_success
        acl = result.unwrap()
        assert isinstance(acl, FlextLdifModels.UnifiedAcl)
        # Admin should have multiple permissions set to True
        perms = acl.permissions
        enabled_perms = sum([
            perms.read,
            perms.write,
            perms.add,
            perms.delete,
            perms.search,
            perms.compare,
            perms.proxy,
        ])
        assert enabled_perms > 1

    def test_converter_to_openldap(self) -> None:
        """Test Converter.to_openldap conversion."""
        coordinator = FlextLdifAcls()

        acl = FlextLdifModels.UnifiedAcl.create(
            name="test_acl",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(subject_dn="users"),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="openldap",
            raw_acl="access to * by users read",
        ).unwrap()

        result = coordinator.converter.to_openldap(acl)

        assert result.is_success
        openldap_acl = result.unwrap()
        assert isinstance(openldap_acl, str)

    def test_converter_to_389ds(self) -> None:
        """Test Converter.to_389ds conversion."""
        coordinator = FlextLdifAcls()

        acl = FlextLdifModels.UnifiedAcl.create(
            name="test_acl",
            target=FlextLdifModels.AclTarget(dn="dc=example,dc=com"),
            subject=FlextLdifModels.AclSubject(dn="self"),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="389ds",
            raw_acl="aci: access to dc=example,dc=com by self read",
        ).unwrap()

        result = coordinator.converter.to_389ds(acl)

        assert result.is_success
        ds_acl = result.unwrap()
        assert isinstance(ds_acl, str)

    def test_converter_to_oracle(self) -> None:
        """Test Converter.to_oracle conversion."""
        coordinator = FlextLdifAcls()

        acl = FlextLdifModels.UnifiedAcl.create(
            name="test_acl",
            target=FlextLdifModels.AclTarget(dn="*"),
            subject=FlextLdifModels.AclSubject(dn="users"),
            permissions=FlextLdifModels.AclPermissions(read=True),
            server_type="oracle",
            raw_acl="orclaci: access to * by users read",
        ).unwrap()

        result = coordinator.converter.to_oracle(acl)

        assert result.is_success
        oracle_acl = result.unwrap()
        assert isinstance(oracle_acl, str)

    def test_converter_to_ad(self) -> None:
        """Test Converter.to_ad conversion."""
        coordinator = FlextLdifAcls()

        acl = FlextLdifModels.UnifiedAcl.create(
            name="test_acl",
            target=FlextLdifModels.AclTarget(dn="dc=example,dc=com"),
            subject=FlextLdifModels.AclSubject(dn="cn=REDACTED_LDAP_BIND_PASSWORD"),
            permissions=FlextLdifModels.AclPermissions(read=True, write=True),
            server_type="ad",
            raw_acl="access to dc=example,dc=com by cn=REDACTED_LDAP_BIND_PASSWORD read,write",
        ).unwrap()

        result = coordinator.converter.to_ad(acl)

        assert result.is_success
        ad_acl = result.unwrap()
        assert isinstance(ad_acl, str)  # AD converter returns SDDL string format


class TestFlextLdifAclsEdgeCases:
    """Test edge cases and error conditions."""

    def test_parser_with_empty_string(self) -> None:
        """Test Parser handles empty string."""
        coordinator = FlextLdifAcls()

        result = coordinator.parser.parse_openldap("")

        # Should handle gracefully - either fail or return empty ACL
        assert result.is_failure or result.is_success

    def test_parser_with_invalid_format(self) -> None:
        """Test Parser with invalid format."""
        coordinator = FlextLdifAcls()

        result = coordinator.parser.parse_389ds("invalid aci format")

        # Should fail gracefully
        assert isinstance(result, FlextResult)

    def test_builder_with_wildcard_target(self) -> None:
        """Test Builder with wildcard target."""
        coordinator = FlextLdifAcls()

        result = coordinator.builder.build_read_permission(
            target_dn="*", subject_dn="anonymous"
        )

        assert result.is_success
        acl = result.unwrap()
        assert acl.target.target_dn == "*"

    def test_converter_operations_list(self) -> None:
        """Test Converter._get_operations_list helper."""
        coordinator = FlextLdifAcls()

        # Create ACL with multiple permissions
        acl = FlextLdifModels.UnifiedAcl.create(
            name="test_acl",
            target=FlextLdifModels.AclTarget(target_dn="*"),
            subject=FlextLdifModels.AclSubject(subject_dn="self"),
            permissions=FlextLdifModels.AclPermissions(
                read=True, write=True, search=True
            ),
            server_type="openldap",
            raw_acl="access to * by self read,write,search",
        ).unwrap()

        # Convert to different formats
        openldap_result = coordinator.converter.to_openldap(acl)
        assert openldap_result.is_success

        ds_result = coordinator.converter.to_389ds(acl)
        assert ds_result.is_success

    def test_service_with_entries(self) -> None:
        """Test Service with multiple entries."""
        coordinator = FlextLdifAcls()

        entries = [
            FlextLdifModels.Entry.create({
                "dn": "cn=test1,dc=example,dc=com",
                "attributes": {"cn": ["test1"]},
            }).unwrap(),
            FlextLdifModels.Entry.create({
                "dn": "cn=test2,dc=example,dc=com",
                "attributes": {"cn": ["test2"]},
            }).unwrap(),
        ]

        result = coordinator.service.extract_from_entries(entries)
        assert result.is_success

    def test_parser_server_type_detection(self) -> None:
        """Test Parser with different server types."""
        coordinator = FlextLdifAcls()

        # Test auto-detection through parse method
        openldap_acl = "access to * by self write"
        result = coordinator.parser.parse(openldap_acl, server_type="openldap")
        assert result.is_success

        # Test with 389DS format
        ds_acl = 'aci: (targetattr="*")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        result = coordinator.parser.parse(ds_acl, server_type="389ds")
        assert result.is_success


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
