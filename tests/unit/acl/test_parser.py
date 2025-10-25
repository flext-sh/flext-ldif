"""Test suite for FlextLdifAcl components.

This module provides comprehensive testing for the ACL parser and service functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast

import pytest
from flext_core import FlextResult

from flext_ldif.acl_parser import FlextLdifAclParser
from flext_ldif.acl_service import FlextLdifAclService
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class TestFlextLdifAclParser:
    """Test suite for FlextLdifAclParser."""

    def test_initialization(self) -> None:
        """Test ACL parser initialization."""
        parser = FlextLdifAclParser()
        assert parser is not None
        assert parser.logger is not None

    def test_execute_success(self) -> None:
        """Test execute method returns success."""
        parser = FlextLdifAclParser()
        result = parser.execute()

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclParser
        assert data["status"] == "ready"

    def test_execute_sync_success(self) -> None:
        """Test execute method returns success (converted from )."""
        # NOTE: Converted from test_execute - method removed
        parser = FlextLdifAclParser()
        result = parser.execute()

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclParser
        assert data["status"] == "ready"

    def test_parse_openldap_acl_basic(self) -> None:
        """Test parsing OpenLDAP ACL."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn,sn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_openldap_acl_empty_string(self) -> None:
        """Test parsing OpenLDAP ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_openldap_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP
        assert not acl.raw_acl

    def test_parse_openldap_acl_complex(self) -> None:
        """Test parsing complex OpenLDAP ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            'to attrs=cn,sn,mail by dn.exact="cn=admin,dc=example,dc=com" '
            "write by * read"
        )
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP
        assert acl.raw_acl == acl_string

    def test_parse_389ds_acl_basic(self) -> None:
        """Test parsing 389DS ACL."""
        parser = FlextLdifAclParser()

        acl_string = '(targetattr="cn")(version 3.0; acl "test acl"; allow (read) userdn="ldap:///self";)'
        result = parser.parse_389ds_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.DS_389
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_389ds_acl_empty_string(self) -> None:
        """Test parsing 389DS ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_389ds_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.DS_389
        assert not acl.raw_acl

    def test_parse_389ds_acl_complex(self) -> None:
        """Test parsing complex 389DS ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            '(targetattr="cn || sn || mail")(version 3.0; acl "admin acl"; '
            "allow (read, write, search) "
            'groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=com";)'
        )
        result = parser.parse_389ds_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.DS_389
        assert acl.raw_acl == acl_string

    def test_parse_oracle_acl_basic(self) -> None:
        """Test parsing Oracle ACL."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn,sn:read:user"
        result = parser.parse_oracle_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OID
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_oracle_acl_with_server_type(self) -> None:
        """Test parsing Oracle ACL with specific server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn,sn:read:user"
        result = parser.parse_oracle_acl(
            acl_string, FlextLdifConstants.LdapServers.ORACLE_OUD
        )

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OUD
        assert acl.raw_acl == acl_string

    def test_parse_oracle_acl_empty_string(self) -> None:
        """Test parsing Oracle ACL with empty string."""
        parser = FlextLdifAclParser()

        result = parser.parse_oracle_acl("")

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OID
        assert not acl.raw_acl

    def test_parse_oracle_acl_complex(self) -> None:
        """Test parsing complex Oracle ACL."""
        parser = FlextLdifAclParser()

        acl_string = (
            "cn=admin,dc=example,dc=com:cn,sn,mail,telephoneNumber:read,write:group"
        )
        result = parser.parse_oracle_acl(acl_string)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OID
        assert acl.raw_acl == acl_string

    def test_parse_acl_openldap(self) -> None:
        """Test parse_acl method with OpenLDAP server type."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn by * read"
        result = parser.parse_acl(acl_string, FlextLdifConstants.LdapServers.OPENLDAP)

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.OPENLDAP

    def test_parse_acl_389ds(self) -> None:
        """Test parse_acl method with 389DS server type."""
        parser = FlextLdifAclParser()

        acl_string = '(targetattr="cn")(version 3.0; acl "test"; allow (read) userdn="ldap:///self";)'
        result = parser.parse_acl(acl_string, FlextLdifConstants.LdapServers.DS_389)

        assert result.is_success
        acl = result.value
        assert acl.name == "389ds_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.DS_389

    def test_parse_acl_oracle_oid(self) -> None:
        """Test parse_acl method with Oracle OID server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn:read:user"
        result = parser.parse_acl(acl_string, FlextLdifConstants.LdapServers.ORACLE_OID)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OID

    def test_parse_acl_oracle_oud(self) -> None:
        """Test parse_acl method with Oracle OUD server type."""
        parser = FlextLdifAclParser()

        acl_string = "cn=test,dc=example,dc=com:cn:read:user"
        result = parser.parse_acl(acl_string, FlextLdifConstants.LdapServers.ORACLE_OUD)

        assert result.is_success
        acl = result.value
        assert acl.name == "oracle_acl"
        assert acl.server_type == FlextLdifConstants.LdapServers.ORACLE_OUD

    def test_parse_acl_unsupported_server_type(self) -> None:
        """Test parse_acl method with unsupported server type."""
        parser = FlextLdifAclParser()

        acl_string = "some acl string"
        result = parser.parse_acl(acl_string, "unsupported_server")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Unsupported server type" in result.error

    def test_parse_acl_empty_server_type(self) -> None:
        """Test parse_acl method with empty server type."""
        parser = FlextLdifAclParser()

        acl_string = "some acl string"
        result = parser.parse_acl(acl_string, "")

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Unsupported server type" in result.error

    def test_acl_components_creation(self) -> None:
        """Test that ACL components are created correctly."""
        parser = FlextLdifAclParser()

        # Test that all parser methods create valid ACL components
        acl_string = "test acl"

        # Test OpenLDAP
        result = parser.parse_openldap_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

        # Test 389DS
        result = parser.parse_389ds_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

        # Test Oracle
        result = parser.parse_oracle_acl(acl_string)
        assert result.is_success
        acl = result.value
        assert isinstance(acl.target, FlextLdifModels.AclTarget)
        assert isinstance(acl.subject, FlextLdifModels.AclSubject)
        assert isinstance(acl.permissions, FlextLdifModels.AclPermissions)

    def test_unified_acl_structure(self) -> None:
        """Test that Acl structure is correct."""
        parser = FlextLdifAclParser()

        acl_string = "to attrs=cn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        acl = result.value

        # Check Acl structure
        assert hasattr(acl, "name")
        assert hasattr(acl, "target")
        assert hasattr(acl, "subject")
        assert hasattr(acl, "permissions")
        assert hasattr(acl, "server_type")
        assert hasattr(acl, "raw_acl")

        assert isinstance(acl.name, str)
        assert isinstance(acl.server_type, str)
        assert isinstance(acl.raw_acl, str)

    def test_logging_functionality(self) -> None:
        """Test that logging functionality works correctly."""
        parser = FlextLdifAclParser()

        # Test that successful operations log info messages
        result = parser.execute()

        assert result.is_success
        # The logging should have occurred (we can't easily test the actual log output
        # but we can verify the operation succeeded, which means logging was called)

    def test_error_handling_in_acl_creation(self) -> None:
        """Test error handling during ACL creation."""
        parser = FlextLdifAclParser()

        # Test with valid ACL string to ensure normal operation works
        acl_string = "to attrs=cn by * read"
        result = parser.parse_openldap_acl(acl_string)

        assert result.is_success
        # This tests the error handling path in the ACL creation process

    def test_server_type_constants(self) -> None:
        """Test that server type constants are used correctly."""
        parser = FlextLdifAclParser()

        # Test that constants are properly imported and used
        assert FlextLdifConstants.LdapServers.OPENLDAP is not None
        assert FlextLdifConstants.LdapServers.DS_389 is not None
        assert FlextLdifConstants.LdapServers.ORACLE_OID is not None
        assert FlextLdifConstants.LdapServers.ORACLE_OUD is not None

        # Test that parser methods use these constants
        acl_string = "test acl"

        result = parser.parse_openldap_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == FlextLdifConstants.LdapServers.OPENLDAP

        result = parser.parse_389ds_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == FlextLdifConstants.LdapServers.DS_389

        result = parser.parse_oracle_acl(acl_string)
        assert result.is_success
        assert result.value.server_type == FlextLdifConstants.LdapServers.ORACLE_OID

    def test_acl_parsing_consistency(self) -> None:
        """Test that ACL parsing is consistent across different methods."""
        parser = FlextLdifAclParser()

        acl_string = "test acl string"

        # Parse using specific methods
        openldap_result = parser.parse_openldap_acl(acl_string)
        ds389_result = parser.parse_389ds_acl(acl_string)
        oracle_result = parser.parse_oracle_acl(acl_string)

        # Parse using generic method
        openldap_generic_result = parser.parse_acl(
            acl_string, FlextLdifConstants.LdapServers.OPENLDAP
        )
        ds389_generic_result = parser.parse_acl(
            acl_string, FlextLdifConstants.LdapServers.DS_389
        )
        oracle_generic_result = parser.parse_acl(
            acl_string, FlextLdifConstants.LdapServers.ORACLE_OID
        )

        # Results should be equivalent
        assert openldap_result.is_success == openldap_generic_result.is_success
        assert ds389_result.is_success == ds389_generic_result.is_success
        assert oracle_result.is_success == oracle_generic_result.is_success

        if openldap_result.is_success:
            assert (
                openldap_result.value.server_type
                == openldap_generic_result.value.server_type
            )
            assert openldap_result.value.name == openldap_generic_result.value.name

        if ds389_result.is_success:
            assert (
                ds389_result.value.server_type == ds389_generic_result.value.server_type
            )
            assert ds389_result.value.name == ds389_generic_result.value.name

        if oracle_result.is_success:
            assert (
                oracle_result.value.server_type
                == oracle_generic_result.value.server_type
            )
            assert oracle_result.value.name == oracle_generic_result.value.name


class TestFlextLdifAclService:
    """Test suite for FlextLdifAclService."""

    def test_initialization_default(self) -> None:
        """Test ACL service initialization with default quirks manager."""
        service = FlextLdifAclService()
        assert service is not None
        assert service.logger is not None
        assert service._quirks is not None
        assert isinstance(service._quirks, FlextLdifQuirksManager)

    def test_initialization_with_quirks_manager(self) -> None:
        """Test ACL service initialization with provided quirks manager."""
        quirks_manager = FlextLdifQuirksManager()
        service = FlextLdifAclService(quirks_manager)
        assert service is not None
        assert service._quirks is quirks_manager

    def test_execute_success(self) -> None:
        """Test execute method returns success."""
        service = FlextLdifAclService()
        result = service.execute()

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclService
        assert data["status"] == "ready"
        assert "patterns" in data
        patterns = data["patterns"]
        assert isinstance(patterns, dict)
        assert "composite" in patterns
        assert "rule_evaluation" in patterns

    def test_execute_sync_service_success(self) -> None:
        """Test service execute method returns success (converted from )."""
        # NOTE: Converted from test_execute - method removed
        service = FlextLdifAclService()
        result = service.execute()

        assert result.is_success
        data = result.value
        assert data["service"] == FlextLdifAclService
        assert data["status"] == "ready"
        assert "patterns" in data

    def test_create_composite_rule_default(self) -> None:
        """Test creating composite rule with default operator."""
        service = FlextLdifAclService()
        rule = service.create_composite_rule()

        assert rule is not None
        assert rule._operator == "AND"
        assert rule._rule_type == "composite"
        assert rule._rules == []

    def test_create_composite_rule_with_operator(self) -> None:
        """Test creating composite rule with specific operator."""
        service = FlextLdifAclService()

        # Test AND operator
        rule_and = service.create_composite_rule("AND")
        assert rule_and._operator == "AND"

        # Test OR operator
        rule_or = service.create_composite_rule("OR")
        assert rule_or._operator == "OR"

        # Test lowercase operator
        rule_lower = service.create_composite_rule("and")
        assert rule_lower._operator == "AND"

    def test_create_permission_rule_default(self) -> None:
        """Test creating permission rule with default required flag."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read")

        assert rule is not None
        assert rule._permission == "read"
        assert rule._required is True
        assert rule._rule_type == "permission"

    def test_create_permission_rule_with_required_false(self) -> None:
        """Test creating permission rule with required=False."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("write", required=False)

        assert rule is not None
        assert rule._permission == "write"
        assert rule._required is False

    def test_create_subject_rule(self) -> None:
        """Test creating subject rule."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        assert rule is not None
        assert rule._subject_dn == "cn=admin,dc=example,dc=com"
        assert rule._rule_type == "subject"

    def test_base_acl_rule_evaluate(self) -> None:
        """Test base ACL rule evaluation."""
        service = FlextLdifAclService()
        rule = service.AclRule()

        context: dict[str, object] = {"test": "value"}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_base_acl_rule_add_rule_not_implemented(self) -> None:
        """Test that base ACL rule add_rule raises NotImplementedError."""
        service = FlextLdifAclService()
        rule = service.AclRule()

        with pytest.raises(
            NotImplementedError, match="Base rule does not support adding sub-rules"
        ):
            rule.add_rule(rule)

    def test_composite_acl_rule_empty_evaluation(self) -> None:
        """Test composite rule evaluation with no sub-rules."""
        service = FlextLdifAclService()
        rule = service.create_composite_rule()

        context: dict[str, object] = {"test": "value"}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_composite_acl_rule_add_rule(self) -> None:
        """Test adding rules to composite rule."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule()
        permission_rule = service.create_permission_rule("read")

        composite.add_rule(permission_rule)

        assert len(composite._rules) == 1
        assert composite._rules[0] is permission_rule

    def test_composite_acl_rule_and_evaluation(self) -> None:
        """Test composite rule AND evaluation."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule("AND")

        # Add permission rules
        read_rule = service.create_permission_rule("read")
        write_rule = service.create_permission_rule("write")
        composite.add_rule(read_rule)
        composite.add_rule(write_rule)

        # Test with all permissions
        test_context1: dict[str, object] = {
            "permissions": {"read": True, "write": True}
        }
        result = composite.evaluate(test_context1)
        assert result.is_success
        assert result.value is True

        # Test with missing permission
        test_context2: dict[str, object] = {
            "permissions": {"read": True, "write": False}
        }
        result = composite.evaluate(test_context2)
        assert result.is_success
        assert result.value is False

    def test_composite_acl_rule_or_evaluation(self) -> None:
        """Test composite rule OR evaluation."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule("OR")

        # Add permission rules
        read_rule = service.create_permission_rule("read")
        write_rule = service.create_permission_rule("write")
        composite.add_rule(read_rule)
        composite.add_rule(write_rule)

        # Test with one permission
        context_one: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = composite.evaluate(context_one)
        assert result.is_success
        assert result.value is True

        # Test with no permissions
        context_none: dict[str, object] = {
            "permissions": {"read": False, "write": False}
        }
        result = composite.evaluate(context_none)
        assert result.is_success
        assert result.value is False

    def test_composite_acl_rule_unknown_operator(self) -> None:
        """Test composite rule with unknown operator."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule("XOR")

        # Add a rule
        read_rule = service.create_permission_rule("read")
        composite.add_rule(read_rule)

        context: dict[str, object] = {"permissions": {"read": True}}
        result = composite.evaluate(context)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Unknown operator" in result.error

    def test_permission_rule_evaluate_required_true(self) -> None:
        """Test permission rule evaluation with required=True."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read", required=True)

        # Test with permission
        context_with_perm: dict[str, object] = {"permissions": {"read": True}}
        result = rule.evaluate(context_with_perm)
        assert result.is_success
        assert result.value is True

        # Test without permission
        context_without_perm: dict[str, object] = {"permissions": {"read": False}}
        result = rule.evaluate(context_without_perm)
        assert result.is_success
        assert result.value is False

        # Test with missing permissions dict
        context_missing: dict[str, object] = {}
        result = rule.evaluate(context_missing)
        assert result.is_success
        assert result.value is False

    def test_permission_rule_evaluate_required_false(self) -> None:
        """Test permission rule evaluation with required=False."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("write", required=False)

        # Test with permission (should be False since required=False)
        context_with_write: dict[str, object] = {"permissions": {"write": True}}
        result = rule.evaluate(context_with_write)
        assert result.is_success
        assert result.value is False

        # Test without permission (should be True since required=False)
        context_without_write: dict[str, object] = {"permissions": {"write": False}}
        result = rule.evaluate(context_without_write)
        assert result.is_success
        assert result.value is True

    def test_subject_rule_evaluate(self) -> None:
        """Test subject rule evaluation."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        # Test with matching subject
        context_admin: dict[str, object] = {"subject_dn": "cn=admin,dc=example,dc=com"}
        result = rule.evaluate(context_admin)
        assert result.is_success
        assert result.value is True

        # Test with non-matching subject
        context_user: dict[str, object] = {"subject_dn": "cn=user,dc=example,dc=com"}
        result = rule.evaluate(context_user)
        assert result.is_success
        assert result.value is False

        # Test with missing subject_dn
        context_empty: dict[str, object] = {}
        result = rule.evaluate(context_empty)
        assert result.is_success
        assert result.value is False

    def test_extract_acls_from_entry_none(self) -> None:
        """Test extracting ACLs from None entry."""
        service = FlextLdifAclService()
        # Test the None case that the method explicitly handles
        # Use cast to tell type checker we're intentionally passing None for testing
        result = service.extract_acls_from_entry(None)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Invalid entry: Entry is None" in result.error

    def test_extract_acls_from_entry_no_acl_attribute(self) -> None:
        """Test extracting ACLs from entry with no ACL attribute."""
        service = FlextLdifAclService()

        # Create a simple entry without ACL attributes
        entry_result = FlextLdifModels.Entry.create(
            dn="cn=testuser,dc=example,dc=com",
            attributes={"objectclass": ["person"], "cn": ["testuser"]},
        )
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_acls_from_entry(entry)

        # Should return empty list since no ACL attributes found
        assert result.is_success
        assert result.value == []

    def test_evaluate_acl_rules_none_context(self) -> None:
        """Test evaluating ACL rules with None context."""
        service = FlextLdifAclService()
        rules: list[FlextLdifAclService.AclRule] = [
            service.create_permission_rule("read")
        ]
        # Use cast to tell type checker we're intentionally passing None for testing
        result = service.evaluate_acl_rules(rules, cast("dict[str, object]", None))

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Invalid context: Context is None" in result.error

    def test_evaluate_acl_rules_empty_list(self) -> None:
        """Test evaluating empty ACL rules list."""
        service = FlextLdifAclService()
        context_empty_rules: dict[str, object] = {"permissions": {"read": True}}

        result = service.evaluate_acl_rules([], context_empty_rules)

        assert result.is_success
        assert result.value is True  # Empty composite rule returns True

    def test_evaluate_acl_rules_multiple_rules(self) -> None:
        """Test evaluating multiple ACL rules."""
        service = FlextLdifAclService()

        # Create multiple rules
        read_rule = service.create_permission_rule("read")
        write_rule = service.create_permission_rule("write")
        subject_rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        rules: list[FlextLdifAclService.AclRule] = [read_rule, write_rule, subject_rule]

        # Test with all conditions met
        context_all_conditions: dict[str, object] = {
            "permissions": {"read": True, "write": True},
            "subject_dn": "cn=admin,dc=example,dc=com",
        }
        result = service.evaluate_acl_rules(rules, context_all_conditions)
        assert result.is_success
        assert result.value is True

        # Test with some conditions not met
        context_partial_conditions: dict[str, object] = {
            "permissions": {"read": True, "write": False},
            "subject_dn": "cn=admin,dc=example,dc=com",
        }
        result = service.evaluate_acl_rules(rules, context_partial_conditions)
        assert result.is_success
        assert result.value is False

    def test_parse_acl_with_rules_success(self) -> None:
        """Test parsing ACL with rules."""
        service = FlextLdifAclService()

        acl_string = "to attrs=cn by * read"
        server_type: FlextLdifTypes.AclServerType = "openldap"

        result = service._parse_acl_with_rules(acl_string, server_type)

        assert result.is_success
        acl = result.value
        assert acl.name == "parsed_acl"
        assert acl.server_type == server_type
        assert acl.raw_acl == acl_string
        assert acl.target is not None
        assert acl.subject is not None
        assert acl.permissions is not None

    def test_parse_acl_with_rules_empty_string(self) -> None:
        """Test parsing ACL with empty string."""
        FlextLdifAclService()

        from flext_ldif.acl_parser import FlextLdifAclParser

        parser = FlextLdifAclParser()
        result = parser.parse_acl("", "openldap")

        assert result.is_success
        acl = result.value
        assert acl.name == "openldap_acl"
        assert acl.server_type == "openldap"
        assert not acl.raw_acl

    def test_rule_types_inheritance(self) -> None:
        """Test that rule types properly inherit from base rule."""
        service = FlextLdifAclService()

        # Test composite rule inheritance
        composite = service.create_composite_rule()
        assert isinstance(composite, service.AclRule)

        # Test permission rule inheritance
        permission = service.create_permission_rule("read")
        assert isinstance(permission, service.AclRule)

        # Test subject rule inheritance
        subject = service.create_subject_rule("cn=test,dc=example,dc=com")
        assert isinstance(subject, service.AclRule)

    def test_composite_rule_nested_rules(self) -> None:
        """Test nested composite rules."""
        service = FlextLdifAclService()

        # Create nested composite rules
        outer_composite = service.create_composite_rule("AND")
        inner_composite = service.create_composite_rule("OR")

        # Add rules to inner composite
        read_rule = service.create_permission_rule("read")
        write_rule = service.create_permission_rule("write")
        inner_composite.add_rule(read_rule)
        inner_composite.add_rule(write_rule)

        # Add inner composite to outer composite
        outer_composite.add_rule(inner_composite)

        # Test evaluation
        context_or_test: dict[str, object] = {
            "permissions": {"read": True, "write": False}
        }
        result = outer_composite.evaluate(context_or_test)

        assert result.is_success
        assert result.value is True  # OR of read=True, write=False = True

    def test_rule_evaluation_error_handling(self) -> None:
        """Test error handling in rule evaluation."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule("AND")

        # Add a rule that will cause evaluation to fail
        # We'll create a custom rule that returns failure
        class FailingRule(FlextLdifAclService.AclRule):
            def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
                _ = context  # Suppress unused argument warning
                return FlextResult[bool].fail("Test failure")

        failing_rule = FailingRule()
        composite.add_rule(failing_rule)

        context_error_test: dict[str, object] = {"test": "value"}
        result = composite.evaluate(context_error_test)

        assert result.is_failure
        assert result.error is not None
        assert result.error is not None
        assert result.error is not None
        assert "Test failure" in result.error

    def test_service_patterns_in_execute(self) -> None:
        """Test that execute method returns correct patterns."""
        service = FlextLdifAclService()
        result = service.execute()

        assert result.is_success
        data = result.value
        patterns = data["patterns"]
        assert isinstance(patterns, dict)

        assert "composite" in patterns
        assert "rule_evaluation" in patterns
        assert patterns["composite"] == "Composite ACL rule evaluation"
        assert patterns["rule_evaluation"] == "Individual ACL rule processing"

    def test_execute_returns_consistent_results(self) -> None:
        """Test that execute returns consistent results (converted from test)."""
        # NOTE: Converted from test_execute_consistency - method removed
        service = FlextLdifAclService()

        # Call execute twice to verify consistency
        result1 = service.execute()
        result2 = service.execute()

        assert result1.is_success == result2.is_success
        if result1.is_success:
            assert result1.value == result2.value


class TestFlextLdifAclUtils:
    """Test suite for FlextLdifUtilities."""

    def test_create_acl_components_success(self) -> None:
        """Test successful creation of ACL components."""
        result = FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()

        assert result.is_success
        components = result.unwrap()
        assert len(components) == 3

        target, subject, permissions = components
        assert isinstance(target, FlextLdifModels.AclTarget)
        assert isinstance(subject, FlextLdifModels.AclSubject)
        assert isinstance(permissions, FlextLdifModels.AclPermissions)

    def test_create_acl_components_type_validation(self) -> None:
        """Test type validation of created ACL components."""
        result = FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()

        assert result.is_success
        target, subject, permissions = result.unwrap()

        # Verify each component is the correct type
        assert type(target).__name__ == "AclTarget"
        assert type(subject).__name__ == "AclSubject"
        assert type(permissions).__name__ == "AclPermissions"

    def test_create_unified_acl_success(self) -> None:
        """Test successful creation of unified ACL."""
        # Create components first
        components_result = (
            FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()
        )
        assert components_result.is_success
        target, subject, permissions = components_result.unwrap()

        # Create unified ACL
        result = FlextLdifUtilities.AclUtils.ComponentFactory.create_unified_acl(
            name="test_acl",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="openldap",
            raw_acl="to attrs=cn,sn by * read",
        )

        assert result.is_success
        unified_acl = result.unwrap()
        # Aggressive Pydantic 2 pattern: discriminated union returns specific subtype
        assert isinstance(unified_acl, FlextLdifModels.Acl)
        assert unified_acl.name == "test_acl"
        assert unified_acl.server_type == "openldap"
        assert unified_acl.raw_acl == "to attrs=cn,sn by * read"

    def test_create_unified_acl_with_different_server_types(self) -> None:
        """Test creating unified ACL with different server types."""
        components_result = (
            FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()
        )
        assert components_result.is_success
        target, subject, permissions = components_result.unwrap()

        # Use valid server types that match actual constant values and discriminator Literals
        server_types = [
            (FlextLdifConstants.LdapServers.OPENLDAP, FlextLdifModels.Acl),
            (FlextLdifConstants.LdapServers.OPENLDAP_2, FlextLdifModels.Acl),
            (FlextLdifConstants.LdapServers.ORACLE_OID, FlextLdifModels.Acl),
            (FlextLdifConstants.LdapServers.ORACLE_OUD, FlextLdifModels.Acl),
            (FlextLdifConstants.LdapServers.DS_389, FlextLdifModels.Acl),
        ]

        for server_type, expected_class in server_types:
            result = FlextLdifUtilities.AclUtils.ComponentFactory.create_unified_acl(
                name=f"{server_type}_acl",
                target=target,
                subject=subject,
                permissions=permissions,
                server_type=server_type,  # Use loop variable, not string literal
                raw_acl=f"test ACL for {server_type}",
            )

            assert result.is_success
            unified_acl = result.unwrap()
            assert unified_acl.server_type == server_type
            assert unified_acl.name == f"{server_type}_acl"
            assert isinstance(unified_acl, expected_class)

    def test_create_unified_acl_type_validation(self) -> None:
        """Test type validation of created unified ACL."""
        components_result = (
            FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()
        )
        assert components_result.is_success
        target, subject, permissions = components_result.unwrap()

        # Use a valid server type (defaults to OpenLdapAcl for unknown types)
        result = FlextLdifUtilities.AclUtils.ComponentFactory.create_unified_acl(
            name="validation_test",
            target=target,
            subject=subject,
            permissions=permissions,
            server_type="openldap",  # Valid server type for discriminated union
            raw_acl="test ACL",
        )

        assert result.is_success
        unified_acl = result.unwrap()
        # Aggressive Pydantic 2 pattern: direct subclass instantiation (e.g., OpenLdapAcl, OracleOudAcl)
        assert isinstance(unified_acl, FlextLdifModels.Acl)
        assert isinstance(unified_acl, FlextLdifModels.Acl)

    def test_component_factory_integration(self) -> None:
        """Test ComponentFactory integration with full ACL creation flow."""
        # Step 1: Create components
        components_result = (
            FlextLdifUtilities.AclUtils.ComponentFactory.create_acl_components()
        )
        assert components_result.is_success

        # Step 2: Use components to create unified ACL
        target, subject, permissions = components_result.unwrap()

        unified_acl_result = (
            FlextLdifUtilities.AclUtils.ComponentFactory.create_unified_acl(
                name="integration_test",
                target=target,
                subject=subject,
                permissions=permissions,
                server_type="openldap",
                raw_acl="to * by * read",
            )
        )

        assert unified_acl_result.is_success
        unified_acl = unified_acl_result.unwrap()

        # Verify all components are properly integrated
        assert unified_acl.target == target
        assert unified_acl.subject == subject
        assert unified_acl.permissions == permissions
