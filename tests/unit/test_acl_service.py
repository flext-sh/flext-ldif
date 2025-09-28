"""Test suite for FlextLdifAclService.

This module provides comprehensive testing for the ACL service functionality
using real services and FlextTests infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import asyncio

import pytest

from flext_core import FlextResult
from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class TestFlextLdifAclService:
    """Test suite for FlextLdifAclService."""

    def test_initialization_default(self) -> None:
        """Test ACL service initialization with default quirks manager."""
        service = FlextLdifAclService()
        assert service is not None
        assert service._logger is not None
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

    def test_execute_async_success(self) -> None:
        """Test execute_async method returns success."""
        service = FlextLdifAclService()
        result = asyncio.run(service.execute_async())

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
        rule = service.create_subject_rule("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        assert rule is not None
        assert rule._subject_dn == "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"
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
        context: dict[str, object] = {"permissions": {"read": True, "write": True}}
        result = composite.evaluate(context)
        assert result.is_success
        assert result.value is True

        # Test with missing permission
        context: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = composite.evaluate(context)
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
        context: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = composite.evaluate(context)
        assert result.is_success
        assert result.value is True

        # Test with no permissions
        context: dict[str, object] = {"permissions": {"read": False, "write": False}}
        result = composite.evaluate(context)
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
        assert "Unknown operator" in result.error

    def test_permission_rule_evaluate_required_true(self) -> None:
        """Test permission rule evaluation with required=True."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read", required=True)

        # Test with permission
        context: dict[str, object] = {"permissions": {"read": True}}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is True

        # Test without permission
        context: dict[str, object] = {"permissions": {"read": False}}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is False

        # Test with missing permissions dict
        context: dict[str, object] = {}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is False

    def test_permission_rule_evaluate_required_false(self) -> None:
        """Test permission rule evaluation with required=False."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("write", required=False)

        # Test with permission (should be False since required=False)
        context: dict[str, object] = {"permissions": {"write": True}}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is False

        # Test without permission (should be True since required=False)
        context: dict[str, object] = {"permissions": {"write": False}}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is True

    def test_subject_rule_evaluate(self) -> None:
        """Test subject rule evaluation."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        # Test with matching subject
        context: dict[str, object] = {"subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com"}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is True

        # Test with non-matching subject
        context: dict[str, object] = {"subject_dn": "cn=user,dc=example,dc=com"}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is False

        # Test with missing subject_dn
        context: dict[str, object] = {}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.value is False

    def test_extract_acls_from_entry_none(self) -> None:
        """Test extracting ACLs from None entry."""
        service = FlextLdifAclService()
        # Test the None case that the method explicitly handles
        result = service.extract_acls_from_entry(None)

        assert result.is_failure
        assert result.error is not None
        assert "Invalid entry: Entry is None" in result.error

    def test_extract_acls_from_entry_no_acl_attribute(self) -> None:
        """Test extracting ACLs from entry with no ACL attribute."""
        service = FlextLdifAclService()

        # Create a simple entry without ACL attributes
        entry_data: dict[str, object] = {
            "dn": "cn=testuser,dc=example,dc=com",
            "attributes": {"objectClass": ["person"], "cn": ["testuser"]},
        }

        entry_result = FlextLdifModels.Entry.create(entry_data)
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

        result = service.evaluate_acl_rules(rules, None)

        assert result.is_failure
        assert result.error is not None
        assert "Invalid context: Context is None" in result.error

    def test_evaluate_acl_rules_empty_list(self) -> None:
        """Test evaluating empty ACL rules list."""
        service = FlextLdifAclService()
        context: dict[str, object] = {"permissions": {"read": True}}

        result = service.evaluate_acl_rules([], context)

        assert result.is_success
        assert result.value is True  # Empty composite rule returns True

    def test_evaluate_acl_rules_multiple_rules(self) -> None:
        """Test evaluating multiple ACL rules."""
        service = FlextLdifAclService()

        # Create multiple rules
        read_rule = service.create_permission_rule("read")
        write_rule = service.create_permission_rule("write")
        subject_rule = service.create_subject_rule("cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com")

        rules: list[FlextLdifAclService.AclRule] = [read_rule, write_rule, subject_rule]

        # Test with all conditions met
        context: dict[str, object] = {
            "permissions": {"read": True, "write": True},
            "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        }
        result = service.evaluate_acl_rules(rules, context)
        assert result.is_success
        assert result.value is True

        # Test with some conditions not met
        context: dict[str, object] = {
            "permissions": {"read": True, "write": False},
            "subject_dn": "cn=REDACTED_LDAP_BIND_PASSWORD,dc=example,dc=com",
        }
        result = service.evaluate_acl_rules(rules, context)
        assert result.is_success
        assert result.value is False

    def test_parse_acl_with_rules_success(self) -> None:
        """Test parsing ACL with rules."""
        service = FlextLdifAclService()

        acl_string = "to attrs=cn by * read"
        server_type = "openldap"

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
        service = FlextLdifAclService()

        result = service._parse_acl_with_rules("", "generic")

        assert result.is_success
        acl = result.value
        assert acl.name == "parsed_acl"
        assert acl.server_type == "generic"
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
        context: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = outer_composite.evaluate(context)

        assert result.is_success
        assert result.value is True  # OR of read=True, write=False = True

    def test_rule_evaluation_error_handling(self) -> None:
        """Test error handling in rule evaluation."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule("AND")

        # Add a rule that will cause evaluation to fail
        # We'll create a custom rule that returns failure
        class FailingRule(service.AclRule):
            def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
                _ = context  # Suppress unused argument warning
                return FlextResult[bool].fail("Test failure")

        failing_rule = FailingRule()
        composite.add_rule(failing_rule)

        context: dict[str, object] = {"test": "value"}
        result = composite.evaluate(context)

        assert result.is_failure
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

    def test_async_execute_consistency(self) -> None:
        """Test that async execute returns same result as sync execute."""
        service = FlextLdifAclService()

        sync_result = service.execute()
        async_result = asyncio.run(service.execute_async())

        assert sync_result.is_success == async_result.is_success
        if sync_result.is_success:
            assert sync_result.value == async_result.value
