"""Test ACL Composite Pattern Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

import pytest

from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class TestAclCompositePattern:
    """Test ACL service composite pattern implementation."""

    def test_base_acl_rule_creation(self) -> None:
        """Test base ACL rule creation and evaluation."""
        service = FlextLdifAclService()
        rule = service.AclRule(rule_type="base")

        context: dict[str, object] = {}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_composite_rule_and_operator(self) -> None:
        """Test composite rule with AND operator."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule(operator="AND")

        perm_rule1 = service.create_permission_rule("read", required=True)
        perm_rule2 = service.create_permission_rule("write", required=True)

        composite.add_rule(perm_rule1)
        composite.add_rule(perm_rule2)

        context: dict[str, object] = {"permissions": {"read": True, "write": True}}
        result = composite.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_composite_rule_and_operator_fails(self) -> None:
        """Test composite rule with AND operator fails when one rule fails."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule(operator="AND")

        perm_rule1 = service.create_permission_rule("read", required=True)
        perm_rule2 = service.create_permission_rule("write", required=True)

        composite.add_rule(perm_rule1)
        composite.add_rule(perm_rule2)

        context: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = composite.evaluate(context)

        assert result.is_success
        assert result.value is False

    def test_composite_rule_or_operator(self) -> None:
        """Test composite rule with OR operator."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule(operator="OR")

        perm_rule1 = service.create_permission_rule("read", required=True)
        perm_rule2 = service.create_permission_rule("write", required=True)

        composite.add_rule(perm_rule1)
        composite.add_rule(perm_rule2)

        context: dict[str, object] = {"permissions": {"read": True, "write": False}}
        result = composite.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_composite_rule_empty_rules(self) -> None:
        """Test composite rule with no sub-rules."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule(operator="AND")

        context: dict[str, object] = {}
        result = composite.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_composite_rule_invalid_operator(self) -> None:
        """Test composite rule with invalid operator."""
        service = FlextLdifAclService()
        composite = service.create_composite_rule(operator="XOR")

        perm_rule = service.create_permission_rule("read", required=True)
        composite.add_rule(perm_rule)

        context: dict[str, object] = {"permissions": {"read": True}}
        result = composite.evaluate(context)

        assert result.is_failure
        assert result.error is not None
        assert "Unknown operator" in result.error

    def test_permission_rule_required_true(self) -> None:
        """Test permission rule with required=True."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read", required=True)

        context_with_perm: dict[str, object] = {"permissions": {"read": True}}
        result = rule.evaluate(context_with_perm)
        assert result.is_success
        assert result.value is True

        context_without_perm: dict[str, object] = {"permissions": {"read": False}}
        result = rule.evaluate(context_without_perm)
        assert result.is_success
        assert result.value is False

    def test_permission_rule_required_false(self) -> None:
        """Test permission rule with required=False."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read", required=False)

        context_with_perm: dict[str, object] = {"permissions": {"read": False}}
        result = rule.evaluate(context_with_perm)
        assert result.is_success
        assert result.value is True

        context_without_perm: dict[str, object] = {"permissions": {"read": True}}
        result = rule.evaluate(context_without_perm)
        assert result.is_success
        assert result.value is False

    def test_permission_rule_missing_permissions(self) -> None:
        """Test permission rule when permissions are missing from context."""
        service = FlextLdifAclService()
        rule = service.create_permission_rule("read", required=True)

        context: dict[str, object] = {}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is False

    def test_subject_rule_match(self) -> None:
        """Test subject rule with matching DN."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        context: dict[str, object] = {"subject_dn": "cn=admin,dc=example,dc=com"}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is True

    def test_subject_rule_no_match(self) -> None:
        """Test subject rule with non-matching DN."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        context: dict[str, object] = {"subject_dn": "cn=user,dc=example,dc=com"}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is False

    def test_subject_rule_missing_dn(self) -> None:
        """Test subject rule when DN is missing from context."""
        service = FlextLdifAclService()
        rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        context: dict[str, object] = {}
        result = rule.evaluate(context)

        assert result.is_success
        assert result.value is False

    def test_evaluate_acl_rules_list(self) -> None:
        """Test evaluating a list of ACL rules."""
        service = FlextLdifAclService()

        rules = [
            service.create_permission_rule("read", required=True),
            service.create_subject_rule("cn=admin,dc=example,dc=com"),
        ]

        context: dict[str, object] = {
            "permissions": {"read": True},
            "subject_dn": "cn=admin,dc=example,dc=com",
        }

        result = service.evaluate_acl_rules(rules, context)

        assert result.is_success
        assert result.value is True

    def test_service_execute(self) -> None:
        """Test ACL service execute method."""
        service = FlextLdifAclService()
        result = service.execute()

        assert result.is_success
        assert isinstance(result.value, dict)
        assert result.value["service"] == "FlextLdifAclService"
        assert result.value["status"] == "ready"
        assert "patterns" in result.value
        patterns = result.value["patterns"]
        assert isinstance(patterns, dict)
        assert "composite" in patterns

    def test_extract_acls_from_entry(self) -> None:
        """Test extracting ACLs from LDIF entry."""
        service = FlextLdifAclService()

        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
                "aclentry": ["access-id: read(...)"],
            },
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_acls_from_entry(entry, "openldap")

        assert result.is_success
        assert isinstance(result.value, list)

    def test_extract_acls_no_acl_attribute(self) -> None:
        """Test extracting ACLs when entry has no ACL attribute."""
        service = FlextLdifAclService()

        entry_data = {
            "dn": "cn=test,dc=example,dc=com",
            "attributes": {
                "cn": ["test"],
            },
        }
        entry_result = FlextLdifModels.Entry.create(entry_data)
        assert entry_result.is_success
        entry = entry_result.value

        result = service.extract_acls_from_entry(entry, "openldap")

        assert result.is_success
        assert result.value == []

    def test_base_rule_add_rule_raises(self) -> None:
        """Test that base rule raises error when adding sub-rules."""
        service = FlextLdifAclService()
        base_rule = service.AclRule()
        sub_rule = service.AclRule()

        with pytest.raises(
            NotImplementedError, match="does not support adding sub-rules"
        ):
            base_rule.add_rule(sub_rule)

    def test_composite_with_quirks_manager(self) -> None:
        """Test ACL service with custom quirks manager."""
        quirks = FlextLdifQuirksManager()
        service = FlextLdifAclService(quirks_manager=quirks)

        result = service.execute()

        assert result.is_success
        assert isinstance(result.value, dict)
        assert result.value["service"] == "FlextLdifAclService"
        assert result.value["status"] == "ready"

    def test_nested_composite_rules(self) -> None:
        """Test nested composite rules."""
        service = FlextLdifAclService()

        # Create inner composite (AND)
        inner_composite = service.create_composite_rule(operator="AND")
        inner_composite.add_rule(service.create_permission_rule("read", required=True))
        inner_composite.add_rule(service.create_permission_rule("write", required=True))

        # Create outer composite (OR)
        outer_composite = service.create_composite_rule(operator="OR")
        outer_composite.add_rule(inner_composite)
        outer_composite.add_rule(
            service.create_subject_rule("cn=admin,dc=example,dc=com")
        )

        # Test with permissions only
        context1: dict[str, object] = {
            "permissions": {"read": True, "write": True},
            "subject_dn": "cn=user,dc=example,dc=com",
        }
        result1 = outer_composite.evaluate(context1)
        assert result1.is_success
        assert result1.value is True

        # Test with subject only
        context2: dict[str, object] = {
            "permissions": {"read": False, "write": False},
            "subject_dn": "cn=admin,dc=example,dc=com",
        }
        result2 = outer_composite.evaluate(context2)
        assert result2.is_success
        assert result2.value is True

        # Test with neither
        context3: dict[str, object] = {
            "permissions": {"read": False, "write": True},
            "subject_dn": "cn=user,dc=example,dc=com",
        }
        result3 = outer_composite.evaluate(context3)
        assert result3.is_success
        assert result3.value is False


class TestAclServiceIntegration:
    """Integration tests for ACL service."""

    def test_complete_acl_workflow(self) -> None:
        """Test complete ACL workflow with composite pattern."""
        service = FlextLdifAclService()

        # Create complex rule: (read AND write) OR admin
        permissions_rule = service.create_composite_rule(operator="AND")
        permissions_rule.add_rule(service.create_permission_rule("read", required=True))
        permissions_rule.add_rule(
            service.create_permission_rule("write", required=True)
        )

        admin_rule = service.create_subject_rule("cn=admin,dc=example,dc=com")

        final_rule = service.create_composite_rule(operator="OR")
        final_rule.add_rule(permissions_rule)
        final_rule.add_rule(admin_rule)

        # Test scenarios
        admin_context: dict[str, object] = {
            "permissions": {"read": False, "write": False},
            "subject_dn": "cn=admin,dc=example,dc=com",
        }
        assert final_rule.evaluate(admin_context).value is True

        full_perms_context: dict[str, object] = {
            "permissions": {"read": True, "write": True},
            "subject_dn": "cn=user,dc=example,dc=com",
        }
        assert final_rule.evaluate(full_perms_context).value is True

        partial_perms_context: dict[str, object] = {
            "permissions": {"read": True, "write": False},
            "subject_dn": "cn=user,dc=example,dc=com",
        }
        assert final_rule.evaluate(partial_perms_context).value is False
