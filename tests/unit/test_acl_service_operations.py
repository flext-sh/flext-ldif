"""Comprehensive operational tests for ACL service with real LDIF data.

Tests ACL service operations including rule creation, composition, evaluation,
and ACL extraction from real LDIF entries with multiple server types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from pathlib import Path

import pytest

from flext_ldif.acl.service import FlextLdifAclService
from flext_ldif.quirks.registry import FlextLdifQuirksRegistry


class TestAclServiceRuleCreation:
    """Test ACL rule creation and composition."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        return FlextLdifAclService()

    def test_create_composite_rule_and(self, acl_service: FlextLdifAclService) -> None:
        """Test creating composite AND rule."""
        rule = acl_service.create_composite_rule(operator="AND")
        assert rule is not None
        assert rule._operator == "AND"
        assert rule._rules == []

    def test_create_composite_rule_or(self, acl_service: FlextLdifAclService) -> None:
        """Test creating composite OR rule."""
        rule = acl_service.create_composite_rule(operator="OR")
        assert rule is not None
        assert rule._operator == "OR"

    def test_create_composite_rule_not(self, acl_service: FlextLdifAclService) -> None:
        """Test creating composite NOT rule."""
        rule = acl_service.create_composite_rule(operator="NOT")
        assert rule is not None
        assert rule._operator == "NOT"

    def test_create_permission_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test creating permission rule."""
        rule = acl_service.create_permission_rule("READ", required=True)
        assert rule is not None

    def test_create_permission_rule_optional(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test creating optional permission rule."""
        rule = acl_service.create_permission_rule("WRITE", required=False)
        assert rule is not None

    def test_create_subject_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test creating subject rule."""
        dn = "CN=User,DC=Example,DC=Com"
        rule = acl_service.create_subject_rule(dn)
        assert rule is not None
        assert rule._subject_dn == dn

    def test_create_target_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test creating target rule."""
        dn = "CN=Group,DC=Example,DC=Com"
        rule = acl_service.create_target_rule(dn)
        assert rule is not None
        assert rule._target_dn == dn

    def test_create_time_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test creating time-based rule."""
        rule = acl_service.create_time_rule(start_time="08:00", end_time="17:00")
        assert rule is not None

    def test_create_group_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test creating group rule."""
        group_dn = "CN=Admins,DC=Example,DC=Com"
        rule = acl_service.create_group_rule(group_dn, member_required=True)
        assert rule is not None


class TestAclServiceRuleEvaluation:
    """Test ACL rule evaluation with various contexts."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        return FlextLdifAclService()

    def test_evaluate_permission_rule_granted(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test permission rule evaluation when permission granted."""
        rule = acl_service.create_permission_rule("READ", required=True)
        context = {"permissions": ["READ", "WRITE"]}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.unwrap() is True

    def test_evaluate_permission_rule_denied(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test permission rule evaluation when permission denied."""
        rule = acl_service.create_permission_rule("EXECUTE", required=True)
        context = {"permissions": ["READ", "WRITE"]}
        result = rule.evaluate(context)
        assert result.is_success
        assert result.unwrap() is False

    def test_evaluate_subject_rule_match(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test subject rule evaluation on matching DN."""
        dn = "CN=User,DC=Example,DC=Com"
        rule = acl_service.create_subject_rule(dn)
        context = {"subject": dn}
        result = rule.evaluate(context)
        assert result.is_success

    def test_evaluate_subject_rule_no_match(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test subject rule evaluation on non-matching DN."""
        dn = "CN=User1,DC=Example,DC=Com"
        rule = acl_service.create_subject_rule(dn)
        context = {"subject": "CN=User2,DC=Example,DC=Com"}
        result = rule.evaluate(context)
        assert result.is_success

    def test_evaluate_target_rule_match(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test target rule evaluation on matching DN."""
        dn = "CN=Group,DC=Example,DC=Com"
        rule = acl_service.create_target_rule(dn)
        context = {"target": dn}
        result = rule.evaluate(context)
        assert result.is_success

    def test_evaluate_composite_and_all_true(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test composite AND rule when all sub-rules are true."""
        composite = acl_service.create_composite_rule(operator="AND")
        rule1 = acl_service.create_permission_rule("READ", required=True)
        rule2 = acl_service.create_permission_rule("WRITE", required=True)
        composite.add_rule(rule1)
        composite.add_rule(rule2)

        context = {"permissions": ["READ", "WRITE", "EXECUTE"]}
        result = composite.evaluate(context)
        assert result.is_success

    def test_evaluate_composite_or_one_true(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test composite OR rule when at least one sub-rule is true."""
        composite = acl_service.create_composite_rule(operator="OR")
        rule1 = acl_service.create_permission_rule("READ", required=True)
        rule2 = acl_service.create_permission_rule("EXECUTE", required=True)
        composite.add_rule(rule1)
        composite.add_rule(rule2)

        context = {"permissions": ["READ", "WRITE"]}
        result = composite.evaluate(context)
        assert result.is_success

    def test_evaluate_composite_empty(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test composite rule with no sub-rules."""
        composite = acl_service.create_composite_rule(operator="AND")
        context = {"permissions": ["READ"]}
        result = composite.evaluate(context)
        assert result.is_success
        assert result.unwrap() is True

    def test_evaluate_time_rule_within_window(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test time rule evaluation within time window."""
        rule = acl_service.create_time_rule(start_time="00:00", end_time="23:59")
        context = {}
        result = rule.evaluate(context)
        assert result.is_success

    def test_evaluate_time_rule_invalid_format(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test time rule with invalid time format."""
        rule = acl_service.create_time_rule(start_time="invalid", end_time="17:00")
        context = {}
        result = rule.evaluate(context)
        # Should handle gracefully
        assert result is not None

    def test_evaluate_group_rule(self, acl_service: FlextLdifAclService) -> None:
        """Test group membership rule evaluation."""
        group_dn = "CN=Admins,DC=Example,DC=Com"
        rule = acl_service.create_group_rule(group_dn, member_required=True)
        context = {"groups": [group_dn]}
        result = rule.evaluate(context)
        assert result.is_success


class TestAclServiceExtraction:
    """Test ACL extraction from LDIF entries."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        return FlextLdifAclService()

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    def test_extract_acls_from_entry_with_aci(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test extracting ACLs from entry with ACI attribute."""
        from flext_ldif import FlextLdifModels
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={
                "aci": ['(targetattr=*)(version 3.0;acl "test";allow(all) userdn="*";)']
            },
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success

    def test_extract_acls_from_entry_with_orclaci(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test extracting ACLs from OID entry with orclaci attribute."""
        from flext_ldif import FlextLdifModels
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={"orclaci": ["(targetattr=*)(allow all)"]},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success

    def test_extract_acls_from_entry_no_acl(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test extracting ACLs from entry without ACL attributes."""
        from flext_ldif import FlextLdifModels
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={"cn": ["Test"], "objectClass": ["person"]},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success

    def test_extract_acls_from_entry_empty_attributes(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test extracting ACLs from entry with empty attributes."""
        from flext_ldif import FlextLdifModels
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success

    def test_extract_acls_from_entry_minimal(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test extracting ACLs from minimal entry with empty attributes."""
        from flext_ldif import FlextLdifModels
        result = FlextLdifModels.Entry.create(
            "CN=Test,DC=Example,DC=Com",
            {},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success


class TestAclServiceWithRealFixtures:
    """Test ACL service with real LDIF fixture data."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        quirks_manager = FlextLdifQuirksRegistry()
        return FlextLdifAclService(quirks_manager=quirks_manager)

    @pytest.fixture
    def oid_acl_fixture(self) -> Path:
        """Get path to OID ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oid" / "oid_acl_fixtures.ldif"
        )

    @pytest.fixture
    def oud_acl_fixture(self) -> Path:
        """Get path to OUD ACL fixture."""
        return (
            Path(__file__).parent.parent / "fixtures" / "oud" / "oud_acl_fixtures.ldif"
        )

    def test_extract_acls_from_oid_fixture(
        self, acl_service: FlextLdifAclService, oid_acl_fixture: Path
    ) -> None:
        """Test ACL extraction from real OID fixture."""
        from flext_ldif import FlextLdifModels

        if not oid_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oid_acl_fixture}")

        content = oid_acl_fixture.read_text(encoding="utf-8")
        # Parse entries from LDIF (at least one should exist)
        assert "dn:" in content

        # Create a test entry with ACL data
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={"orclaci": [content[:50]]},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success

    def test_extract_acls_from_oud_fixture(
        self, acl_service: FlextLdifAclService, oud_acl_fixture: Path
    ) -> None:
        """Test ACL extraction from real OUD fixture."""
        from flext_ldif import FlextLdifModels

        if not oud_acl_fixture.exists():
            pytest.skip(f"Fixture not found: {oud_acl_fixture}")

        content = oud_acl_fixture.read_text(encoding="utf-8")
        assert len(content) > 0

        # Create a test entry with OUD ACL data
        result = FlextLdifModels.Entry.create(
            dn="CN=Test,DC=Example,DC=Com",
            attributes={"aci": [content[:100]]},
        )
        if result.is_success:
            entry = result.unwrap()
            extract_result = acl_service.extract_acls_from_entry(entry)
            assert extract_result.is_success


class TestAclServiceIntegration:
    """Test ACL service integration scenarios."""

    @pytest.fixture
    def acl_service(self) -> FlextLdifAclService:
        """Create ACL service instance."""
        return FlextLdifAclService()

    def test_complex_acl_evaluation_scenario(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test complex ACL evaluation with multiple rules."""
        # Build complex rule: (READ OR WRITE) AND SubjectDN
        permission_composite = acl_service.create_composite_rule(operator="OR")
        permission_composite.add_rule(acl_service.create_permission_rule("READ"))
        permission_composite.add_rule(acl_service.create_permission_rule("WRITE"))

        main_composite = acl_service.create_composite_rule(operator="AND")
        main_composite.add_rule(permission_composite)
        main_composite.add_rule(
            acl_service.create_subject_rule("CN=User,DC=Example,DC=Com")
        )

        context = {
            "permissions": ["READ"],
            "subject": "CN=User,DC=Example,DC=Com",
        }
        result = main_composite.evaluate(context)
        assert result.is_success

    def test_acl_service_with_multiple_entries(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test ACL extraction from multiple entries."""
        from flext_ldif import FlextLdifModels

        entries_data = [
            {
                "dn": "CN=User1,DC=Example,DC=Com",
                "attributes": {"aci": ["(allow all)"]},
            },
            {
                "dn": "CN=User2,DC=Example,DC=Com",
                "attributes": {"orclaci": ["(allow all)"]},
            },
            {
                "dn": "CN=User3,DC=Example,DC=Com",
                "attributes": {"cn": ["User3"]},
            },
        ]

        for entry_data in entries_data:
            result = FlextLdifModels.Entry.create(**entry_data)
            if result.is_success:
                entry = result.unwrap()
                extract_result = acl_service.extract_acls_from_entry(entry)
                assert extract_result.is_success

    def test_acl_rule_not_implemented_on_base(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test that base rule doesn't support adding sub-rules."""
        base_rule = acl_service.AclRule()
        with pytest.raises(NotImplementedError):
            base_rule.add_rule(acl_service.AclRule())

    def test_acl_rule_base_evaluation(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test base rule evaluation (always allows)."""
        base_rule = acl_service.AclRule()
        context = {}
        result = base_rule.evaluate(context)
        assert result.is_success
        assert result.unwrap() is True

    def test_acl_service_execute_default(
        self, acl_service: FlextLdifAclService
    ) -> None:
        """Test ACL service execute method default behavior."""
        result = acl_service.execute()
        assert result.is_success
        data = result.unwrap()
        assert isinstance(data, dict)
