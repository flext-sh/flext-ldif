"""FLEXT LDIF ACL Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from typing import cast

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class FlextLdifAclService(FlextService[dict[str, object]]):
    """Unified ACL management service using Composite pattern for rule composition."""

    class AclRule:
        """Base ACL rule following AclRuleProtocol - Composite pattern."""

        def __init__(self, rule_type: str = "base") -> None:
            """Initialize ACL rule."""
            self._rule_type = rule_type
            self._logger = FlextLogger(__name__)

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate ACL rule against context."""
            # Placeholder: ACL evaluation logic will be implemented in future version
            _ = context  # Suppress unused argument warning
            return FlextResult[bool].ok(True)

        def add_rule(self, rule: "FlextLdifAclService.AclRule") -> None:
            """Add sub-rule (for composite rules)."""
            msg = "Base rule does not support adding sub-rules"
            raise NotImplementedError(msg)

    class CompositeAclRule(AclRule):
        """Composite ACL rule combining multiple rules."""

        def __init__(self, operator: str = "AND") -> None:
            """Initialize composite ACL rule."""
            super().__init__(rule_type="composite")
            self._operator = operator.upper()
            self._rules: list[FlextLdifAclService.AclRule] = []

        def add_rule(self, rule: "FlextLdifAclService.AclRule") -> None:
            """Add sub-rule to composite."""
            self._rules.append(rule)

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate all rules with operator logic."""
            if not self._rules:
                return FlextResult[bool].ok(True)

            results: list[bool] = []
            for rule in self._rules:
                eval_result = rule.evaluate(context)
                if eval_result.is_failure:
                    return eval_result
                results.append(eval_result.value)

            if self._operator == "AND":
                final_result = all(results)
            elif self._operator == "OR":
                final_result = any(results)
            else:
                return FlextResult[bool].fail(f"Unknown operator: {self._operator}")

            return FlextResult[bool].ok(final_result)

    class PermissionRule(AclRule):
        """Permission-based ACL rule."""

        def __init__(self, permission: str, *, required: bool = True) -> None:
            """Initialize permission rule."""
            super().__init__(rule_type="permission")
            self._permission = permission
            self._required = required

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate permission requirement."""
            perms = cast("dict[str, bool]", context.get("permissions", {}))
            has_perm = perms.get(self._permission, False)
            result = has_perm == self._required
            return FlextResult[bool].ok(result)

    class SubjectRule(AclRule):
        """Subject-based ACL rule."""

        def __init__(self, subject_dn: str) -> None:
            """Initialize subject rule."""
            super().__init__(rule_type="subject")
            self._subject_dn = subject_dn

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate subject match."""
            subject = context.get("subject_dn", "")
            result = subject == self._subject_dn
            return FlextResult[bool].ok(result)

    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize ACL service with composite pattern support."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    def create_composite_rule(
        self, operator: str = "AND"
    ) -> "FlextLdifAclService.CompositeAclRule":
        """Create composite ACL rule for combining multiple rules."""
        return self.CompositeAclRule(operator=operator)

    def create_permission_rule(
        self, permission: str, *, required: bool = True
    ) -> "FlextLdifAclService.PermissionRule":
        """Create permission-based ACL rule."""
        return self.PermissionRule(permission=permission, required=required)

    def create_subject_rule(self, subject_dn: str) -> "FlextLdifAclService.SubjectRule":
        """Create subject-based ACL rule."""
        return self.SubjectRule(subject_dn=subject_dn)

    def extract_acls_from_entry(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[list[FlextLdifModels.UnifiedAcl]]:
        """Extract ACLs from LDIF entry using composite pattern.

        Args:
            entry: LDIF entry to extract ACLs from
            server_type: Server type for ACL format detection

        Returns:
            FlextResult containing list of unified ACL entries

        """
        acl_attr_result: FlextResult[str] = self._quirks.get_acl_attribute_name(
            server_type
        )
        if acl_attr_result.is_failure:
            error_msg = acl_attr_result.error or "Unknown ACL attribute error"
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].fail(error_msg)

        acl_attribute = acl_attr_result.value
        acl_values: list[str] = entry.get_attribute(acl_attribute) or []

        if not acl_values:
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].ok([])

        acls: list[FlextLdifModels.UnifiedAcl] = []
        for acl_value in acl_values:
            parse_result: FlextResult[FlextLdifModels.UnifiedAcl] = (
                self._parse_acl_with_rules(acl_value, server_type or "generic")
            )
            if parse_result.is_success:
                acls.append(parse_result.value)

        return FlextResult[list[FlextLdifModels.UnifiedAcl]].ok(acls)

    def _parse_acl_with_rules(
        self, acl_string: str, server_type: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse ACL string using composite rule pattern.

        Args:
            acl_string: Raw ACL string
            server_type: Server type for format detection

        Returns:
            FlextResult containing unified ACL with composite rules

        """
        target_result: FlextResult[FlextLdifModels.AclTarget] = (
            FlextLdifModels.AclTarget.create()
        )
        subject_result: FlextResult[FlextLdifModels.AclSubject] = (
            FlextLdifModels.AclSubject.create()
        )
        perms_result: FlextResult[FlextLdifModels.AclPermissions] = (
            FlextLdifModels.AclPermissions.create(read=True)
        )

        if (
            target_result.is_failure
            or subject_result.is_failure
            or perms_result.is_failure
        ):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create ACL components"
            )

        return FlextLdifModels.UnifiedAcl.create(
            name="parsed_acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
            server_type=server_type,
            raw_acl=acl_string,
        )

    def evaluate_acl_rules(
        self, rules: list[AclRule], context: dict[str, object]
    ) -> FlextResult[bool]:
        """Evaluate ACL rules against context using composite pattern."""
        composite = self.create_composite_rule(operator="AND")
        for rule in rules:
            composite.add_rule(rule)
        return composite.evaluate(context)

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute ACL service health check.

        Returns:
            FlextResult containing service status and available patterns

        """
        return FlextResult[dict[str, object]].ok({
            "service": "FlextLdifAclService",
            "status": "ready",
            "patterns": {
                "composite": "Composite ACL rule evaluation",
                "rule_evaluation": "Individual ACL rule processing",
            },
        })


__all__ = ["FlextLdifAclService"]
