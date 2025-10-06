"""FLEXT LDIF ACL Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextLogger, FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclService(FlextService[FlextLdifTypes.Dict]):
    """Unified ACL management service using Composite pattern for rule composition."""

    class AclComponentHelper:
        """Helper class for creating and validating ACL components."""

        @staticmethod
        def create_acl_components() -> FlextResult[
            tuple[
                FlextLdifModels.AclTarget,
                FlextLdifModels.AclSubject,
                FlextLdifModels.AclPermissions,
            ]
        ]:
            """Create ACL components with proper validation."""
            # Create ACL components
            target_creation = FlextLdifModels.AclTarget.create()
            subject_creation = FlextLdifModels.AclSubject.create()
            perms_creation = FlextLdifModels.AclPermissions.create(read=True)

            # Validate and extract values
            if not target_creation.is_success:
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Failed to create AclTarget")
            if not isinstance(target_creation.value, FlextLdifModels.AclTarget):
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Invalid AclTarget type")

            if not subject_creation.is_success:
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Failed to create AclSubject")
            if not isinstance(subject_creation.value, FlextLdifModels.AclSubject):
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Invalid AclSubject type")

            if not perms_creation.is_success:
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Failed to create AclPermissions")
            if not isinstance(perms_creation.value, FlextLdifModels.AclPermissions):
                return FlextResult[
                    tuple[
                        FlextLdifModels.AclTarget,
                        FlextLdifModels.AclSubject,
                        FlextLdifModels.AclPermissions,
                    ]
                ].fail("Invalid AclPermissions type")

            return FlextResult[
                tuple[
                    FlextLdifModels.AclTarget,
                    FlextLdifModels.AclSubject,
                    FlextLdifModels.AclPermissions,
                ]
            ].ok((
                target_creation.value,
                subject_creation.value,
                perms_creation.value,
            ))

        @staticmethod
        def create_unified_acl(
            name: str,
            target: FlextLdifModels.AclTarget,
            subject: FlextLdifModels.AclSubject,
            permissions: FlextLdifModels.AclPermissions,
            server_type: str,
            raw_acl: str,
        ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
            """Create unified ACL with proper validation."""
            acl_result = FlextLdifModels.UnifiedAcl.create(
                name=name,
                target=target,
                subject=subject,
                permissions=permissions,
                server_type=server_type,
                raw_acl=raw_acl,
            )

            if acl_result.is_success and isinstance(
                acl_result.value, FlextLdifModels.UnifiedAcl
            ):
                return FlextResult[FlextLdifModels.UnifiedAcl].ok(acl_result.value)
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                acl_result.error or "Failed to create UnifiedAcl"
            )

    class AclRule:
        """Base ACL rule following AclRuleProtocol - Composite pattern."""

        @override
        def __init__(self, rule_type: str = "base") -> None:
            """Initialize ACL rule."""
            self._rule_type = rule_type
            self._logger = FlextLogger(__name__)

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate ACL rule against context."""
            # Placeholder: ACL evaluation logic will be implemented in future version
            _ = context  # Suppress unused argument warning
            return FlextResult[bool].ok(True)

        def add_rule(self, rule: FlextLdifAclService.AclRule) -> None:
            """Add sub-rule (for composite rules)."""
            msg = "Base rule does not support adding sub-rules"
            raise NotImplementedError(msg)

    class CompositeAclRule(AclRule):
        """Composite ACL rule combining multiple rules."""

        @override
        def __init__(self, operator: str = "AND") -> None:
            """Initialize composite ACL rule."""
            super().__init__(rule_type="composite")
            self._operator = operator.upper()
            self._rules: list[FlextLdifAclService.AclRule] = []

        def add_rule(self, rule: FlextLdifAclService.AclRule) -> None:
            """Add sub-rule to composite."""
            self._rules.append(rule)

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate all rules with operator logic."""
            if not self._rules:
                return FlextResult[bool].ok(True)

            results: FlextLdifTypes.BoolList = []
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

        @override
        def __init__(self, permission: str, *, required: bool = True) -> None:
            """Initialize permission rule."""
            super().__init__(rule_type="permission")
            self._permission = permission
            self._required = required

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate permission requirement."""
            perms = cast("FlextLdifTypes.BoolDict", context.get("permissions", {}))
            has_perm = perms.get(self._permission, False)
            result = has_perm == self._required
            return FlextResult[bool].ok(result)

    class SubjectRule(AclRule):
        """Subject-based ACL rule."""

        @override
        def __init__(self, subject_dn: str) -> None:
            """Initialize subject rule."""
            super().__init__(rule_type="subject")
            self._subject_dn = subject_dn

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate subject match."""
            subject = context.get("subject_dn", "")
            result = subject == self._subject_dn
            return FlextResult[bool].ok(result)

    @override
    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize ACL service with composite pattern support."""
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    def create_composite_rule(
        self, operator: str = "AND"
    ) -> FlextLdifAclService.CompositeAclRule:
        """Create composite ACL rule for combining multiple rules."""
        return self.CompositeAclRule(operator=operator)

    def create_permission_rule(
        self, permission: str, *, required: bool = True
    ) -> FlextLdifAclService.PermissionRule:
        """Create permission-based ACL rule."""
        return self.PermissionRule(permission=permission, required=required)

    def create_subject_rule(self, subject_dn: str) -> FlextLdifAclService.SubjectRule:
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
        if entry is None:
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].fail(
                "Invalid entry: Entry is None"
            )

        acl_attr_result: FlextResult[str] = self._quirks.get_acl_attribute_name(
            server_type
        )
        if acl_attr_result.is_failure:
            error_msg = acl_attr_result.error or "Unknown ACL attribute error"
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].fail(error_msg)

        acl_attribute = acl_attr_result.value
        acl_values: FlextLdifTypes.StringList = entry.get_attribute(acl_attribute) or []

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
        # Create ACL components using helper
        components_result = self.AclComponentHelper.create_acl_components()
        if components_result.is_failure:
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(components_result.error)

        target_result, subject_result, perms_result = components_result.value

        # Create unified ACL using helper
        return self.AclComponentHelper.create_unified_acl(
            name="parsed_acl",
            target=target_result,
            subject=subject_result,
            permissions=perms_result,
            server_type=server_type,
            raw_acl=acl_string,
        )

    def evaluate_acl_rules(
        self, rules: list[AclRule], context: FlextLdifTypes.Dict
    ) -> FlextResult[bool]:
        """Evaluate ACL rules against context using composite pattern."""
        if context is None:
            return FlextResult[bool].fail("Invalid context: Context is None")

        composite = self.create_composite_rule(operator="AND")
        for rule in rules:
            composite.add_rule(rule)
        return composite.evaluate(context)

    @override
    def execute(self) -> FlextResult[FlextLdifTypes.Dict]:
        """Execute ACL service health check.

        Returns:
            FlextResult containing service status and available patterns

        """
        return FlextResult[FlextLdifTypes.Dict].ok({
            "service": FlextLdifAclService,
            "status": "ready",
            "patterns": {
                "composite": "Composite ACL rule evaluation",
                "rule_evaluation": "Individual ACL rule processing",
            },
        })


__all__ = ["FlextLdifAclService"]
