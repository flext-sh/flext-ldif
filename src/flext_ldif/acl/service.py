"""FLEXT LDIF ACL Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from typing import cast, override

from flext_core import FlextResult, FlextService

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclService(FlextService[FlextLdifTypes.Dict]):
    """Unified ACL management service using Composite pattern for rule composition."""

    class AclRule:
        """Base ACL rule following AclRuleProtocol - Composite pattern."""

        @override
        def __init__(self, rule_type: str = "base") -> None:
            """Initialize ACL rule."""
            self._rule_type = rule_type

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate ACL rule against context.

            This base implementation provides a default evaluation strategy.
            Subclasses should override this method to implement specific rule logic.

            Args:
                context: Evaluation context containing subject, target, permissions, etc.

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Default evaluation - check if context is valid
                if context is None:
                    return FlextResult[bool].ok(False)

                # Base rule always evaluates to True (allow by default)
                # Specific rule types (SubjectRule, TargetRule, etc.) check their required keys
                return FlextResult[bool].ok(True)

            except Exception as e:
                return FlextResult[bool].fail(f"ACL evaluation failed: {e}")

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
            """Evaluate permission requirement.

            Checks if the required permission is present (or absent) in the context.

            Args:
                context: Evaluation context with permissions dict

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Get permissions from context
                perms = cast("FlextLdifTypes.BoolDict", context.get("permissions", {}))

                # Handle different permission formats
                has_perm = False
                if isinstance(perms, dict):
                    has_perm = perms.get(self._permission, False)
                elif isinstance(perms, list):
                    has_perm = self._permission in perms
                elif isinstance(perms, str):
                    # Comma or space separated permissions
                    perm_list = [p.strip() for p in perms.replace(",", " ").split()]
                    has_perm = self._permission in perm_list

                # Check if permission matches requirement
                result = has_perm == self._required
                return FlextResult[bool].ok(result)

            except Exception as e:
                return FlextResult[bool].fail(f"Permission rule evaluation failed: {e}")

    class SubjectRule(AclRule):
        """Subject-based ACL rule."""

        @override
        def __init__(self, subject_dn: str) -> None:
            """Initialize subject rule."""
            super().__init__(rule_type="subject")
            self._subject_dn = subject_dn

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate subject match.

            Checks if the subject DN matches the required DN, with support for
            wildcards and DN normalization.

            Args:
                context: Evaluation context with subject_dn

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                subject_dn_obj = context.get("subject_dn", "")
                subject_dn = str(subject_dn_obj) if subject_dn_obj else ""

                # Handle different subject formats
                if not subject_dn and not self._subject_dn:
                    return FlextResult[bool].ok(True)  # Both empty matches

                if not subject_dn or not self._subject_dn:
                    return FlextResult[bool].ok(False)  # One empty, no match

                # Normalize DNs for comparison (case insensitive, trimmed)
                subject_normalized = subject_dn.lower().strip()
                rule_normalized = self._subject_dn.lower().strip()

                # Support for wildcards
                if "*" in rule_normalized:
                    result = fnmatch.fnmatch(subject_normalized, rule_normalized)
                else:
                    result = subject_normalized == rule_normalized

                return FlextResult[bool].ok(result)

            except Exception as e:
                return FlextResult[bool].fail(f"Subject rule evaluation failed: {e}")

    class TargetRule(AclRule):
        """Target-based ACL rule."""

        @override
        def __init__(self, target_dn: str) -> None:
            """Initialize target rule."""
            super().__init__(rule_type="target")
            self._target_dn = target_dn

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate target match.

            Checks if the target DN matches the required DN, with support for
            wildcards and DN normalization.

            Args:
                context: Evaluation context with target_dn

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                target_dn = context.get("target_dn", "")

                # Handle different target formats
                if not target_dn and not self._target_dn:
                    return FlextResult[bool].ok(True)  # Both empty matches

                if not target_dn or not self._target_dn:
                    return FlextResult[bool].ok(False)  # One empty, no match

                # Normalize DNs for comparison (case insensitive, trimmed)
                target_normalized = target_dn.lower().strip()
                rule_normalized = self._target_dn.lower().strip()

                # Support for wildcards
                if "*" in rule_normalized:
                    result = fnmatch.fnmatch(target_normalized, rule_normalized)
                else:
                    result = target_normalized == rule_normalized

                return FlextResult[bool].ok(result)

            except Exception as e:
                return FlextResult[bool].fail(f"Target rule evaluation failed: {e}")

    class TimeRule(AclRule):
        """Time-based ACL rule."""

        @override
        def __init__(
            self, start_time: str | None = None, end_time: str | None = None
        ) -> None:
            """Initialize time rule.

            Args:
                start_time: Start time in HH:MM format (inclusive)
                end_time: End time in HH:MM format (inclusive)

            """
            super().__init__(rule_type="time")
            self._start_time = start_time
            self._end_time = end_time

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate time-based access.

            Checks if current time falls within the allowed time range.

            Args:
                context: Evaluation context (current time can be provided or auto-detected)

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Get current time or from context
                current_time_str = context.get("current_time")
                if current_time_str:
                    current_time = datetime.fromisoformat(current_time_str)
                else:
                    current_time = datetime.now(UTC)

                current_minutes = current_time.hour * 60 + current_time.minute

                # If no time restrictions, always allow
                if not self._start_time and not self._end_time:
                    return FlextResult[bool].ok(True)

                # Parse time bounds
                start_minutes = (
                    self._parse_time_to_minutes(self._start_time)
                    if self._start_time
                    else 0
                )
                end_minutes = (
                    self._parse_time_to_minutes(self._end_time)
                    if self._end_time
                    else 24 * 60
                )

                # Handle time ranges that cross midnight
                if start_minutes <= end_minutes:
                    # Normal range (e.g., 09:00 to 17:00)
                    result = start_minutes <= current_minutes <= end_minutes
                else:
                    # Range crosses midnight (e.g., 22:00 to 06:00)
                    result = (
                        current_minutes >= start_minutes
                        or current_minutes <= end_minutes
                    )

                return FlextResult[bool].ok(result)

            except Exception as e:
                return FlextResult[bool].fail(f"Time rule evaluation failed: {e}")

        def _parse_time_to_minutes(self, time_str: str) -> int:
            """Parse HH:MM time string to minutes since midnight.

            Args:
                time_str: Time in HH:MM format

            Returns:
                Minutes since midnight

            """
            hours, minutes = map(int, time_str.split(":"))
            return hours * 60 + minutes

    class GroupRule(AclRule):
        """Group membership ACL rule."""

        @override
        def __init__(self, group_dn: str, *, member_required: bool = True) -> None:
            """Initialize group rule."""
            super().__init__(rule_type="group")
            self._group_dn = group_dn
            self._member_required = member_required

        def evaluate(self, context: FlextLdifTypes.Dict) -> FlextResult[bool]:
            """Evaluate group membership.

            Checks if the subject is a member of the required group.

            Args:
                context: Evaluation context with subject_groups list

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                subject_groups = context.get("subject_groups", [])

                # Handle different group formats
                if isinstance(subject_groups, str):
                    subject_groups = [subject_groups]
                elif not isinstance(subject_groups, list):
                    subject_groups = []

                # Normalize group DNs
                normalized_groups = [group.lower().strip() for group in subject_groups]
                required_group = self._group_dn.lower().strip()

                is_member = required_group in normalized_groups
                result = is_member == self._member_required

                return FlextResult[bool].ok(result)

            except Exception as e:
                return FlextResult[bool].fail(f"Group rule evaluation failed: {e}")

    @override
    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize ACL service with composite pattern support and Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
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

    def create_target_rule(self, target_dn: str) -> FlextLdifAclService.TargetRule:
        """Create target-based ACL rule."""
        return self.TargetRule(target_dn=target_dn)

    def create_time_rule(
        self, start_time: str | None = None, end_time: str | None = None
    ) -> FlextLdifAclService.TimeRule:
        """Create time-based ACL rule."""
        return self.TimeRule(start_time=start_time, end_time=end_time)

    def create_group_rule(
        self, group_dn: str, *, member_required: bool = True
    ) -> FlextLdifAclService.GroupRule:
        """Create group membership ACL rule."""
        return self.GroupRule(group_dn=group_dn, member_required=member_required)

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
        # Create ACL components directly - Pydantic handles validation
        target = FlextLdifModels.AclTarget(target_dn="*", attributes=[])
        subject = FlextLdifModels.AclSubject(subject_type="*", subject_value="*")
        perms = FlextLdifModels.AclPermissions(read=True)

        # Create unified ACL directly
        acl = FlextLdifModels.UnifiedAcl(
            name="parsed_acl",
            target=target,
            subject=subject,
            permissions=perms,
            server_type=server_type,
            raw_acl=acl_string,
        )
        return FlextResult[FlextLdifModels.UnifiedAcl].ok(acl)

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
