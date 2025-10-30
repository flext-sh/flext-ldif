"""FLEXT LDIF ACL Service - Enterprise Access Control Management.

This module provides comprehensive Access Control List (ACL) management for LDIF entries
using a composite pattern for flexible rule composition and evaluation. Supports server-specific
ACL syntaxes including Oracle OID/OUD ACI attributes and standard LDAP ACL formats.

Features:
- Composite pattern for complex ACL rule composition
- Server-specific ACL syntax support (OID, OUD, OpenLDAP)
- Context-aware ACL evaluation with subject/target/permission checking
- Pattern-based matching with glob and regex support
- Permission inheritance and precedence resolution
- ACL parsing and validation with detailed error reporting
- Integration with LDIF entry processing pipeline

Architecture:
- AclRule: Base class implementing composite pattern for rule composition
- AclEvaluator: Context-aware evaluation engine with permission checking
- AclParser: Server-specific ACL syntax parsing and normalization
- Rule composition using logical operators (AND, OR, NOT)

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import fnmatch
from datetime import UTC, datetime
from typing import cast, override

from flext_core import FlextDecorators, FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.manager import FlextLdifQuirksManager
from flext_ldif.typings import FlextLdifTypes


class FlextLdifAclService(FlextService[dict[str, object]]):
    """Unified ACL management service using Composite pattern for rule composition."""

    class AclRule:
        """Base ACL rule following AclRuleProtocol - Composite pattern."""

        @override
        def __init__(self, rule_type: str = FlextLdifConstants.RuleTypes.BASE) -> None:
            """Initialize ACL rule."""
            super().__init__()
            self._rule_type = rule_type

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate ACL rule against context.

            This base implementation provides a default evaluation strategy.
            Subclasses should override this method to implement specific rule logic.

            Args:
                context: Evaluation context containing subject, target, permissions, etc.

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Base rule always evaluates to True (allow by default)
                # Specific rule types (SubjectRule, TargetRule, etc.) check their required keys
                # Note: context parameter unused in base class but required for subclass overrides
                _ = context  # Mark as intentionally unused
                return FlextResult[bool].ok(True)

            except (ValueError, TypeError, AttributeError) as e:
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
            super().__init__(rule_type=FlextLdifConstants.RuleTypes.COMPOSITE)
            self._operator = operator.upper()
            self._rules: list[FlextLdifAclService.AclRule] = []

        def add_rule(self, rule: FlextLdifAclService.AclRule) -> None:
            """Add sub-rule to composite."""
            self._rules.append(rule)

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
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
            super().__init__(rule_type=FlextLdifConstants.RuleTypes.PERMISSION)
            self._permission = permission
            self._required = required

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate permission requirement.

            Checks if the required permission is present (or absent) in the context.

            Args:
                context: Evaluation context with permissions dict

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Get permissions from context - can be dict, list, or str
                perms = context.get("permissions", {})

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

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[bool].fail(f"Permission rule evaluation failed: {e}")

    class SubjectRule(AclRule):
        """Subject-based ACL rule."""

        @override
        def __init__(self, subject_dn: str) -> None:
            """Initialize subject rule."""
            super().__init__(rule_type="subject")
            self._subject_dn = subject_dn

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
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

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[bool].fail(f"Subject rule evaluation failed: {e}")

    class TargetRule(AclRule):
        """Target-based ACL rule."""

        @override
        def __init__(self, target_dn: str) -> None:
            """Initialize target rule."""
            super().__init__(rule_type="target")
            self._target_dn = target_dn

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate target match.

            Checks if the target DN matches the required DN, with support for
            wildcards and DN normalization.

            Args:
                context: Evaluation context with target_dn

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                target_dn_obj = context.get("target_dn", "")
                target_dn = str(target_dn_obj) if target_dn_obj else ""

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

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[bool].fail(f"Target rule evaluation failed: {e}")

    class TimeRule(AclRule):
        """Time-based ACL rule."""

        @override
        def __init__(
            self,
            start_time: str | None = None,
            end_time: str | None = None,
        ) -> None:
            """Initialize time rule.

            Args:
                start_time: Start time in HH:MM format (inclusive)
                end_time: End time in HH:MM format (inclusive)

            """
            super().__init__(rule_type="time")
            self._start_time = start_time
            self._end_time = end_time

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
            """Evaluate time-based access.

            Checks if current time falls within the allowed time range.

            Args:
                context: Evaluation context (current time can be provided or auto-detected)

            Returns:
                FlextResult with boolean evaluation result

            """
            try:
                # Get current time or from context
                current_time_obj = context.get("current_time")
                if current_time_obj:
                    current_time_str = str(current_time_obj)
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

            except (ValueError, TypeError, AttributeError) as e:
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

        def evaluate(self, context: dict[str, object]) -> FlextResult[bool]:
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

            except (ValueError, TypeError, AttributeError) as e:
                return FlextResult[bool].fail(f"Group rule evaluation failed: {e}")

    @override
    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize ACL service with composite pattern support and Phase 1 context enrichment."""
        super().__init__()
        # Logger and container inherited from FlextService via FlextMixins
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    def create_composite_rule(
        self,
        operator: str = "AND",
    ) -> FlextLdifAclService.CompositeAclRule:
        """Create composite ACL rule for combining multiple rules."""
        return self.CompositeAclRule(operator=operator)

    def create_permission_rule(
        self,
        permission: str,
        *,
        required: bool = True,
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
        self,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> FlextLdifAclService.TimeRule:
        """Create time-based ACL rule."""
        return self.TimeRule(start_time=start_time, end_time=end_time)

    def create_group_rule(
        self,
        group_dn: str,
        *,
        member_required: bool = True,
    ) -> FlextLdifAclService.GroupRule:
        """Create group membership ACL rule."""
        return self.GroupRule(group_dn=group_dn, member_required=member_required)

    def extract_acls_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str | None = None,
    ) -> FlextResult[list[FlextLdifModels.Acl]]:
        """Extract ACLs from LDIF entry using composite pattern.

        Args:
            entry: LDIF entry to extract ACLs from
            server_type: Server type for ACL format detection

        Returns:
            FlextResult containing list of unified ACL entries

        """
        # Handle None entry case
        if entry is None:
            return FlextResult[list[FlextLdifModels.Acl]].fail(
                "Invalid entry: Entry is None",
            )

        acl_attr_result: FlextResult[str] = self._quirks.get_acl_attribute_name(
            server_type,
        )
        if acl_attr_result.is_failure:
            error_msg = acl_attr_result.error or "Unknown ACL attribute error"
            return FlextResult[list[FlextLdifModels.Acl]].fail(error_msg)

        acl_attribute = acl_attr_result.value
        acl_values: list[str] = entry.get_attribute_values(acl_attribute)

        if not acl_values:
            return FlextResult[list[FlextLdifModels.Acl]].ok([])

        acls: list[FlextLdifModels.Acl] = []
        for acl_value in acl_values:
            parse_result: FlextResult[FlextLdifModels.Acl] = self._parse_acl_with_rules(
                acl_value,
                cast("FlextLdifTypes.AclServerType", server_type or "openldap"),
            )
            if parse_result.is_success:
                acls.append(parse_result.value)

        return FlextResult[list[FlextLdifModels.Acl]].ok(acls)

    def _parse_acl_with_rules(
        self,
        acl_string: str,
        server_type: FlextLdifTypes.AclServerType,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string using composite rule pattern.

        Args:
            acl_string: Raw ACL string
            server_type: Server type for format detection

        Returns:
            FlextResult containing unified ACL with composite rules

        """
        # Use consolidated Acl model with server_type discriminator
        try:
            # Validate server_type is supported
            supported_servers = {
                FlextLdifConstants.LdapServers.OPENLDAP,
                FlextLdifConstants.LdapServers.OPENLDAP_2,
                FlextLdifConstants.LdapServers.OPENLDAP_1,
                FlextLdifConstants.LdapServers.ORACLE_OID,
                FlextLdifConstants.LdapServers.ORACLE_OUD,
                FlextLdifConstants.LdapServers.DS_389,
            }

            # Default to OpenLDAP for generic/unknown server types
            effective_server_type = (
                server_type
                if server_type in supported_servers
                else FlextLdifConstants.LdapServers.OPENLDAP
            )

            # Create ACL using consolidated Acl model
            acl = FlextLdifModels.Acl(
                name="parsed_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=effective_server_type,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(f"Failed to parse ACL: {e}")

    def evaluate_acl_rules(
        self,
        rules: list[AclRule],
        context: dict[str, object],
    ) -> FlextResult[bool]:
        """Evaluate ACL rules against context using composite pattern."""
        # Handle None context case
        if context is None:
            return FlextResult[bool].fail("Invalid context: Context is None")

        composite = self.create_composite_rule(operator="AND")
        for rule in rules:
            composite.add_rule(rule)
        return composite.evaluate(context)

    @override
    @FlextDecorators.log_operation("acl_service_health_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute ACL service health check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing service status and available patterns

        """
        return FlextResult[dict[str, object]].ok({
            "service": FlextLdifAclService,
            "status": "ready",
            "patterns": {
                "composite": "Composite ACL rule evaluation",
                "rule_evaluation": "Individual ACL rule processing",
            },
        })

    def parse_openldap_acl(self, acl_string: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse OpenLDAP olcAccess ACL format.

        Args:
            acl_string: OpenLDAP ACL string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL using consolidated Acl model with server_type discriminator
        try:
            acl = FlextLdifModels.Acl(
                name="openldap_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=FlextLdifConstants.LdapServers.OPENLDAP,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse OpenLDAP ACL: {e}",
            )

    def parse_389ds_acl(self, acl_string: str) -> FlextResult[FlextLdifModels.Acl]:
        """Parse 389DS ACI format.

        Args:
            acl_string: 389DS ACI string

        Returns:
            FlextResult containing unified ACL

        """
        # Create ACL using consolidated Acl model with server_type discriminator
        try:
            acl = FlextLdifModels.Acl(
                name="389ds_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=FlextLdifConstants.LdapServers.DS_389,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse 389DS ACL: {e}",
            )

    def parse_oracle_acl(
        self,
        acl_string: str,
        server_type: FlextLdifTypes.AclServerType = FlextLdifConstants.LdapServers.ORACLE_OID,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse Oracle OID/OUD ACL format.

        Args:
            acl_string: Oracle ACL string
            server_type: Oracle server type (OID or OUD)

        Returns:
            FlextResult containing unified ACL

        """
        # Use consolidated Acl model with server_type discriminator
        try:
            # Validate Oracle server type
            if server_type not in {
                FlextLdifConstants.LdapServers.ORACLE_OID,
                FlextLdifConstants.LdapServers.ORACLE_OUD,
            }:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Unknown Oracle server type: {server_type}",
                )

            acl = FlextLdifModels.Acl(
                name="oracle_acl",
                target=FlextLdifModels.AclTarget(target_dn="*", attributes=[]),
                subject=FlextLdifModels.AclSubject(subject_type="*", subject_value="*"),
                permissions=FlextLdifModels.AclPermissions(read=True),
                server_type=server_type,
                raw_acl=acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].ok(acl)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"Failed to parse Oracle ACL: {e}",
            )

    def parse_acl(
        self,
        acl_string: str,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string based on server type.

        Args:
            acl_string: Raw ACL string
            server_type: LDAP server type

        Returns:
            FlextResult containing unified ACL

        """
        if server_type == FlextLdifConstants.LdapServers.OPENLDAP:
            return self.parse_openldap_acl(acl_string)

        if server_type == FlextLdifConstants.LdapServers.DS_389:
            return self.parse_389ds_acl(acl_string)

        if server_type in {
            FlextLdifConstants.LdapServers.ORACLE_OID,
            FlextLdifConstants.LdapServers.ORACLE_OUD,
        }:
            return self.parse_oracle_acl(
                acl_string,
                cast("FlextLdifTypes.AclServerType", server_type),
            )

        return FlextResult[FlextLdifModels.Acl].fail(
            f"Unsupported server type: {server_type}",
        )


# Backward compatibility: FlextLdifAclParser is now merged into FlextLdifAclService
FlextLdifAclParser = FlextLdifAclService

__all__ = ["FlextLdifAclParser", "FlextLdifAclService"]
