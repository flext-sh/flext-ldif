"""FLEXT LDIF ACL Service - Enterprise Access Control Management.

This module provides comprehensive Access Control List (ACL) management for LDIF entries
by delegating format-specific parsing to quirks.

Features:
- Quirks-based server-specific ACL syntax support (no fallback)
- Direct ACL context evaluation without unnecessary abstractions
- ACL extraction and validation with detailed error reporting
- Integration with LDIF entry processing pipeline

Architecture:
- ACL Parsing: Delegated entirely to quirks via FlextLdifRegistry (RFC/server-specific/relaxed)
- ACL Evaluation: Direct context matching against ACL attributes
- No unnecessary abstraction layers or unused pattern implementations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDecorators, FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.registry import FlextLdifRegistry


class FlextLdifAclService(FlextService[FlextLdifModels.AclResponse]):
    """Unified ACL management service.

    Provides ACL parsing via quirks and direct context evaluation.
    Keeps it simple - no unnecessary abstractions.

    Returns composed AclResponse models with extracted ACLs and statistics.

    """

    _logger: FlextLogger
    _config: FlextLdifConfig
    _registry: FlextLdifRegistry

    @override
    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize ACL service.

        Uses quirks registry for server-specific ACL handling (no fallback).

        Args:
            config: Optional FlextLdifConfig instance. If None, uses default config.

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._logger = FlextLogger(__name__)
        self._registry = FlextLdifRegistry()

    def extract_acls_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACLs from LDIF entry using server-specific quirks.

        Delegates entirely to quirks - no fallback logic.

        Args:
            entry: LDIF entry to extract ACLs from
            server_type: Server type for ACL detection (required, not optional)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        """
        # Handle None entry case
        if entry is None:
            return FlextResult[FlextLdifModels.AclResponse].fail(
                "Invalid entry: Entry is None",
            )

        # Get ACL attribute name for this server type (from quirk)
        acl_attribute = self._get_acl_attribute_for_server(server_type)
        if not acl_attribute:
            return FlextResult[FlextLdifModels.AclResponse].ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.AclStatistics(
                        total_entries_processed=1,
                        entries_with_acls=0,
                        total_acls_extracted=0,
                        acl_attribute_name=None,
                    ),
                )
            )

        acl_values: list[str] = entry.get_attribute_values(acl_attribute)

        if not acl_values:
            return FlextResult[FlextLdifModels.AclResponse].ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.AclStatistics(
                        total_entries_processed=1,
                        entries_with_acls=0,
                        total_acls_extracted=0,
                        acl_attribute_name=acl_attribute,
                    ),
                )
            )

        acls: list[FlextLdifModels.Acl] = []

        for acl_value in acl_values:
            parse_result: FlextResult[FlextLdifModels.Acl] = self.parse_acl(
                acl_value,
                server_type,
            )
            if not parse_result.is_success:
                continue
            acls.append(parse_result.value)

        return FlextResult[FlextLdifModels.AclResponse].ok(
            FlextLdifModels.AclResponse(
                acls=acls,
                statistics=FlextLdifModels.AclStatistics(
                    total_entries_processed=1,
                    entries_with_acls=1 if acls else 0,
                    total_acls_extracted=len(acls),
                    acl_attribute_name=acl_attribute,
                ),
            )
        )

    def _get_acl_attribute_for_server(self, server_type: str) -> str | None:
        """Get ACL attribute name for a given server type using quirks.

        Args:
            server_type: LDAP server type

        Returns:
            ACL attribute name or None if server type has no ACL attributes

        """
        # Get ACL attribute name from quirks - no fallback
        try:
            acl_quirks = self._registry.get_acl_quirks(server_type)
            if acl_quirks:
                # Get the ACL attribute name from the first quirk class variable
                for quirk in acl_quirks:
                    if hasattr(quirk, "acl_attribute_name"):
                        attr_name = getattr(quirk, "acl_attribute_name", None)
                        if attr_name:
                            return attr_name

            # No quirks available for this server type - return None
            # (Caller will handle appropriately)
            return None

        except (AttributeError, TypeError, ValueError):
            self._logger.exception(
                f"Failed to get ACL attribute for server type {server_type}",
            )
            return None

    @override
    @FlextDecorators.log_operation("acl_service_health_check")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[FlextLdifModels.AclResponse]:
        """Execute ACL service health check.

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing composed AclResponse with service status

        """
        return FlextResult[FlextLdifModels.AclResponse].ok(
            FlextLdifModels.AclResponse(
                acls=[],
                statistics=FlextLdifModels.AclStatistics(
                    total_entries_processed=0,
                    entries_with_acls=0,
                    total_acls_extracted=0,
                    acl_attribute_name=None,
                ),
            )
        )

    def parse_acl(
        self,
        acl_string: str,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string using server-specific quirks.

        Delegates entirely to quirks via FlextLdifRegistry. No fallback logic.

        Args:
            acl_string: Raw ACL string
            server_type: LDAP server type

        Returns:
            FlextResult containing unified ACL (or failure if quirk can't parse)

        """
        try:
            # Find the appropriate quirk that can handle this ACL line
            # Registry returns the first quirk that can_handle_acl(acl_line)
            acl_quirk = self._registry.find_acl_quirk(server_type, acl_string)
            if not acl_quirk:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"No ACL quirk available to parse for {server_type}: {acl_string[:50]}...",
                )

            # Delegate to quirk for parsing - NO FALLBACK
            # If the quirk can't parse it, the parsing fails
            return acl_quirk.parse_acl(acl_string)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing failed for {server_type}: {e}",
            )

    def convert_acl_attributes_to_aci(
        self,
        entry_data: dict[str, object],
        source_server: str,
        target_server: str,
    ) -> FlextResult[dict[str, object]]:
        """Convert _acl_attributes to proper ACI attributes using server-specific quirks.

        Uses a two-step conversion process:
        1. Source server ACLs -> RFC format (using source server quirks)
        2. RFC ACLs -> Target server ACI format (using target server quirks)

        Works on RFC as the intermediate base format with metadata preservation.

        Args:
            entry_data: Entry data with _acl_attributes metadata
            source_server: Source server type where ACLs were originally extracted
            target_server: Target server type for final ACI attribute format

        Returns:
            FlextResult with entry data containing proper ACI attributes for target server

        """
        try:
            # Make a copy to avoid modifying the original
            converted_data = dict(entry_data)

            # Check if entry has ACL attributes to convert
            acl_attrs = entry_data.get("_acl_attributes")
            if not acl_attrs or not isinstance(acl_attrs, dict):
                # No ACL attributes to convert, return as-is
                return FlextResult[dict[str, object]].ok(converted_data)

            # Step 1: Convert source ACLs to RFC format using source server quirks
            rfc_acl_attrs = (
                acl_attrs  # Assume _acl_attributes is already in internal format
            )
            if source_server.lower() != FlextLdifConstants.ServerTypes.RFC.value:
                source_quirk = self._registry.find_entry_quirk(source_server, "", {})
                if source_quirk and hasattr(source_quirk, "convert_acl_to_rfc"):
                    rfc_result = source_quirk.convert_acl_to_rfc(acl_attrs)
                    if rfc_result.is_failure:
                        return FlextResult[dict[str, object]].fail(
                            f"Source ACL to RFC conversion failed: {rfc_result.error}",
                        )
                    rfc_acl_attrs = rfc_result.unwrap()

            # Step 2: Convert RFC ACLs to target server ACI format using target server ACL quirks
            if target_server.lower() == FlextLdifConstants.ServerTypes.RFC.value:
                # Target is RFC, use the RFC ACLs directly
                final_aci_attrs = rfc_acl_attrs
            else:
                # Use ACL quirk for the target server to convert RFC ACLs to ACI format
                # ACL quirks handle the conversion from internal format to server-specific ACI format
                target_acl_quirk = self._registry.find_acl_quirk(target_server, "")
                if not target_acl_quirk:
                    return FlextResult[dict[str, object]].fail(
                        f"No ACL quirk available for target server {target_server}",
                    )

                if hasattr(target_acl_quirk, "convert_rfc_acl_to_aci"):
                    aci_result = target_acl_quirk.convert_rfc_acl_to_aci(
                        rfc_acl_attrs, target_server
                    )
                    if aci_result.is_failure:
                        return FlextResult[dict[str, object]].fail(
                            f"RFC ACL to target ACI conversion failed: {aci_result.error}",
                        )
                    final_aci_attrs = aci_result.unwrap()
                else:
                    return FlextResult[dict[str, object]].fail(
                        f"Target server ACL quirk {target_server} does not support RFC to ACI conversion",
                    )

            # Merge the final ACI attributes into the entry data
            converted_data.update(final_aci_attrs)

            # Remove the internal metadata
            converted_data.pop("_acl_attributes", None)

            return FlextResult[dict[str, object]].ok(converted_data)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[dict[str, object]].fail(
                f"ACL attribute conversion failed from {source_server} to {target_server}: {e}",
            )

    def evaluate_acl_context(
        self,
        acls: list[FlextLdifModels.Acl],
        context: dict[str, object] | None = None,
    ) -> FlextResult[bool]:
        """Evaluate ACLs against a context.

        Direct evaluation without unnecessary abstraction layers.

        Args:
            acls: List of ACL entries to evaluate
            context: Evaluation context (subject_dn, target_dn, permissions, etc.)

        Returns:
            FlextResult with boolean evaluation result

        """
        try:
            if not acls:
                # No ACLs means no restrictions - allow by default
                return FlextResult[bool].ok(True)

            eval_context = context or {}

            # Evaluate each ACL against the context
            for acl in acls:
                # Check permissions
                if hasattr(acl, "permissions") and acl.permissions:
                    perms_data = acl.permissions
                    if isinstance(perms_data, dict):
                        perms = perms_data
                    elif hasattr(perms_data, "model_dump"):
                        perms = perms_data.model_dump()
                    else:
                        perms = {}

                    # All required permissions must be present
                    # Skip the 'permissions' computed field (contains list of permission names)
                    for perm_name, perm_value in perms.items():
                        # Skip the computed 'permissions' field
                        if perm_name == "permissions":
                            continue
                        if perm_value:
                            # Check if permission is in context
                            context_perms = eval_context.get("permissions", {})
                            if isinstance(context_perms, dict):
                                if not context_perms.get(perm_name, False):
                                    return FlextResult[bool].fail(
                                        f"Permission {perm_name} not granted",
                                    )
                            elif (
                                isinstance(context_perms, list)
                                and perm_name not in context_perms
                            ):
                                return FlextResult[bool].fail(
                                    f"Permission {perm_name} not granted",
                                )

                # Check subject DN
                if hasattr(acl, "subject") and acl.subject:
                    subject_value = getattr(acl.subject, "subject_value", None)
                    if subject_value and subject_value != "*":
                        context_subject = eval_context.get("subject_dn", "")
                        if (
                            context_subject
                            and str(context_subject).lower() != subject_value.lower()
                        ):
                            return FlextResult[bool].fail(
                                f"Subject DN mismatch: {context_subject} != {subject_value}",
                            )

                # Check target DN
                if hasattr(acl, "target") and acl.target:
                    target_dn = getattr(acl.target, "target_dn", None)
                    if target_dn and target_dn != "*":
                        context_target = eval_context.get("target_dn", "")
                        if (
                            context_target
                            and str(context_target).lower() != target_dn.lower()
                        ):
                            return FlextResult[bool].fail(
                                f"Target DN mismatch: {context_target} != {target_dn}",
                            )

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"ACL evaluation failed: {e}")


__all__ = ["FlextLdifAclService"]
