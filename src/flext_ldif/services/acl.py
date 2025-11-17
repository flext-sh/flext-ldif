"""FLEXT LDIF ACL Service - Enterprise Access Control Management.

This module provides comprehensive Access Control List (ACL) management for LDIF entries
by delegating format-specific parsing to quirks.

Features:
- Quirks-based server-specific ACL syntax support (no fallback)
- Direct ACL context evaluation without unnecessary abstractions
- ACL extraction and validation with detailed error reporting
- Integration with LDIF entry processing pipeline

Architecture:
- ACL Parsing: Delegated entirely to quirks via FlextLdifServer (RFC/server-specific/relaxed)
- ACL Evaluation: Direct context matching against ACL attributes
- No unnecessary abstraction layers or unused pattern implementations

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import cast, override

from flext_core import FlextDecorators, FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifAcl(FlextService[FlextLdifModels.AclResponse]):
    """Unified ACL management service.

    Provides ACL parsing via quirks and direct context evaluation.
    Keeps it simple - no unnecessary abstractions.

    Returns composed AclResponse models with extracted ACLs and statistics.

    """

    _logger: FlextLogger
    _config: FlextLdifConfig
    _registry: FlextLdifServer

    def __init__(self, config: FlextLdifConfig | None = None) -> None:
        """Initialize ACL service.

        Uses quirks registry for server-specific ACL handling (no fallback).

        Args:
            config: Optional FlextLdifConfig instance. If None, uses default config.

        """
        super().__init__()
        self._config = config if config is not None else FlextLdifConfig()
        self._logger = FlextLogger(__name__)
        self._registry = FlextLdifServer()

    def extract_acls_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACLs from LDIF entry using server-specific quirks.

        Delegates entirely to quirks - no fallback logic.

        Args:
            entry: LDIF entry to extract ACLs from (required, not optional)
            server_type: Server type for ACL detection (required, not optional)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        """
        # Get ACL attribute name for this server type (from quirk)
        acl_attribute_result = self._get_acl_attribute_for_server(server_type)

        # Handle error case - propagate failure
        if acl_attribute_result.is_failure:
            return FlextResult[FlextLdifModels.AclResponse].fail(
                f"Failed to determine ACL attribute: {acl_attribute_result.error}",
            )

        # Extract attribute name (may be None if server has no ACL support)
        acl_attribute = acl_attribute_result.unwrap()
        if not acl_attribute:
            # Server has no ACL attributes - return empty response (success case)
            return FlextResult[FlextLdifModels.AclResponse].ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.Statistics(
                        processed_entries=1,
                        acls_extracted=0,
                        acl_attribute_name=None,
                    ),
                ),
            )

        acl_values: list[str] = entry.get_attribute_values(acl_attribute)

        if not acl_values:
            return FlextResult[FlextLdifModels.AclResponse].ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.Statistics(
                        processed_entries=1,
                        acls_extracted=0,
                        acl_attribute_name=acl_attribute,
                    ),
                ),
            )

        acls: list[FlextLdifModels.Acl] = []
        failed_acls = 0
        total_acl_values = len(acl_values)
        max_acl_log_length = 100  # Maximum ACL value length to include in error logs

        for idx, acl_value in enumerate(acl_values):
            parse_result: FlextResult[FlextLdifModels.Acl] = self.parse(
                acl_value,
                server_type,
            )
            if not parse_result.is_success:
                failed_acls += 1
                truncated_acl = (
                    acl_value[:max_acl_log_length]
                    if len(acl_value) > max_acl_log_length
                    else acl_value
                )
                self._logger.error(
                    "FAILED to parse ACL value %d/%d: %s. Entry DN: %s, Error: %s",
                    idx + 1,
                    total_acl_values,
                    truncated_acl,
                    entry.dn.value if entry.dn else "Unknown",
                    parse_result.error,
                )
                continue
            acls.append(parse_result.value)

        # Log summary if failures occurred
        if failed_acls > 0:
            self._logger.error(
                "ACL extraction completed with %d FAILURES out of %d ACL values. "
                "Successful: %d, Failed: %d",
                failed_acls,
                total_acl_values,
                len(acls),
                failed_acls,
            )

        # Create response with statistics
        response = FlextLdifModels.AclResponse(
            acls=acls,
            statistics=FlextLdifModels.Statistics(
                processed_entries=1,
                acls_extracted=len(acls),
                acls_failed=failed_acls,
                acl_attribute_name=acl_attribute,
            ),
        )

        return FlextResult[FlextLdifModels.AclResponse].ok(response)

    def _get_acl_attribute_for_server(
        self,
        server_type: str,
    ) -> FlextResult[str]:
        """Get ACL attribute name for a given server type using quirks.

        Args:
            server_type: LDAP server type

        Returns:
            FlextResult containing ACL attribute name
            Returns FlextResult.fail() if server has no ACL attributes or error occurs

        """
        # Get ACL attribute name from quirks - no fallback
        try:
            acls = self._registry.get_acls(server_type)
            if acls:
                # Get the ACL attribute name from the first quirk class variable
                for quirk in acls:
                    if hasattr(quirk, "acl_attribute_name"):
                        attr_name = getattr(quirk, "acl_attribute_name", None)
                        if attr_name and isinstance(attr_name, str):
                            # attr_name is already str from getattr - no cast needed
                            return FlextResult[str].ok(attr_name)

            # No ACL attribute for this server type - explicit failure
            # Caller must handle this case (not all servers have ACL attributes)
            return FlextResult[str].fail(
                f"No ACL attributes available for server type: {server_type}",
            )

        except (AttributeError, TypeError, ValueError) as e:
            # Error occurred - return failure
            self._logger.exception(
                "Failed to get ACL attribute for server type %s",
                server_type,
                exception=e,
            )
            return FlextResult[str].fail(
                f"Error retrieving ACL attribute for {server_type}: {e}",
            )

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
                statistics=FlextLdifModels.Statistics(
                    processed_entries=0,
                    acls_extracted=0,
                    acl_attribute_name=None,
                ),
            ),
        )

    def parse(
        self,
        acl_string: str,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string using server-specific quirks.

        Delegates entirely to quirks via FlextLdifServer. No fallback logic.

        Args:
            acl_string: Raw ACL string
            server_type: LDAP server type

        Returns:
            FlextResult containing unified ACL (or failure if quirk can't parse)

        """
        try:
            # Find the appropriate quirk that can handle this ACL line
            # Registry returns the first quirk that can_handle(acl_line)
            acl = self._registry.find_acl(server_type, acl_string)
            if not acl:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"No ACL quirk available to parse for {server_type}: {acl_string[:50]}...",
                )

            # Delegate to quirk for parsing - NO FALLBACK
            # If the quirk can't parse it, the parsing fails
            return acl.parse(acl_string)

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

            # Step 1: ACLs are expected to be in RFC-compliant format already
            # Use only private _parse_acl() method for format conversions
            rfc_acl_attrs = acl_attrs

            # Step 2: Convert RFC ACLs to target server ACI format using target server ACL quirks
            if target_server.lower() == FlextLdifConstants.ServerTypes.RFC:
                # Target is RFC, use the RFC ACLs directly
                final_aci_attrs = rfc_acl_attrs
            else:
                # Use ACL quirk for the target server to convert RFC ACLs to ACI format
                # ACL quirks handle the conversion from internal format to server-specific ACI format
                target_acl_quirk = self._registry.find_acl(target_server, "")
                if not target_acl_quirk:
                    return FlextResult[dict[str, object]].fail(
                        f"No ACL quirk available for target server {target_server}",
                    )

                # hasattr check ensures method exists - Protocol structural typing handles this
                if hasattr(target_acl_quirk, "convert_rfc_acl_to_aci"):
                    # target_acl_quirk satisfies AclProtocol via structural typing
                    acl_protocol: FlextLdifProtocols.Quirks.AclProtocol = cast(
                        "FlextLdifProtocols.Quirks.AclProtocol",
                        target_acl_quirk,
                    )
                    aci_result = acl_protocol.convert_rfc_acl_to_aci(
                        rfc_acl_attrs,
                        target_server,
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

    @staticmethod
    def _extract_permissions(acl: FlextLdifModels.Acl) -> dict[str, object]:
        """Extract permissions dictionary from ACL.

        Args:
            acl: ACL model instance

        Returns:
            Dictionary of permissions

        """
        if not hasattr(acl, "permissions") or not acl.permissions:
            return {}

        perms_data = acl.permissions
        if isinstance(perms_data, dict):
            return perms_data

        # Access permissions fields directly from model
        if isinstance(perms_data, FlextLdifModels.AclPermissions):
            return {
                "read": perms_data.read,
                "write": perms_data.write,
                "add": perms_data.add,
                "delete": perms_data.delete,
                "search": perms_data.search,
                "compare": perms_data.compare,
                "self_write": perms_data.self_write,
                "proxy": perms_data.proxy,
            }

        return {}

    @staticmethod
    def _validate_permissions(
        perms: dict[str, object],
        context: dict[str, object],
    ) -> FlextResult[bool]:
        """Validate permissions against context.

        Args:
            perms: ACL permissions dictionary
            context: Evaluation context

        Returns:
            FlextResult with validation result

        """
        for perm_name, perm_value in perms.items():
            # Skip the computed 'permissions' field
            if perm_name == "permissions":
                continue

            if not perm_value:
                continue

            # Check if permission is in context
            context_perms = context.get("permissions", {})

            if isinstance(context_perms, dict):
                if not context_perms.get(perm_name, False):
                    return FlextResult[bool].fail(f"Permission {perm_name} not granted")
            elif isinstance(context_perms, list) and perm_name not in context_perms:
                return FlextResult[bool].fail(f"Permission {perm_name} not granted")

        return FlextResult[bool].ok(True)

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

            # Use empty dict as default value, not fallback
            eval_context: dict[str, object] = context if context is not None else {}

            # Evaluate each ACL against the context
            for acl in acls:
                # Extract and validate permissions using helper
                perms = self._extract_permissions(acl)
                if perms:
                    result = self._validate_permissions(perms, eval_context)
                    if result.is_failure:
                        return result

                # Validate subject DN using FlextLdifUtilities
                subject_value = (
                    getattr(acl.subject, "subject_value", None)
                    if hasattr(acl, "subject") and acl.subject
                    else None
                )
                context_subject = (
                    str(eval_context.get("subject_dn"))
                    if eval_context.get("subject_dn")
                    else None
                )
                result = FlextLdifUtilities.DN.validate_dn_with_context(
                    subject_value,
                    context_subject,
                    "subject DN",
                )
                if result.is_failure:
                    return result

                # Validate target DN using FlextLdifUtilities
                target_dn = (
                    getattr(acl.target, "target_dn", None)
                    if hasattr(acl, "target") and acl.target
                    else None
                )
                context_target = (
                    str(eval_context.get("target_dn"))
                    if eval_context.get("target_dn")
                    else None
                )
                result = FlextLdifUtilities.DN.validate_dn_with_context(
                    target_dn,
                    context_target,
                    "target DN",
                )
                if result.is_failure:
                    return result

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"ACL evaluation failed: {e}")


__all__ = ["FlextLdifAcl"]
