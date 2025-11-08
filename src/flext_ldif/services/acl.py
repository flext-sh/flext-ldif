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

import time
import uuid
from datetime import UTC, datetime
from typing import cast, override

from flext_core import FlextDecorators, FlextLogger, FlextResult, FlextService

from flext_ldif.config import FlextLdifConfig
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
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
            entry: LDIF entry to extract ACLs from
            server_type: Server type for ACL detection (required, not optional)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        """
        # Track ACL extraction metrics (MANDATORY - eventos obrigatórios)
        start_time = time.perf_counter()

        # Handle None entry case
        if entry is None:
            return FlextResult[FlextLdifModels.AclResponse].fail(
                "Invalid entry: Entry is None",
            )

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

        # Create response
        response = FlextLdifModels.AclResponse(
            acls=acls,
            statistics=FlextLdifModels.Statistics(
                processed_entries=1,
                acls_extracted=len(acls),
                acls_failed=failed_acls,
                acl_attribute_name=acl_attribute,
            ),
        )

        # Emit AclEvent ALWAYS (MANDATORY - eventos obrigatórios)
        acl_duration_ms = (time.perf_counter() - start_time) * 1000.0

        acl_event = FlextLdifModels.AclEvent(
            unique_id=f"acl_{uuid.uuid4().hex[:8]}",
            event_type="ldif.acl",
            aggregate_id=str(entry.dn) if entry.dn else f"acl_{uuid.uuid4().hex[:8]}",
            created_at=datetime.now(UTC),
            acl_operation="extract_from_entry",
            entries_processed=1,
            acls_extracted=len(acls),
            extraction_duration_ms=acl_duration_ms,
            server_type=server_type,
            acl_format=server_type,
        )
        # Attach event to AclResponse statistics
        updated_stats = response.statistics.add_event(acl_event)
        response = response.model_copy(update={"statistics": updated_stats})

        return FlextResult[FlextLdifModels.AclResponse].ok(response)

    def _get_acl_attribute_for_server(
        self,
        server_type: str,
    ) -> FlextResult[str | None]:
        """Get ACL attribute name for a given server type using quirks.

        Args:
            server_type: LDAP server type

        Returns:
            FlextResult containing ACL attribute name or None if server has no ACL attributes
            Returns FlextResult.fail() if error occurs during quirk lookup

        """
        # Get ACL attribute name from quirks - no fallback
        try:
            acls = self._registry.get_acls(server_type)
            if acls:
                # Get the ACL attribute name from the first quirk class variable
                for quirk in acls:
                    if hasattr(quirk, "acl_attribute_name"):
                        attr_name = getattr(quirk, "acl_attribute_name", None)
                        if attr_name:
                            return FlextResult[str | None].ok(cast("str", attr_name))

            # No quirks available for this server type - return success with None
            # This is a legitimate case (not all servers have ACL attributes)
            return FlextResult[str | None].ok(None)

        except (AttributeError, TypeError, ValueError) as e:
            # Error occurred - return failure (not silent None)
            self._logger.exception(
                f"Failed to get ACL attribute for server type {server_type}",
                exception=e,
            )
            return FlextResult[str | None].fail(
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
                target_acl = self._registry.find_acl(target_server, "")
                if not target_acl:
                    return FlextResult[dict[str, object]].fail(
                        f"No ACL quirk available for target server {target_server}",
                    )

                if hasattr(target_acl, "convert_rfc_acl_to_aci"):
                    aci_result = target_acl.convert_rfc_acl_to_aci(
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
            return cast("dict[str, object]", perms_data)
        if hasattr(perms_data, "model_dump"):
            return cast("dict[str, object]", perms_data.model_dump())

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

    @staticmethod
    def _validate_subject_dn(
        acl: FlextLdifModels.Acl,
        context: dict[str, object],
    ) -> FlextResult[bool]:
        """Validate subject DN against context using FlextLdifUtilities.

        Args:
            acl: ACL model instance
            context: Evaluation context

        Returns:
            FlextResult with validation result

        """
        if not hasattr(acl, "subject") or not acl.subject:
            return FlextResult[bool].ok(True)

        subject_value = getattr(acl.subject, "subject_value", None)
        if not subject_value or subject_value == "*":
            return FlextResult[bool].ok(True)

        # Validate subject DN using FlextLdifUtilities.DN
        if (
            subject_value
            and subject_value != "*"
            and not FlextLdifUtilities.DN.validate(subject_value)
        ):
            return FlextResult[bool].fail(
                f"Invalid subject DN format per RFC 4514: {subject_value}",
            )

        context_subject = context.get("subject_dn", "")
        if context_subject:
            # Use FlextLdifUtilities for case-insensitive DN comparison
            comparison_result = FlextLdifUtilities.DN.compare_dns(
                str(context_subject),
                subject_value,
            )
            if comparison_result != 0:  # 0 means equal
                return FlextResult[bool].fail(
                    f"Subject DN mismatch: {context_subject} != {subject_value}",
                )

        return FlextResult[bool].ok(True)

    @staticmethod
    def _validate_target_dn(
        acl: FlextLdifModels.Acl,
        context: dict[str, object],
    ) -> FlextResult[bool]:
        """Validate target DN against context using FlextLdifUtilities.

        Args:
            acl: ACL model instance
            context: Evaluation context

        Returns:
            FlextResult with validation result

        """
        if not hasattr(acl, "target") or not acl.target:
            return FlextResult[bool].ok(True)

        target_dn = getattr(acl.target, "target_dn", None)
        if not target_dn or target_dn == "*":
            return FlextResult[bool].ok(True)

        # Validate target DN using FlextLdifUtilities.DN
        if (
            target_dn
            and target_dn != "*"
            and not FlextLdifUtilities.DN.validate(target_dn)
        ):
            return FlextResult[bool].fail(
                f"Invalid target DN format per RFC 4514: {target_dn}",
            )

        context_target = context.get("target_dn", "")
        if context_target:
            # Use FlextLdifUtilities for case-insensitive DN comparison
            comparison_result = FlextLdifUtilities.DN.compare_dns(
                str(context_target),
                target_dn,
            )
            if comparison_result != 0:  # 0 means equal
                return FlextResult[bool].fail(
                    f"Target DN mismatch: {context_target} != {target_dn}",
                )

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

            eval_context = context or {}

            # Evaluate each ACL against the context
            for acl in acls:
                # Extract and validate permissions using helper
                perms = self._extract_permissions(acl)
                if perms:
                    result = self._validate_permissions(perms, eval_context)
                    if result.is_failure:
                        return result

                # Validate subject DN using helper
                result = self._validate_subject_dn(acl, eval_context)
                if result.is_failure:
                    return result

                # Validate target DN using helper
                result = self._validate_target_dn(acl, eval_context)
                if result.is_failure:
                    return result

            return FlextResult[bool].ok(True)

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[bool].fail(f"ACL evaluation failed: {e}")


__all__ = ["FlextLdifAcl"]
