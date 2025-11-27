"""FLEXT LDIF ACL Service - Enterprise Access Control Management.

This module provides comprehensive Access Control List (ACL) management for LDIF entries
by delegating format-specific parsing to quirks via FlextLdifServer DI.

Features:
- Quirks-based server-specific ACL syntax support (no fallback)
- Direct ACL context evaluation without unnecessary abstractions
- ACL extraction and validation with detailed error reporting
- Entry extraction with ACL attributes (excluding schema entries)
- Integration with LDIF entry processing pipeline
- Metadata management via FlextLdifUtilities.Metadata

Architecture:
- ACL Parsing: Delegated entirely to quirks via FlextLdifServer (RFC/server-specific/relaxed)
- ACL Evaluation: Direct context matching against ACL attributes
- Entry Extraction: Filtering entries with ACL attributes (excluding schema)
- Metadata: Uses FlextLdifUtilities.Metadata for all metadata operations
- No server-specific knowledge in service layer - all via FlextLdifServer DI

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_core import FlextDecorators, FlextResult, FlextRuntime

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.protocols import FlextLdifProtocols
from flext_ldif.servers.base import FlextLdifServersBase
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifAcl(FlextLdifServiceBase[FlextLdifModels.ServiceStatus]):
    """Unified ACL management service.

    Provides ACL parsing via quirks and direct context evaluation.
    Keeps it simple - no unnecessary abstractions.

    Returns composed AclResponse models with extracted ACLs and statistics.

    Config access via self.config.ldif (inherited from FlextLdifServiceBase).
    """

    _registry: FlextLdifServer

    def __init__(self) -> None:
        """Initialize ACL service.

        Uses quirks registry for server-specific ACL handling (no fallback).
        Config is accessed via self.config.ldif (inherited from FlextLdifServiceBase).
        """
        super().__init__()
        self._registry = FlextLdifServer()

    def extract_acls_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: str,
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACLs from LDIF entry using server-specific quirks.

        Delegates entirely to quirks - no fallback logic.

        Args:
            entry: LDIF entry to extract ACLs from (guaranteed non-None by type)
            server_type: Server type for ACL detection (required, not optional)

        Returns:
            FlextResult containing composed AclResponse with extracted ACLs and statistics

        Note:
            - Uses FlextResult for error handling - no None returns

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

        # Type annotation guarantees entry is not None after validation
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
                (
                    acl_value[:max_acl_log_length]
                    if len(acl_value) > max_acl_log_length
                    else acl_value
                )
                self.logger.warning(
                    "Failed to parse ACL value",
                    acl_index=idx + 1,
                    total_acl_values=total_acl_values,
                    server_type=server_type,
                    entry_dn=entry.dn.value if entry.dn else "unknown",
                    error=str(parse_result.error),
                )
                continue

            parsed_acl = parse_result.unwrap()
            # Preserve entry metadata in ACL metadata using FlextLdifUtilities.Metadata
            if entry.metadata:
                # Ensure ACL has metadata
                if not parsed_acl.metadata:
                    parsed_acl.metadata = FlextLdifModels.QuirkMetadata.create_for(
                        server_type,
                    )
                # Track ACL extraction from entry preserving original entry metadata
                FlextLdifUtilities.Metadata.track_minimal_differences_in_metadata(
                    metadata=parsed_acl.metadata,
                    original=acl_value,
                    converted=None,
                    context="acl_extraction",
                    attribute_name=acl_attribute,
                )
                # Preserve entry metadata extensions in ACL metadata
                if entry.metadata.extensions:
                    if not parsed_acl.metadata.extensions:
                        parsed_acl.metadata.extensions = {}
                    # Copy relevant entry metadata extensions to ACL metadata
                    entry_dn = entry.dn.value if entry.dn else "unknown"
                    parsed_acl.metadata.extensions[
                        FlextLdifConstants.MetadataKeys.ENTRY_SOURCE_DN_CASE
                    ] = entry_dn
            acls.append(parsed_acl)

        # FlextLdifModels.Acl inherits from FlextLdifModelsDomains.Acl
        # No conversion needed - use directly
        return FlextResult[FlextLdifModels.AclResponse].ok(
            FlextLdifModels.AclResponse(
                acls=list(acls),
                statistics=FlextLdifModels.Statistics(
                    processed_entries=1,
                    acls_extracted=len(acls),
                    acl_attribute_name=acl_attribute,
                    failed_entries=failed_acls,
                ),
            ),
        )

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
            acl_quirk = self._registry.acl(server_type)
            if (
                acl_quirk
                and hasattr(acl_quirk, "acl_attribute_name")
                and isinstance(
                    attr_name := getattr(acl_quirk, "acl_attribute_name", None),
                    str,
                )
            ):
                # attr_name is already str from getattr - no cast needed
                return FlextResult[str].ok(attr_name)

            # No ACL attribute for this server type - explicit failure
            # Caller must handle this case (not all servers have ACL attributes)
            return FlextResult[str].fail(
                f"No ACL attributes available for server type: {server_type}",
            )

        except (AttributeError, TypeError, ValueError) as e:
            # Error occurred - return failure
            self.logger.exception(
                "Failed to get ACL attribute",
                server_type=server_type,
                error=str(e),
            )
            return FlextResult[str].fail(
                f"Error retrieving ACL attribute for {server_type}: {e}",
            )

    @override
    @FlextDecorators.log_operation("acl_service_execute")
    @FlextDecorators.track_performance()
    def execute(self) -> FlextResult[FlextLdifModels.ServiceStatus]:
        """Execute ACL service with empty initialization.

        Returns empty AclResponse with no ACLs extracted. This serves as a baseline
        for ACL processing - callers use parse() and evaluate_acl_context() methods.

        Args:
            None

        FlextDecorators automatically:
        - Log operation start/completion/failure
        - Track performance metrics
        - Handle context propagation (correlation_id, operation_name)

        Returns:
            FlextResult containing empty AclResponse

        """
        return FlextResult[FlextLdifModels.ServiceStatus].ok(
            FlextLdifModels.ServiceStatus(
                service="acl",
                status="operational",
                rfc_compliance="RFC 2849",
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
            # Registry returns the quirk that can_handle(acl_line)
            acl = self._registry.acl(server_type)
            if not acl:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"No ACL quirk available to parse for {server_type}: {acl_string[:50]}...",
                )

            # Delegate to quirk for parsing - NO FALLBACK
            # If the quirk can't parse it, the parsing fails
            # Validate protocol compliance using isinstance
            if not isinstance(acl, FlextLdifProtocols.Quirks.AclProtocol):
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"ACL quirk for {server_type} does not implement AclProtocol",
                )
            # acl is now typed as AclProtocol - no cast needed
            parse_result = acl.parse(acl_string)
            # Type narrowing: parse returns FlextResult[Acl]
            if parse_result.is_success:
                parsed_acl = parse_result.unwrap()
                return FlextResult[FlextLdifModels.Acl].ok(parsed_acl)
            self.logger.warning(
                "Failed to parse ACL",
                server_type=server_type,
                error=str(parse_result.error),
                acl_preview=acl_string[: FlextLdifConstants.ACI_PREVIEW_LENGTH]
                if len(acl_string) > FlextLdifConstants.ACI_PREVIEW_LENGTH
                else acl_string,
            )
            return FlextResult[FlextLdifModels.Acl].fail(
                parse_result.error or "Unknown error",
            )

        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[FlextLdifModels.Acl].fail(
                f"ACL parsing failed for {server_type}: {e}",
            )

    @staticmethod
    def _extract_permissions(
        acl: FlextLdifModels.Acl,
    ) -> FlextLdifTypes.Acl.PermissionsDict:
        """Extract permissions dictionary from ACL.

        Args:
            acl: ACL model instance

        Returns:
            Dictionary of permissions

        """
        if not hasattr(acl, "permissions") or not acl.permissions:
            return {}

        perms_data = acl.permissions
        if FlextRuntime.is_dict_like(perms_data):
            # Type narrowing: is_dict_like ensures dict[str, object]
            # Convert to PermissionsDict type
            raw_perms = dict(perms_data)
            return FlextLdifTypes.Acl.PermissionsDict(
                read=bool(raw_perms.get("read")),
                write=bool(raw_perms.get("write")),
                add=bool(raw_perms.get("add")),
                delete=bool(raw_perms.get("delete")),
                search=bool(raw_perms.get("search")),
                compare=bool(raw_perms.get("compare")),
                self_write=bool(raw_perms.get("self_write")),
                proxy=bool(raw_perms.get("proxy")),
                browse=bool(raw_perms.get("browse")),
                auth=bool(raw_perms.get("auth")),
                all=bool(raw_perms.get("all")),
            )

        # Access permissions fields directly from model
        if isinstance(perms_data, FlextLdifModels.AclPermissions):
            return FlextLdifTypes.Acl.PermissionsDict(
                read=perms_data.read,
                write=perms_data.write,
                add=perms_data.add,
                delete=perms_data.delete,
                search=perms_data.search,
                compare=perms_data.compare,
                self_write=perms_data.self_write,
                proxy=perms_data.proxy,
                browse=False,  # Not in AclPermissions model
                auth=False,  # Not in AclPermissions model
                all=False,  # Not in AclPermissions model
            )

        return FlextLdifTypes.Acl.PermissionsDict()

    @staticmethod
    def _validate_permissions(
        perms: FlextLdifTypes.Acl.PermissionsDict,
        context: FlextLdifTypes.Acl.EvaluationContextDict,
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

            if FlextRuntime.is_dict_like(context_perms):
                # Type narrowing: is_dict_like ensures dict[str, object]
                perms_dict = dict(context_perms)
                if not perms_dict.get(perm_name):
                    return FlextResult[bool].fail(f"Permission {perm_name} not granted")
            elif (
                FlextRuntime.is_list_like(context_perms)
                and perm_name not in context_perms
            ):
                return FlextResult[bool].fail(f"Permission {perm_name} not granted")

        return FlextResult[bool].ok(True)

    def evaluate_acl_context(
        self,
        acls: list[FlextLdifModels.Acl],
        context: FlextLdifTypes.Acl.EvaluationContextDict | None = None,
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
            eval_context: FlextLdifTypes.Acl.EvaluationContextDict = (
                context if context is not None else {}
            )

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

    def get_acls_for_transformation(
        self,
        source_type: str,
        target_type: str,
    ) -> FlextResult[tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]]:
        """Get ACL quirks for source and target servers.

        Internal helper method to reduce complexity in transform_acl_entries() method.

        Args:
            source_type: Source server type string
            target_type: Target server type string

        Returns:
            FlextResult containing tuple of (source_acl, target_acl) or failure if not available

        """
        # Get schema quirks for source and target
        source = self._registry.schema(source_type)
        target = self._registry.schema(target_type)

        if source is None or target is None:
            return FlextResult[
                tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
            ].fail(
                f"Schema quirks not available for source={source_type} or target={target_type}",
            )

        # Extract ACL quirks from schema quirks
        source_acl = getattr(source, "acl", None) if hasattr(source, "acl") else None
        target_acl = getattr(target, "acl", None) if hasattr(target, "acl") else None

        if source_acl is None or target_acl is None:
            return FlextResult[
                tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
            ].fail(
                f"ACL quirks not available for source={source_type} or target={target_type}",
            )

        return FlextResult[
            tuple[FlextLdifServersBase.Acl, FlextLdifServersBase.Acl]
        ].ok((source_acl, target_acl))

    def transform_acl_in_entry(
        self,
        entry: FlextLdifModels.Entry,
        source_type: str,
        target_type: str,
    ) -> FlextResult[FlextLdifModels.Entry]:
        """Transform ACL attributes in a single entry.

        Internal helper method to reduce complexity in transform_acl_entries() method.

        Args:
            entry: Entry to transform
            source_type: Source server type string
            target_type: Target server type string

        Returns:
            FlextResult containing transformed entry (or original if no ACLs)

        """
        # Check if entry has any ACL attributes
        if not entry.attributes.attributes:
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        attrs = entry.attributes.attributes
        # Use constants for ACL attribute detection
        acl_attrs_lower = {
            attr.lower() for attr in FlextLdifConstants.AclAttributes.ALL_ACL_ATTRIBUTES
        }
        has_acl = any(key.lower() in acl_attrs_lower for key in attrs)

        if not has_acl:
            # No ACL attributes, pass through unchanged
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        # Get ACL quirks for transformation
        acls_result = self.get_acls_for_transformation(
            source_type,
            target_type,
        )

        if acls_result.is_failure:
            # No ACL transformation available for this server pair
            dn_str = entry.dn.value
            self.logger.debug(
                "ACL quirks not available, passing entry unchanged",
                source_type=source_type,
                target_type=target_type,
                entry_dn=dn_str,
                error=str(acls_result.error),
            )
            return FlextResult[FlextLdifModels.Entry].ok(entry)

        _source_acl, _target_acl = acls_result.unwrap()

        # ACL transformation between different server types is complex and requires
        # server-specific semantics. Currently not implemented - return failure to prevent
        # silent data loss from ACL transformations.
        dn_value = entry.dn.value
        return FlextResult[FlextLdifModels.Entry].fail(
            (
                f"ACL transformation not yet supported for {source_type}→{target_type}: "
                f"entry with ACLs requires manual validation (DN: {dn_value})"
            ),
        )

    def transform_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        source_server: str | type[FlextLdifConstants.ServerTypes],
        target_server: str | type[FlextLdifConstants.ServerTypes],
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Transform ACL attributes from source to target server format.

        This is the ONLY way to transform ACLs through the facade. Internal quirks
        are accessed here, but consumers never see them directly. This ensures:
        - Consistent ACL transformation across all consuming code
        - Proper validation of transformation results
        - Centralized error handling and logging
        - Server-specific quirks remain private implementation details

        Args:
            entries: List of entries with ACL attributes in source format
            source_server: Source server type (obtained via FlextLdifServer)
            target_server: Target server type (obtained via FlextLdifServer)

        Returns:
            FlextResult containing list of entries with ACL attributes in target format

        Raises:
            Returns FlextResult.fail() if transformation fails

        """
        try:
            if not entries:
                return FlextResult[list[FlextLdifModels.Entry]].ok([])

            # Normalize server type strings if needed
            source_type = (
                source_server
                if isinstance(source_server, str)
                else getattr(source_server, "value", str(source_server))
            )
            target_type = (
                target_server
                if isinstance(target_server, str)
                else getattr(target_server, "value", str(target_server))
            )

            transformed_entries: list[FlextLdifModels.Entry] = []
            transformation_errors: list[tuple[str, str]] = []

            # Process each entry
            for entry in entries:
                try:
                    transform_result = self.transform_acl_in_entry(
                        entry,
                        source_type,
                        target_type,
                    )
                    if transform_result.is_success:
                        transformed_entries.append(transform_result.unwrap())
                    else:
                        dn_str = entry.dn.value
                        transformation_errors.append((
                            dn_str,
                            f"Transformation failed: {transform_result.error}",
                        ))

                except (ValueError, TypeError, AttributeError, KeyError) as e:
                    dn_str = entry.dn.value
                    transformation_errors.append((
                        dn_str,
                        f"Transformation error: {e!s}",
                    ))
                    self.logger.debug(
                        "Exception during ACL transformation",
                        entry_dn=dn_str,
                        error=str(e),
                        error_type=type(e).__name__,
                    )
                    continue

            # Log overall transformation statistics
            total = len(entries)
            succeeded = len(transformed_entries)
            failed = len(transformation_errors)

            self.logger.info(
                "ACL transformation complete",
                total_entries=total,
                succeeded_entries=succeeded,
                failed_entries=failed,
                success_rate=f"{succeeded / total * 100:.1f}%" if total > 0 else "0%",
            )

            if transformation_errors:
                for dn, error in transformation_errors[
                    : FlextLdifConstants.MAX_LOGGED_ERRORS
                ]:
                    self.logger.debug(
                        "ACL transformation failed for entry",
                        entry_dn=dn,
                        error=str(error),
                    )
                if failed > FlextLdifConstants.MAX_LOGGED_ERRORS:
                    self.logger.debug(
                        "Additional ACL transformation failures",
                        additional_failures=failed
                        - FlextLdifConstants.MAX_LOGGED_ERRORS,
                        max_logged=FlextLdifConstants.MAX_LOGGED_ERRORS,
                    )

            return FlextResult[list[FlextLdifModels.Entry]].ok(transformed_entries)

        except Exception as e:
            return FlextResult[list[FlextLdifModels.Entry]].fail(
                f"ACL transformation failed: {e}",
            )

    # =========================================================================
    # ACL ENTRY EXTRACTION
    # =========================================================================

    @staticmethod
    def _is_schema_entry(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema definition.

        Schema entries are detected by presence of attributeTypes, objectClasses,
        ldapSyntaxes, or matchingRules attributes (case-insensitive).

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema definition

        """
        entry_attrs = {attr.lower() for attr in entry.attributes.attributes}
        schema_attrs_lower = {
            attr.lower() for attr in FlextLdifConstants.SchemaFields.ALL_SCHEMA_FIELDS
        }
        return bool(schema_attrs_lower & entry_attrs)

    def extract_acl_entries(
        self,
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries with ACL attributes.

        Filters entries to find those with ACL attributes,
        while excluding schema entries.

        Args:
            entries: List of entries to filter
            acl_attributes: List of ACL attribute names to look for
                          Default: FlextLdifConstants.AclAttributeRegistry.RFC_FOUNDATION

        Returns:
            FlextResult with list of entries containing ACL attributes
            (excluding schema entries)

        Example:
            # Extract with default ACL attributes
            result = acl_service.extract_acl_entries(entries)

            # Extract with custom ACL attributes
            result = acl_service.extract_acl_entries(
                entries,
                acl_attributes=["orclaci", "aci"]
            )

        """
        if not entries:
            return FlextResult[list[FlextLdifModels.Entry]].ok([])

        filter_acl_attrs = (
            acl_attributes
            if acl_attributes is not None
            else FlextLdifConstants.AclAttributeRegistry.RFC_FOUNDATION
        )

        return FlextResult[list[FlextLdifModels.Entry]].ok([
            entry
            for entry in entries
            if not self._is_schema_entry(entry)
            and FlextLdifUtilities.Entry.has_any_attributes(entry, filter_acl_attrs)
        ])


__all__ = ["FlextLdifAcl"]
