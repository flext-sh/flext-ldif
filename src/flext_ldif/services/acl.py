"""ACL Service - Direct ACL Processing with flext-core APIs.

This service provides direct ACL processing using flext-core and flext-ldif APIs:
- Direct use of FlextLdifServer ACL quirks for parsing and writing
- No unnecessary model conversions or type casting
- Railway-oriented error handling with FlextResult

Single Responsibility: Process ACL strings using direct APIs.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifAcl(FlextLdifServiceBase[FlextLdifModelsResults.AclResponse]):
    """Direct ACL processing service using flext-core APIs.

    Business Rule: ACL service delegates directly to server-specific ACL quirks for
    parsing and writing. All server-specific ACL formats (Oracle ACI, OpenLDAP olcAccess,
    etc.) are handled by quirks, ensuring RFC compliance with server enhancements.

    Implication: ACL processing uses the same quirk system as entry/schema processing,
    ensuring consistency. Server type normalization ensures correct quirk selection.
    OpenLDAP generic requests route to openldap1 (legacy) first, then openldap2.

    This service provides minimal, direct ACL processing by delegating
    to FlextLdifServer ACL quirks which handle all server-specific parsing.
    No unnecessary abstraction layers or model conversions.
    """

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize ACL service with optional server instance.

        Business Rule: Server registry is optional - defaults to global instance if not provided.
        This enables dependency injection for testing while maintaining convenience defaults.

        Args:
            server: Optional FlextLdifServer instance (defaults to global instance)

        """
        super().__init__()
        # Use object.__setattr__ for PrivateAttr in frozen models
        object.__setattr__(
            self,
            "_server",
            server if server is not None else FlextLdifServer(),
        )

    def parse_acl_string(
        self,
        acl_string: str,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral | str,
    ) -> FlextResult[FlextLdifModelsDomains.Acl]:
        """Parse ACL string using server-specific quirks.

        Business Rule: ACL parsing normalizes server type to canonical form before
        quirk resolution. OpenLDAP generic requests ("openldap") route to openldap1
        (legacy format) first, then fallback to openldap2. Invalid server types result
        in fail-fast error responses.

        Implication: Server type normalization ensures consistent quirk selection.
        OpenLDAP fallback logic handles legacy ACL formats while supporting modern
        olcAccess format. All parsing maintains RFC compliance with server enhancements.

        Args:
            acl_string: Raw ACL string to parse (server-specific format)
            server_type: Server type for quirk selection (will be normalized)

        Returns:
            FlextResult containing parsed ACL model (RFC-compliant with server metadata)

        """
        # Normalize server type to canonical form
        # Store original server_type for fallback logic
        original_server_type = str(server_type)
        try:
            normalized_server_type = FlextLdifConstants.normalize_server_type(
                original_server_type,
            )
        except (ValueError, TypeError) as e:
            # Invalid server type validation error
            return FlextResult.fail(f"Invalid server type: {server_type} - {e}")

        # Get ACL quirk for normalized server type
        # If "openldap" (generic) was requested, try "openldap1" (legacy format) first
        # as it's more compatible with older ACL formats, then fallback to "openldap2"
        try:
            # If original was "openldap", try "openldap1" first (legacy format)
            if original_server_type.lower() == "openldap":
                acl_quirk = self._server.acl("openldap1")
                if acl_quirk is None:
                    # Fallback to openldap2 if openldap1 not found
                    acl_quirk = self._server.acl("openldap2")
            else:
                # Use normalized server type directly
                acl_quirk = self._server.acl(normalized_server_type)
        except ValueError as e:
            # Invalid server type validation error
            return FlextResult.fail(str(e))
        if acl_quirk is None:
            return FlextResult.fail(
                f"No ACL quirk found for server type: {normalized_server_type}",
            )

        # Direct call to ACL quirk parse method
        parse_result = acl_quirk.parse(acl_string)

        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error or "ACL parsing failed")

        # Return the parsed ACL directly (no unnecessary conversions)
        return parse_result

    def write_acl(
        self,
        acl: FlextLdifModelsDomains.Acl,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[str]:
        """Write ACL model to string format.

        Business Rule: ACL writing uses server-specific quirks for formatting.
        ACL model is converted to server-specific string format (Oracle ACI, OpenLDAP
        olcAccess, etc.) based on server type. Invalid server types result in fail-fast
        error responses.

        Implication: Writing uses the same quirk system as parsing, ensuring round-trip
        compatibility. Server-specific formatting preserves ACL semantics while adapting
        to server requirements.

        Args:
            acl: ACL model to write (RFC-compliant with server metadata)
            server_type: Server type for quirk selection (determines output format)

        Returns:
            FlextResult containing ACL string (server-specific format)

        """
        # Get ACL quirk for server type
        acl_quirk = self._server.acl(server_type)
        if acl_quirk is None:
            return FlextResult.fail(
                f"No ACL quirk found for server type: {server_type}",
            )

        # Direct call to ACL quirk write method
        write_result = acl_quirk.write(acl)

        if write_result.is_failure:
            return FlextResult.fail(write_result.error or "ACL writing failed")

        return write_result

    def extract_acls_from_entry(
        self,
        entry: FlextLdifModels.Entry,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[FlextLdifModelsResults.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names.

        Business Rule: ACL extraction uses server-specific attribute detection via
        FlextLdifUtilities.ACL.get_acl_attributes(). Multiple ACL attributes per server
        are supported (e.g., Oracle: orclaci, orclentrylevelaci). Each ACL attribute
        value is parsed separately and aggregated into response.

        Implication: Server type determines which attributes are scanned for ACLs.
        Extraction maintains RFC compliance while handling server-specific ACL formats.
        Response includes statistics for extracted ACLs and processing metadata.

        Args:
            entry: Entry to extract ACLs from (may contain multiple ACL attributes)
            server_type: Server type for ACL attribute detection (determines attributes scanned)

        Returns:
            FlextResult containing AclResponse with extracted ACLs and statistics

        """
        # Get ACL attribute name for server type
        acl_attr_name = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(
            server_type,
        )

        if not acl_attr_name:
            # Server has no ACL attributes
            # Statistics is a PEP 695 type alias - use the underlying class directly
            return FlextResult.ok(
                FlextLdifModelsResults.AclResponse(
                    acls=[],
                    statistics=FlextLdifModelsResults.Statistics(
                        processed_entries=1,
                        acls_extracted=0,
                    ),
                ),
            )

        # Extract ACL values from entry
        acl_values = entry.get_attribute_values(
            next(iter(acl_attr_name)),
        )  # Get first attribute name

        if not acl_values:
            # No ACL values found
            # Statistics is a PEP 695 type alias - use the underlying class directly
            return FlextResult.ok(
                FlextLdifModelsResults.AclResponse(
                    acls=[],
                    statistics=FlextLdifModelsResults.Statistics(
                        processed_entries=1,
                        acls_extracted=0,
                    ),
                ),
            )

        # Parse each ACL value
        acls = []
        failed_count = 0

        for acl_value in acl_values:
            parse_result = self.parse_acl_string(acl_value, server_type)
            if parse_result.is_success:
                acl_obj = parse_result.unwrap()
                acls.append(acl_obj)
            else:
                failed_count += 1
                self.logger.warning(
                    "Failed to parse ACL value",
                    error=parse_result.error,
                    server_type=server_type,
                )

        # Create response
        # Statistics is a PEP 695 type alias - use the underlying class directly
        response = FlextLdifModelsResults.AclResponse(
            acls=acls,
            statistics=FlextLdifModelsResults.Statistics(
                processed_entries=1,
                acls_extracted=len(acls),
                failed_entries=failed_count,
            ),
        )

        return FlextResult.ok(response)

    @staticmethod
    @staticmethod
    def extract_acl_entries(
        entries: list[FlextLdifModels.Entry],
        acl_attributes: list[str] | None = None,
    ) -> FlextResult[list[FlextLdifModels.Entry]]:
        """Extract entries that contain ACL attributes.

        Args:
            entries: List of entries to filter
            acl_attributes: Optional list of ACL attribute names to look for.
                If None, uses default ACL attributes (aci, acl, olcAccess).

        Returns:
            FlextResult containing list of entries with ACL attributes

        """
        if not entries:
            return FlextResult.ok([])

        # Use default ACL attributes if not specified
        if acl_attributes is None:
            acl_attributes = list(
                FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(None),
            )

        # Filter entries that have at least one ACL attribute
        # Exclude schema entries even if they have ACL attributes
        acl_entries = []
        for entry in entries:
            # Skip schema entries
            if FlextLdifAcl._is_schema_entry(entry):
                continue

            # Check if entry has any of the ACL attributes
            has_acl = False
            for attr_name in acl_attributes:
                attr_values = entry.get_attribute_values(attr_name)
                if attr_values and len(attr_values) > 0:
                    has_acl = True
                    break

            if has_acl:
                acl_entries.append(entry)

        return FlextResult.ok(acl_entries)

    @staticmethod
    def _is_schema_entry(entry: FlextLdifModels.Entry) -> bool:
        """Check if entry is a schema entry.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema entry, False otherwise

        """
        return FlextLdifUtilities.Entry.is_schema_entry(entry, strict=False)

    def execute(self) -> FlextResult[FlextLdifModelsResults.AclResponse]:  # noqa: PLR6301
        """Execute ACL service health check.

        Business Rule: Execute method provides service health check for protocol compliance.
        Returns empty ACL response with initialized statistics, indicating service is operational.

        Implication: This method enables service-based execution patterns while maintaining
        type safety. Used internally by service orchestration layers for health monitoring.

        Returns:
            FlextResult containing service status

        Note:
            Method must be instance method to satisfy FlextService interface.
            Returns service status for health checks, actual ACL processing uses
            parse_acl_string(), parse_acl_attribute(), or parse_acl_attributes() methods.

        """
        # Return service status for health check
        # Create a minimal AclResponse indicating service is operational
        return FlextResult[FlextLdifModelsResults.AclResponse].ok(
            FlextLdifModelsResults.AclResponse(
                acls=[],
                statistics=FlextLdifModelsResults.Statistics(),
            ),
        )


__all__ = ["FlextLdifAcl"]
