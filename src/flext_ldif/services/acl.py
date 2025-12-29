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

from flext_core import FlextLogger, r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.entry import FlextLdifUtilitiesEntry
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.base import s
from flext_ldif.models import m
from flext_ldif.services.server import FlextLdifServer
from flext_ldif.utilities import u


class FlextLdifAcl(s[m.Ldif.LdifResults.AclResponse]):
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
        server_type: str,
    ) -> r[m.Ldif.Acl]:
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
            normalized_server_type = FlextLdifUtilitiesServer.normalize_server_type(
                original_server_type,
            )
        except (ValueError, TypeError) as e:
            # Invalid server type validation error
            return r[m.Ldif.Acl].fail(f"Invalid server type: {server_type} - {e}")

        # Get ACL quirk for normalized server type
        # If "openldap" (generic) was requested, try "openldap1" (legacy format) first
        # as it's more compatible with older ACL formats, then fallback to "openldap2"
        try:
            # If original was "openldap", try "openldap1" first (legacy format)
            if original_server_type == "openldap":
                acl_quirk = self._server.acl("openldap1")
                if acl_quirk is None:
                    # Fallback to openldap2 if openldap1 not found
                    acl_quirk = self._server.acl("openldap2")
            else:
                # Use normalized server type directly
                acl_quirk = self._server.acl(normalized_server_type)
        except ValueError as e:
            # Invalid server type validation error
            return r[m.Ldif.Acl].fail(str(e))
        if acl_quirk is None:
            return r[m.Ldif.Acl].fail(
                f"No ACL quirk found for server type: {normalized_server_type}",
            )

        # Direct call to ACL quirk parse method
        # Quirk protocol returns FlextProtocols.Result[AclProtocol]
        # Convert to FlextResult[Acl] for service method return type
        parse_result = acl_quirk.parse(acl_string)

        if parse_result.is_failure:
            return r[m.Ldif.Acl].fail(parse_result.error or "ACL parsing failed")

        # Extract and rewrap as FlextResult[Acl]
        # Type narrowing: parse_result.value satisfies AclProtocol
        parsed_value = parse_result.value
        if isinstance(parsed_value, m.Ldif.Acl):
            return r[m.Ldif.Acl].ok(parsed_value)
        # Protocol duck-typing: create Acl from protocol value
        return r[m.Ldif.Acl].ok(m.Ldif.Acl.model_validate(parsed_value))

    def write_acl(
        self,
        acl: m.Ldif.Acl,
        server_type: str,
    ) -> r[str]:
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
            return r[str].fail(
                f"No ACL quirk found for server type: {server_type}",
            )

        # Direct call to ACL quirk write method
        # Quirk protocol returns FlextProtocols.Result[str]
        # m.Ldif.Acl satisfies p.Ldif.AclProtocol via structural typing
        write_result = acl_quirk.write(acl)

        if write_result.is_failure:
            return r[str].fail(write_result.error or "ACL writing failed")

        # Extract and rewrap as FlextResult[str]
        return r[str].ok(write_result.value)

    def extract_acls_from_entry(
        self,
        entry: m.Ldif.Entry,
        server_type: str,
    ) -> r[m.Ldif.LdifResults.AclResponse]:
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
        acl_attr_name = FlextLdifUtilitiesACL.get_acl_attributes(
            server_type,
        )

        if not acl_attr_name:
            # Server has no ACL attributes
            # Statistics is a PEP 695 type alias - use the underlying class directly
            return r[str].ok(
                m.Ldif.LdifResults.AclResponse(
                    acls=[],
                    statistics=m.Ldif.LdifResults.Statistics(
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
            return r[str].ok(
                m.Ldif.LdifResults.AclResponse(
                    acls=[],
                    statistics=m.Ldif.LdifResults.Statistics(
                        processed_entries=1,
                        acls_extracted=0,
                    ),
                ),
            )

        # Parse each ACL value using u
        acls: list[FlextLdifModelsDomains.Acl] = []
        failed_count = 0

        def parse_acl_wrapper(acl_value: str) -> m.Ldif.Acl:
            """Parse single ACL value - returns Acl directly for batch compatibility.

            The batch function accepts Callable[[T], R | r[R]], meaning it can handle
            both direct returns (R) and FlextResult returns (r[R]). We return R directly
            and raise ValueError on failure so batch's exception handler can catch it.
            """
            nonlocal failed_count
            parse_result = self.parse_acl_string(acl_value, server_type)
            if parse_result.is_success:
                return parse_result.value
            failed_count += 1
            logger = FlextLogger(__name__)
            logger.warning(
                "Failed to parse ACL value",
                error=parse_result.error,
                server_type=server_type,
            )
            msg = parse_result.error or "Failed to parse ACL"
            raise ValueError(msg)

        # Pass wrapper function to batch()
        batch_result = u.Collection.batch(
            list(acl_values),
            parse_acl_wrapper,
            on_error="skip",
        )
        if batch_result.is_success:
            results_raw = batch_result.value.get("results", [])
            # Type narrowing: filter and validate results as m.Ldif.Acl
            acls.extend(item for item in results_raw if isinstance(item, m.Ldif.Acl))

        # Create response
        # Statistics is a PEP 695 type alias - use the underlying class directly
        # Import internal model type for AclResponse compatibility

        response = m.Ldif.LdifResults.AclResponse(
            acls=acls,
            statistics=m.Ldif.LdifResults.Statistics(
                processed_entries=1,
                acls_extracted=len(acls),
                failed_entries=failed_count,
            ),
        )

        return r[str].ok(response)

    @staticmethod
    def extract_acl_entries(
        entries: list[m.Ldif.Entry],
        acl_attributes: list[str] | None = None,
    ) -> r[list[m.Ldif.Entry]]:
        """Extract entries that contain ACL attributes.

        Args:
            entries: List of entries to filter
            acl_attributes: Optional list of ACL attribute names to look for.
                If None, uses default ACL attributes (aci, acl, olcAccess).

        Returns:
            FlextResult containing list of entries with ACL attributes

        """
        if not entries:
            return r[str].ok([])

        # Use default ACL attributes if not specified
        if acl_attributes is None:
            acl_attributes = list(
                FlextLdifUtilitiesACL.get_acl_attributes(None),
            )

        # Filter entries that have at least one ACL attribute
        # Exclude schema entries even if they have ACL attributes
        def has_acl_attribute(entry: m.Ldif.Entry) -> bool:
            """Check if entry has at least one ACL attribute."""
            # Skip schema entries
            if FlextLdifAcl._is_schema_entry(entry):
                return False

            # Check if entry has any of the ACL attributes
            for attr_name in acl_attributes:
                attr_values = entry.get_attribute_values(attr_name)
                if u.Guards.is_list_non_empty(attr_values):
                    return True
            return False

        # Filter entries with ACL attributes using list comprehension
        acl_entries: list[m.Ldif.Entry] = [
            entry for entry in entries if has_acl_attribute(entry)
        ]

        return r[list[m.Ldif.Entry]].ok(acl_entries)

    @staticmethod
    def _is_schema_entry(entry: m.Ldif.Entry) -> bool:
        """Check if entry is a schema entry.

        Args:
            entry: Entry to check

        Returns:
            True if entry is a schema entry, False otherwise

        """
        return FlextLdifUtilitiesEntry.is_schema_entry(entry, strict=False)

    @staticmethod
    def evaluate_acl_context(
        acls: list[m.Ldif.Acl],
        required_permissions: m.Ldif.LdifResults.AclPermissions | dict[str, bool],
    ) -> r[m.Ldif.LdifResults.AclEvaluationResult]:
        """Evaluate if ACLs grant required permissions.

        Business Rule: ACL context evaluation checks if any ACL in the list grants
        all required permissions. Empty ACL lists fail immediately. Each required
        permission must be explicitly granted by at least one ACL (no implicit grants).

        Implication: This method provides security context evaluation for access control
        decisions. It follows a "deny by default" model - permissions must be explicitly
        granted. Results include match details for auditing and debugging.

        Args:
            acls: List of ACLs to evaluate
            required_permissions: Required permissions (as AclPermissions model or dict)

        Returns:
            FlextResult containing AclEvaluationResult with match status and details

        """
        # Convert dict to AclPermissions if needed
        required = (
            m.Ldif.LdifResults.AclPermissions(**required_permissions)
            if isinstance(required_permissions, dict)
            else required_permissions
        )

        # Empty ACL list - evaluation fails (no permissions granted)
        if not acls:
            return r[str].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=False,
                    matched_acl=None,
                    message="No ACLs to evaluate - access denied by default",
                ),
            )

        # Build list of required permission names
        perm_names = ["read", "write", "delete", "add", "search", "compare"]
        required_perms = [p for p in perm_names if getattr(required, p, False)]

        # If no permissions required, evaluation passes trivially
        if not required_perms:
            return r[str].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=True,
                    matched_acl=acls[0] if acls else None,
                    message="No permissions required - access granted trivially",
                ),
            )

        # Find ACL that grants all required permissions
        def acl_grants_all(acl: m.Ldif.Acl) -> bool:
            """Check if ACL grants all required permissions."""
            return all(getattr(acl.permissions, perm, False) for perm in required_perms)

        # Predicate that evaluates if ACL grants all permissions
        def predicate(value: m.Ldif.Acl) -> bool:
            """Check if ACL grants all permissions."""
            return acl_grants_all(value)

        # Use find() with predicate
        found_raw = u.find(acls, predicate=predicate)

        # Type narrowing: validate found result is m.Ldif.Acl
        if found_raw is not None and isinstance(found_raw, m.Ldif.Acl):
            return r[str].ok(
                m.Ldif.LdifResults.AclEvaluationResult(
                    granted=True,
                    matched_acl=found_raw,
                    message=f"ACL '{found_raw.name}' grants required permissions: {required_perms}",
                ),
            )

        # No ACL grants all required permissions
        return r[str].ok(
            m.Ldif.LdifResults.AclEvaluationResult(
                granted=False,
                matched_acl=None,
                message=f"No ACL grants required permissions: {required_perms}",
            ),
        )

    def execute(self) -> r[m.Ldif.LdifResults.AclResponse]:
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
        return r[m.Ldif.LdifResults.AclResponse].ok(
            m.Ldif.LdifResults.AclResponse(
                acls=[],
                statistics=m.Ldif.LdifResults.Statistics(),
            ),
        )


__all__ = ["FlextLdifAcl"]
