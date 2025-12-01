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

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.services.server import FlextLdifServer


class FlextLdifAcl(FlextLdifServiceBase[FlextLdifModels.AclResponse]):
    """Direct ACL processing service using flext-core APIs.

    This service provides minimal, direct ACL processing by delegating
    to FlextLdifServer ACL quirks which handle all server-specific parsing.
    No unnecessary abstraction layers or model conversions.
    """

    _server: FlextLdifServer

    def __init__(self, server: FlextLdifServer | None = None) -> None:
        """Initialize ACL service with optional server instance."""
        super().__init__()
        self._server = server if server is not None else FlextLdifServer()

    def parse_acl_string(
        self,
        acl_string: str,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[FlextLdifModels.Acl]:
        """Parse ACL string using server-specific quirks.

        Args:
            acl_string: Raw ACL string to parse
            server_type: Server type for quirk selection

        Returns:
            FlextResult containing parsed ACL model

        """
        # Get ACL quirk for server type
        acl_quirk = self._server.acl(server_type)
        if acl_quirk is None:
            return FlextResult.fail(
                f"No ACL quirk found for server type: {server_type}",
            )

        # Direct call to ACL quirk parse method
        parse_result = acl_quirk.parse(acl_string)

        if parse_result.is_failure:
            return FlextResult.fail(parse_result.error or "ACL parsing failed")

        # Return the parsed ACL directly (no unnecessary conversions)
        return parse_result

    def write_acl(
        self,
        acl: FlextLdifModels.Acl,
        server_type: FlextLdifConstants.LiteralTypes.ServerTypeLiteral,
    ) -> FlextResult[str]:
        """Write ACL model to string format.

        Args:
            acl: ACL model to write
            server_type: Server type for quirk selection

        Returns:
            FlextResult containing ACL string

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
    ) -> FlextResult[FlextLdifModels.AclResponse]:
        """Extract ACLs from entry using server-specific attribute names.

        Args:
            entry: Entry to extract ACLs from
            server_type: Server type for ACL attribute detection

        Returns:
            FlextResult containing ACL response with extracted ACLs

        """
        # Get ACL attribute name for server type
        acl_attr_name = FlextLdifConstants.AclAttributeRegistry.get_acl_attributes(
            server_type,
        )

        if not acl_attr_name:
            # Server has no ACL attributes
            return FlextResult.ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.Statistics(
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
            return FlextResult.ok(
                FlextLdifModels.AclResponse(
                    acls=[],
                    statistics=FlextLdifModels.Statistics(
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
                acls.append(parse_result.unwrap())
            else:
                failed_count += 1
                self.logger.warning(
                    "Failed to parse ACL value",
                    error=parse_result.error,
                    server_type=server_type,
                )

        # Create response
        response = FlextLdifModels.AclResponse(
            acls=acls,
            statistics=FlextLdifModels.Statistics(
                processed_entries=1,
                acls_extracted=len(acls),
                failed_entries=failed_count,
            ),
        )

        return FlextResult.ok(response)

    def execute(self) -> FlextResult[FlextLdifModels.AclResponse]:
        """Execute ACL service.

        This service requires input data to process ACLs. Use parse_acl_string(),
        parse_acl_attribute(), or parse_acl_attributes() methods instead.

        Returns:
            FlextResult.fail: Always fails as input is required

        """
        return FlextResult.fail(
            "FlextLdifAcl requires input data to process ACLs. "
            "Use parse_acl_string(), parse_acl_attribute(), or parse_acl_attributes() methods.",
        )


__all__ = ["FlextLdifAcl"]
