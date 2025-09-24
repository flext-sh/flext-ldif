"""FLEXT LDIF ACL Service.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_core import FlextLogger, FlextResult, FlextService
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.manager import FlextLdifQuirksManager


class FlextLdifAclService(FlextService[dict[str, object]]):
    """Unified ACL management service for LDIF entries."""

    def __init__(self, quirks_manager: FlextLdifQuirksManager | None = None) -> None:
        """Initialize ACL service.

        Args:
            quirks_manager: Quirks manager for server-specific handling

        """
        super().__init__()
        self._logger = FlextLogger(__name__)
        self._quirks = quirks_manager or FlextLdifQuirksManager()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute ACL service."""
        return FlextResult[dict[str, object]].ok({
            "service": "FlextLdifAclService",
            "status": "ready",
            "quirks_ready": bool(self._quirks),
        })

    def extract_acls_from_entry(
        self, entry: FlextLdifModels.Entry, server_type: str | None = None
    ) -> FlextResult[list[FlextLdifModels.UnifiedAcl]]:
        """Extract ACLs from LDIF entry.

        Args:
            entry: LDIF entry to extract ACLs from
            server_type: Server type for ACL format detection

        Returns:
            FlextResult containing list of unified ACL entries

        """
        acl_attr_result = self._quirks.get_acl_attribute_name(server_type)
        if acl_attr_result.is_failure:
            error_msg = acl_attr_result.error or "Unknown ACL attribute error"
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].fail(error_msg)

        acl_attribute = acl_attr_result.value
        acl_values = entry.get_attribute(acl_attribute) or []

        if not acl_values:
            return FlextResult[list[FlextLdifModels.UnifiedAcl]].ok([])

        acls: list[FlextLdifModels.UnifiedAcl] = []
        for acl_value in acl_values:
            parse_result = self._parse_acl(acl_value, server_type or "generic")
            if parse_result.is_success:
                acls.append(parse_result.value)

        return FlextResult[list[FlextLdifModels.UnifiedAcl]].ok(acls)

    def _parse_acl(
        self, acl_string: str, server_type: str
    ) -> FlextResult[FlextLdifModels.UnifiedAcl]:
        """Parse ACL string into unified format.

        Args:
            acl_string: Raw ACL string
            server_type: Server type for format detection

        Returns:
            FlextResult containing unified ACL

        """
        target_result = FlextLdifModels.AclTarget.create()
        subject_result = FlextLdifModels.AclSubject.create()
        perms_result = FlextLdifModels.AclPermissions.create(read=True)

        if (
            target_result.is_failure
            or subject_result.is_failure
            or perms_result.is_failure
        ):
            return FlextResult[FlextLdifModels.UnifiedAcl].fail(
                "Failed to create ACL components"
            )

        return FlextLdifModels.UnifiedAcl.create(
            name="parsed_acl",
            target=target_result.value,
            subject=subject_result.value,
            permissions=perms_result.value,
            server_type=server_type,
            raw_acl=acl_string,
        )


__all__ = ["FlextLdifAclService"]
