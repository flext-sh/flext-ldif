"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import ClassVar

from pydantic import Field

from flext_core import FlextLogger, FlextResult
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import BaseAclQuirk, BaseEntryQuirk, BaseSchemaQuirk


class OudSchemaQuirk(BaseSchemaQuirk):
    """Oracle OUD schema quirk.

    Extends RFC 4512 schema parsing with Oracle OUD-specific features:
    - OUD namespace (2.16.840.1.113894.*)
    - OUD-specific syntaxes
    - OUD attribute extensions
    - Compatibility with OID schemas

    Example:
        quirk = OudSchemaQuirk(server_type="oud")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(default="oud", description="Oracle OUD server type")
    priority: int = Field(
        default=10, description="High priority for OUD-specific parsing"
    )

    # Oracle OUD namespace pattern (same as OID for compatibility)
    ORACLE_OUD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    def __init__(self, **data: object) -> None:
        """Initialize OUD schema quirk."""
        super().__init__(**data)  # type: ignore[arg-type]
        self._logger = FlextLogger(__name__)

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an Oracle OUD attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains Oracle OUD namespace

        """
        return bool(self.ORACLE_OUD_PATTERN.search(attr_definition))

    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
        """Parse Oracle OUD attribute definition.

        OUD uses RFC 4512 compliant schema format, so we can use
        the RFC parser directly with OUD-specific extensions.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed OUD attribute data

        """
        try:
            # OUD attributes are RFC 4512 compliant
            # Parse as RFC and add OUD-specific metadata
            attr_result = FlextLdifModels.OidSchemaAttribute.from_ldif_line(
                f"attributetypes: {attr_definition}"
            )

            if attr_result.is_success:
                attr_obj = attr_result.value
                # Convert to dict for quirk system with OUD metadata
                base_data = (
                    attr_obj.model_dump() if hasattr(attr_obj, "model_dump") else {}
                )
                return FlextResult[dict[str, object]].ok({
                    **base_data,
                    "server_type": "oud",
                })

            return FlextResult[dict[str, object]].fail(
                attr_result.error or "Failed to parse OUD attribute"
            )

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OUD attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an Oracle OUD objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains Oracle OUD namespace

        """
        return bool(self.ORACLE_OUD_PATTERN.search(oc_definition))

    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
        """Parse Oracle OUD objectClass definition.

        OUD uses RFC 4512 compliant schema format.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed OUD objectClass data

        """
        try:
            # OUD objectClasses are RFC 4512 compliant
            oc_result = FlextLdifModels.OidSchemaObjectClass.from_ldif_line(
                f"objectclasses: {oc_definition}"
            )

            if oc_result.is_success:
                oc_obj = oc_result.value
                # Convert to dict with OUD metadata
                base_data = oc_obj.model_dump() if hasattr(oc_obj, "model_dump") else {}
                return FlextResult[dict[str, object]].ok({
                    **base_data,
                    "server_type": "oud",
                })

            return FlextResult[dict[str, object]].fail(
                oc_result.error or "Failed to parse OUD objectClass"
            )

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OUD objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert OUD attribute to RFC-compliant format.

        OUD attributes are already RFC-compliant, so minimal conversion needed.

        Args:
            attr_data: OUD attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """
        try:
            # OUD attributes are RFC-compliant
            rfc_data = {
                "oid": attr_data.get("oid"),
                "name": attr_data.get("name"),
                "desc": attr_data.get("desc"),
                "syntax": attr_data.get("syntax"),
                "equality": attr_data.get("equality"),
            }

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert OUD objectClass to RFC-compliant format.

        OUD objectClasses are already RFC-compliant.

        Args:
            oc_data: OUD objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """
        try:
            # OUD objectClasses are RFC-compliant
            rfc_data = {
                "oid": oc_data.get("oid"),
                "name": oc_data.get("name"),
                "desc": oc_data.get("desc"),
                "sup": oc_data.get("sup"),
                "kind": oc_data.get("kind"),
                "must": oc_data.get("must"),
                "may": oc_data.get("may"),
            }

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    class AclQuirk(BaseAclQuirk):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

        Example:
            quirk = OudSchemaQuirk.AclQuirk(server_type="oud")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(default="oud", description="Oracle OUD server type")
        priority: int = Field(
            default=10, description="High priority for OUD ACL parsing"
        )

        def __init__(self, **data: object) -> None:
            """Initialize OUD ACL quirk."""
            super().__init__(**data)  # type: ignore[arg-type]
            self._logger = FlextLogger(__name__)

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OUD ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is OUD ACL format

            """
            # OUD uses different ACL format than OID
            return acl_line.startswith(("ds-cfg-", "aci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
            """Parse Oracle OUD ACL definition.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OUD ACL data

            """
            try:
                # OUD ACL format is different from OID
                # Parse basic ACL structure
                oud_acl_data: dict[str, object] = {
                    "type": "oud_acl",
                    "raw": acl_line,
                    "format": "ds-cfg" if acl_line.startswith("ds-cfg-") else "aci",
                }

                return FlextResult[dict[str, object]].ok(oud_acl_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert OUD ACL to RFC-compliant format.

            Args:
                acl_data: OUD ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # OUD ACLs don't have direct RFC equivalent
                rfc_data: dict[str, object] = {
                    "type": "acl",
                    "format": "rfc_generic",
                    "source_format": "oracle_oud",
                    "data": acl_data,
                }

                return FlextResult[dict[str, object]].ok(rfc_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert RFC ACL to OUD-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OUD ACL data

            """
            try:
                # Convert RFC ACL to Oracle OUD format
                oud_data: dict[str, object] = {
                    "format": "oracle_oud",
                    "target_format": "ds-cfg",
                    "data": acl_data,
                }

                return FlextResult[dict[str, object]].ok(oud_data)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"RFC→OUD ACL conversion failed: {e}"
                )

    class EntryQuirk(BaseEntryQuirk):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = OudSchemaQuirk.EntryQuirk(server_type="oud")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(default="oud", description="Oracle OUD server type")
        priority: int = Field(
            default=10, description="High priority for OUD entry processing"
        )

        def __init__(self, **data: object) -> None:
            """Initialize OUD entry quirk."""
            super().__init__(**data)  # type: ignore[arg-type]
            self._logger = FlextLogger(__name__)

        def can_handle_entry(self, entry_dn: str, attributes: dict) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an OUD-specific entry

            """
            # Handle all entries for OUD target
            # Can add specific OUD entry detection logic here
            _ = entry_dn
            _ = attributes
            return True

        def process_entry(
            self, entry_dn: str, attributes: dict
        ) -> FlextResult[dict[str, object]]:
            """Process entry for OUD format.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with processed entry data

            """
            try:
                # OUD entries are RFC-compliant
                # Add OUD-specific processing if needed
                processed_entry: dict[str, object] = {
                    "dn": entry_dn,
                    "server_type": "oud",
                }
                processed_entry.update(attributes)

                return FlextResult[dict[str, object]].ok(processed_entry)

            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: dict[str, object]
        ) -> FlextResult[dict[str, object]]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # OUD entries are already RFC-compliant
                return FlextResult[dict[str, object]].ok(entry_data)
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"OUD entry→RFC conversion failed: {e}"
                )


__all__ = ["OudSchemaQuirk"]
