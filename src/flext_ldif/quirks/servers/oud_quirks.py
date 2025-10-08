"""Oracle Unified Directory (OUD) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OUD-specific quirks for schema, ACL, and entry processing.
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOud(FlextLdifQuirksBaseSchemaQuirk):
    """Oracle OUD schema quirk.

    Extends RFC 4512 schema parsing with Oracle OUD-specific features:
    - OUD namespace (2.16.840.1.113894.*)
    - OUD-specific syntaxes
    - OUD attribute extensions
    - Compatibility with OID schemas

    Example:
        quirk = FlextLdifQuirksServersOud(server_type="oud")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(
        default=FlextLdifConstants.ServerTypes.OUD, description="Oracle OUD server type"
    )
    priority: int = Field(
        default=10, description="High priority for OUD-specific parsing"
    )

    # Oracle OUD namespace pattern (same as OID for compatibility)
    ORACLE_OUD_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OUD schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an Oracle OUD attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains Oracle OUD namespace

        """
        return bool(self.ORACLE_OUD_PATTERN.search(attr_definition))

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
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
                return FlextResult[FlextLdifTypes.Dict].ok({
                    **base_data,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
                })

            return FlextResult[FlextLdifTypes.Dict].fail(
                attr_result.error or "Failed to parse OUD attribute"
            )

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
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

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
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
                return FlextResult[FlextLdifTypes.Dict].ok({
                    **base_data,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
                })

            return FlextResult[FlextLdifTypes.Dict].fail(
                oc_result.error or "Failed to parse OUD objectClass"
            )

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
                FlextLdifConstants.DictKeys.OID: attr_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: attr_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: attr_data.get("desc"),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get("syntax"),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get("equality"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
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
                FlextLdifConstants.DictKeys.OID: oc_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: oc_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: oc_data.get("desc"),
                FlextLdifConstants.DictKeys.SUP: oc_data.get("sup"),
                "kind": oc_data.get("kind"),
                "must": oc_data.get("must"),
                "may": oc_data.get("may"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OUD→RFC conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Oracle OUD ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OUD-specific ACL formats:
        - ds-cfg-access-control-handler: OUD access control
        - OUD-specific ACL syntax (different from OID orclaci)

        Example:
            quirk = FlextLdifQuirksServersOud.AclQuirk(server_type="oud")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OUD,
            description="Oracle OUD server type",
        )
        priority: int = Field(
            default=10, description="High priority for OUD ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OUD ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OUD ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is OUD ACL format

            """
            # OUD uses different ACL format than OID
            return acl_line.startswith(("ds-cfg-", "aci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse Oracle OUD ACL definition.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OUD ACL data

            """
            try:
                # OUD ACL format is different from OID
                # Parse basic ACL structure
                oudacl_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: "oud_acl",
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.FORMAT: "ds-cfg"
                    if acl_line.startswith("ds-cfg-")
                    else FlextLdifConstants.AclFormats.ACI,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(oudacl_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert OUD ACL to RFC-compliant format.

            Args:
                acl_data: OUD ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # OUD ACLs don't have direct RFC equivalent
                rfc_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.OUD_ACL,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OUD-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OUD ACL data

            """
            try:
                # Convert RFC ACL to Oracle OUD format
                oud_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.OUD_ACL,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: "ds-cfg",
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(oud_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OUD ACL conversion failed: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Oracle OUD entry quirk (nested).

        Handles OUD-specific entry transformations:
        - OUD-specific operational attributes
        - OUD entry formatting
        - Compatibility with OID entries

        Example:
            quirk = FlextLdifQuirksServersOud.EntryQuirk(server_type="oud")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default=FlextLdifConstants.ServerTypes.OUD,
            description="Oracle OUD server type",
        )
        priority: int = Field(
            default=10, description="High priority for OUD entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OUD entry quirk."""

        def can_handle_entry(
            self, entry_dn: str, attributes: dict[str, object]
        ) -> bool:
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
            self, entry_dn: str, attributes: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Dict]:
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
                processed_entry: FlextLdifTypes.Dict = {
                    "dn": entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "oud",
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, _entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                _entry_data: Server-specific entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # OUD entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Dict].ok(_entry_data)
            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OUD entry→RFC conversion failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOud"]
