"""Oracle Internet Directory (OID) Quirks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Implements Oracle OID-specific extensions as quirks on top of RFC-compliant
base parsers. This wraps existing OID parser logic as composable quirks.

OID-specific features:
- Oracle OID attribute types (2.16.840.1.113894.* namespace)
- Oracle orclaci and orclentrylevelaci ACLs
- Oracle-specific schema attributes
- Oracle operational attributes
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOid(FlextLdifQuirksBaseSchemaQuirk):
    """Oracle OID schema quirk.

    Extends RFC 4512 schema parsing with Oracle OID-specific features:
    - Oracle OID namespace (2.16.840.1.113894.*)
    - Oracle-specific syntaxes
    - Oracle attribute extensions

    Example:
        quirk = FlextLdifQuirksServersOid(server_type="oid")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(default="oid", description="Oracle OID server type")
    priority: int = Field(
        default=10, description="High priority for OID-specific parsing"
    )

    # Oracle OID namespace pattern
    ORACLE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"2\.16\.840\.1\.113894\."
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OID schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an Oracle OID attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains Oracle OID namespace

        """
        return bool(self.ORACLE_OID_PATTERN.search(attr_definition))

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OID attribute definition.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed OID attribute data

        """
        try:
            # Parse OID attribute using FlextLdifModels
            # This wraps the existing OID parsing logic
            attr_result = FlextLdifModels.OidSchemaAttribute.from_ldif_line(
                f"attributetypes: {attr_definition}"
            )

            if attr_result.is_success:
                attr_obj = attr_result.value
                # Convert to dict for quirk system
                return FlextResult[FlextLdifTypes.Dict].ok(
                    attr_obj.model_dump() if hasattr(attr_obj, "model_dump") else {}
                )

            return FlextResult[FlextLdifTypes.Dict].fail(
                attr_result.error or "Failed to parse OID attribute"
            )

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an Oracle OID objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains Oracle OID namespace

        """
        return bool(self.ORACLE_OID_PATTERN.search(oc_definition))

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse Oracle OID objectClass definition.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed OID objectClass data

        """
        try:
            # Parse OID objectClass using FlextLdifModels
            # This wraps the existing OID parsing logic
            oc_result = FlextLdifModels.OidSchemaObjectClass.from_ldif_line(
                f"objectclasses: {oc_definition}"
            )

            if oc_result.is_success:
                oc_obj = oc_result.value
                # Convert to dict for quirk system
                return FlextResult[FlextLdifTypes.Dict].ok(
                    oc_obj.model_dump() if hasattr(oc_obj, "model_dump") else {}
                )

            return FlextResult[FlextLdifTypes.Dict].fail(
                oc_result.error or "Failed to parse OID objectClass"
            )

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OID attribute to RFC-compliant format.

        Args:
            attr_data: OID attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """
        try:
            # Oracle OID attributes can be represented in RFC format
            # by removing Oracle-specific extensions
            rfc_data = {
                "oid": attr_data.get("oid"),
                "name": attr_data.get("name"),
                "desc": attr_data.get("desc"),
                "syntax": attr_data.get("syntax"),
                "equality": attr_data.get("equality"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OID objectClass to RFC-compliant format.

        Args:
            oc_data: OID objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """
        try:
            # Convert Oracle OID objectClass to RFC format
            rfc_data = {
                "oid": oc_data.get("oid"),
                "name": oc_data.get("name"),
                "desc": oc_data.get("desc"),
                "sup": oc_data.get("sup"),
                "kind": oc_data.get("kind"),
                "must": oc_data.get("must"),
                "may": oc_data.get("may"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OID→RFC conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Oracle OID ACL quirk (nested).

        Extends RFC ACL parsing with Oracle OID-specific ACL formats:
        - orclaci: Oracle standard ACIs
        - orclentrylevelaci: Oracle entry-level ACIs

        Example:
            quirk = FlextLdifQuirksServersOid.AclQuirk(server_type="oid")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(default="oid", description="Oracle OID server type")
        priority: int = Field(
            default=10, description="High priority for OID ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an Oracle OID ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is orclaci or orclentrylevelaci

            """
            return acl_line.startswith(("orclaci:", "orclentrylevelaci:"))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse Oracle OID ACL definition.

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OID ACL data

            """
            try:
                # Determine ACL type
                is_entry_level = acl_line.startswith("orclentrylevelaci:")

                # Parse using existing OID ACI parser models
                acl_obj: FlextLdifModels.OidEntryLevelAci | FlextLdifModels.OidAci
                if is_entry_level:
                    entry_result = FlextLdifModels.OidEntryLevelAci.from_ldif_line(
                        acl_line
                    )
                    if entry_result.is_failure:
                        return FlextResult[FlextLdifTypes.Dict].fail(entry_result.error)
                    acl_obj = entry_result.value
                else:
                    standard_result = FlextLdifModels.OidAci.from_ldif_line(acl_line)
                    if standard_result.is_failure:
                        return FlextResult[FlextLdifTypes.Dict].fail(
                            standard_result.error
                        )
                    acl_obj = standard_result.value

                return FlextResult[FlextLdifTypes.Dict].ok({
                    "type": "entry_level" if is_entry_level else "standard",
                    "raw": acl_line,
                    "parsed": (
                        acl_obj.model_dump() if hasattr(acl_obj, "model_dump") else {}
                    ),
                })

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert OID ACL to RFC-compliant format.

            Args:
                acl_data: OID ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # Oracle OID ACLs don't have direct RFC equivalent
                # Return generic ACL representation
                rfc_data: FlextLdifTypes.Dict = {
                    "type": "acl",
                    "format": "rfc_generic",
                    "source_format": "oracle_oid",
                    "data": acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OID-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OID ACL data

            """
            try:
                # Convert RFC ACL to Oracle OID format
                # This is target-specific conversion for migrations
                oid_data: FlextLdifTypes.Dict = {
                    "format": "oracle_oid",
                    "target_format": "orclaci",
                    "data": acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(oid_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OID ACL conversion failed: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Oracle OID entry quirk (nested).

        Handles Oracle OID-specific entry transformations:
        - Oracle operational attributes
        - OID-specific object classes
        - Oracle namespace attributes

        Example:
            quirk = FlextLdifQuirksServersOid.EntryQuirk(server_type="oid")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(default="oid", description="Oracle OID server type")
        priority: int = Field(
            default=10, description="High priority for OID entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OID entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: dict[str, object],
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an Oracle OID-specific entry

            """
            # Check for Oracle OID-specific attributes
            oid_attrs = [
                "orclguid",
                "orclobjectguid",
                "orclaci",
                "orclentrylevelaci",
                "orclaci",
                "orclentrycreatetime",
                "orclentrymodifytime",
            ]

            has_oid_attrs = any(
                attr.lower() in [a.lower() for a in attributes] for attr in oid_attrs
            )

            # Check for Oracle OID object classes
            object_classes = attributes.get("objectClass", [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]

            has_oid_classes = any(
                str(oc).lower().startswith("orcl") for oc in object_classes
            )

            # Also check DN patterns for OID entries
            has_oid_dn_pattern = any(
                pattern in entry_dn.lower()
                for pattern in ["cn=orcl", "ou=oracle", "dc=oracle"]
            )

            return has_oid_attrs or has_oid_classes or has_oid_dn_pattern

        def process_entry(
            self, entry_dn: str, attributes: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Process entry for Oracle OID format.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextResult with processed entry data

            """
            try:
                # Oracle OID entries are RFC-compliant
                # Add OID-specific metadata
                processed_entry: FlextLdifTypes.Dict = {
                    "dn": entry_dn,
                    "server_type": "oid",
                    "has_oid_acls": any(
                        attr in attributes for attr in ["orclaci", "orclentrylevelaci"]
                    ),
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert Oracle OID entry to RFC-compliant format.

            Args:
                entry_data: Oracle OID entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # Oracle OID entries are already RFC-compliant
                # Remove Oracle-specific operational attributes if needed
                rfc_data = dict(entry_data)

                # Optional: Remove OID-specific operational attributes
                # that don't exist in standard LDAP
                oid_operational_attrs = [
                    "orclguid",
                    "orclobjectguid",
                    "orclentrycreatetime",
                    "orclentrymodifytime",
                    "has_oid_acls",
                    "server_type",
                ]

                for attr in oid_operational_attrs:
                    rfc_data.pop(attr, None)

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OID entry→RFC conversion failed: {e}"
                )


__all__ = [
    "FlextLdifQuirksServersOid",
]
