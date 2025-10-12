"""OpenLDAP 2.x Quirks - Complete Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OpenLDAP 2.x-specific quirks for schema, ACL, and entry processing.
OpenLDAP 2.x uses cn=config based configuration with olc* attributes.

This implementation handles:
- olcAttributeTypes: RFC 4512 compliant attribute definitions
- olcObjectClasses: RFC 4512 compliant object class definitions
- olcAccess: OpenLDAP 2.x ACL format (to <what> by <who> <access>)
- cn=config hierarchy: Configuration entries
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextCore
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOpenldap(FlextLdifQuirksBaseSchemaQuirk):
    """OpenLDAP 2.x schema quirk.

    Extends RFC 4512 schema parsing with OpenLDAP 2.x-specific features:
    - olc* namespace and attributes
    - olcAttributeTypes and olcObjectClasses
    - cn=config based schema configuration
    - OpenLDAP-specific extensions

    Example:
        quirk = FlextLdifQuirksServersOpenldap(server_type="openldap2")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(
        default="openldap2", description="OpenLDAP 2.x server type"
    )
    priority: int = Field(
        default=10, description="High priority for OpenLDAP 2.x-specific parsing"
    )

    # OpenLDAP 2.x olc* attribute pattern
    OPENLDAP_OLC_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\bolc[A-Z][a-zA-Z]*\b"
    )

    # OpenLDAP cn=config DN pattern
    OPENLDAP_CONFIG_DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"cn=config", re.IGNORECASE
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OpenLDAP 2.x schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an OpenLDAP 2.x attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains OpenLDAP 2.x markers

        """
        # Check for olc* prefix or olcAttributeTypes context
        return bool(self.OPENLDAP_OLC_PATTERN.search(attr_definition))

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Parse OpenLDAP 2.x attribute definition.

        OpenLDAP 2.x uses RFC 4512 compliant schema format, so we can
        parse with RFC parser and add OpenLDAP-specific metadata.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextCore.Result with parsed OpenLDAP 2.x attribute data

        """
        try:
            # OpenLDAP 2.x attributes are RFC 4512 compliant
            # Parse basic structure using regex
            oid_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID, attr_definition
            )
            name_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                attr_definition,
                re.IGNORECASE,
            )
            desc_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
                attr_definition,
                re.IGNORECASE,
            )
            syntax_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_SYNTAX, attr_definition
            )
            equality_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_EQUALITY,
                attr_definition,
                re.IGNORECASE,
            )
            single_value = bool(
                re.search(
                    FlextLdifConstants.LdifPatterns.SCHEMA_SINGLE_VALUE, attr_definition
                )
            )

            if not oid_match:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    "No OID found in attribute definition"
                )

            attr_data: FlextLdifTypes.Dict = {
                FlextLdifConstants.DictKeys.OID: oid_match.group(1),
                FlextLdifConstants.DictKeys.NAME: name_match.group(1)
                if name_match
                else None,
                FlextLdifConstants.DictKeys.DESC: desc_match.group(1)
                if desc_match
                else None,
                FlextLdifConstants.DictKeys.SYNTAX: syntax_match.group(1)
                if syntax_match
                else None,
                FlextLdifConstants.DictKeys.EQUALITY: equality_match.group(1)
                if equality_match
                else None,
                "single_value": single_value,
                FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap2",
            }

            return FlextCore.Result[FlextLdifTypes.Dict].ok(attr_data)

        except Exception as e:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 2.x attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an OpenLDAP 2.x objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains OpenLDAP 2.x markers

        """
        return bool(self.OPENLDAP_OLC_PATTERN.search(oc_definition))

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Parse OpenLDAP 2.x objectClass definition.

        OpenLDAP 2.x uses RFC 4512 compliant schema format.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextCore.Result with parsed OpenLDAP 2.x objectClass data

        """
        try:
            # Parse RFC 4512 compliant objectClass
            oid_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_OID, oc_definition
            )
            name_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_NAME,
                oc_definition,
                re.IGNORECASE,
            )
            desc_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_DESC,
                oc_definition,
                re.IGNORECASE,
            )
            sup_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_SUP, oc_definition, re.IGNORECASE
            )

            # Extract MUST attributes
            must_match = re.search(
                FlextLdifConstants.LdifPatterns.SCHEMA_MUST,
                oc_definition,
                re.IGNORECASE,
            )
            must_attrs = (
                [attr.strip() for attr in must_match.group(1).split("$")]
                if must_match
                else []
            )

            # Extract MAY attributes
            may_match = re.search(r"MAY\s+\(([^)]+)\)", oc_definition, re.IGNORECASE)
            may_attrs = (
                [attr.strip() for attr in may_match.group(1).split("$")]
                if may_match
                else []
            )

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            if re.search(r"\bSTRUCTURAL\b", oc_definition):
                kind = "STRUCTURAL"
            elif re.search(r"\bAUXILIARY\b", oc_definition):
                kind = "AUXILIARY"
            elif re.search(r"\bABSTRACT\b", oc_definition):
                kind = "ABSTRACT"
            else:
                kind = "STRUCTURAL"  # Default

            if not oid_match:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    "No OID found in objectClass definition"
                )

            oc_data: FlextLdifTypes.Dict = {
                FlextLdifConstants.DictKeys.OID: oid_match.group(1),
                FlextLdifConstants.DictKeys.NAME: name_match.group(1)
                if name_match
                else None,
                FlextLdifConstants.DictKeys.DESC: desc_match.group(1)
                if desc_match
                else None,
                FlextLdifConstants.DictKeys.SUP: sup_match.group(1)
                if sup_match
                else None,
                "kind": kind,
                "must": must_attrs,
                "may": may_attrs,
                FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap2",
            }

            return FlextCore.Result[FlextLdifTypes.Dict].ok(oc_data)

        except Exception as e:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 2.x objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Convert OpenLDAP 2.x attribute to RFC-compliant format.

        OpenLDAP 2.x attributes are already RFC-compliant.

        Args:
            attr_data: OpenLDAP 2.x attribute data

        Returns:
            FlextCore.Result with RFC-compliant attribute data

        """
        try:
            # OpenLDAP 2.x attributes are RFC-compliant
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: attr_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: attr_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: attr_data.get("desc"),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get("syntax"),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get("equality"),
                "single_value": attr_data.get("single_value"),
            }

            return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 2.x→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Convert OpenLDAP 2.x objectClass to RFC-compliant format.

        OpenLDAP 2.x objectClasses are already RFC-compliant.

        Args:
            oc_data: OpenLDAP 2.x objectClass data

        Returns:
            FlextCore.Result with RFC-compliant objectClass data

        """
        try:
            # OpenLDAP 2.x objectClasses are RFC-compliant
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: oc_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: oc_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: oc_data.get("desc"),
                FlextLdifConstants.DictKeys.SUP: oc_data.get("sup"),
                "kind": oc_data.get("kind"),
                "must": oc_data.get("must"),
                "may": oc_data.get("may"),
            }

            return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 2.x→RFC conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """OpenLDAP 2.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 2.x-specific ACL formats:
        - olcAccess: OpenLDAP 2.x access control directives
        - Format: to <what> by <who> <access>

        Example:
            quirk = FlextLdifQuirksServersOpenldap.AclQuirk(server_type="openldap2")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default="openldap2", description="OpenLDAP 2.x server type"
        )
        priority: int = Field(
            default=10, description="High priority for OpenLDAP 2.x ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OpenLDAP 2.x ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an OpenLDAP 2.x ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is OpenLDAP 2.x ACL format

            """
            # OpenLDAP 2.x ACLs start with "to" or "{n}to"
            return bool(
                re.match(r"^(\{\d+\})?\s*to\s+", acl_line, re.IGNORECASE)
            ) or acl_line.startswith(f"{FlextLdifConstants.DictKeys.OLCACCESS}:")

        def parse_acl(self, acl_line: str) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Parse OpenLDAP 2.x ACL definition.

            Format: to <what> by <who> <access>
            Example: to attrs=userPassword by self write by anonymous auth by * none

            Args:
                acl_line: ACL definition line

            Returns:
                FlextCore.Result with parsed OpenLDAP 2.x ACL data

            """
            try:
                # Remove olcAccess: prefix if present
                acl_content = acl_line
                if acl_line.startswith(f"{FlextLdifConstants.DictKeys.OLCACCESS}:"):
                    acl_content = acl_line[len("olcAccess:") :].strip()

                # Remove {n} index if present
                index_match = re.match(r"^\{(\d+)\}\s*(.+)", acl_content)
                if index_match:
                    index = int(index_match.group(1))
                    acl_content = index_match.group(2)
                else:
                    index = 0

                # Parse "to <what>" clause
                to_match = re.match(r"^to\s+(.+?)\s+by\s+", acl_content, re.IGNORECASE)
                if not to_match:
                    return FlextCore.Result[FlextLdifTypes.Dict].fail(
                        "Invalid OpenLDAP ACL format: missing 'to' clause"
                    )

                what = to_match.group(1).strip()

                # Parse "by <who> <access>" clauses
                by_pattern = re.compile(r"by\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
                by_clauses = [
                    {
                        "who": match.group(1),
                        FlextLdifConstants.DictKeys.ACCESS: match.group(2),
                    }
                    for match in by_pattern.finditer(acl_content)
                ]

                openldapacl_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.AclFormats.OPENLDAP2_ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.DictKeys.OLCACCESS,
                    "index": index,
                    "what": what,
                    "by_clauses": by_clauses,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                }

                return FlextCore.Result[FlextLdifTypes.Dict].ok(openldapacl_data)

            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 2.x ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Convert OpenLDAP 2.x ACL to RFC-compliant format.

            Args:
                acl_data: OpenLDAP 2.x ACL data

            Returns:
                FlextCore.Result with RFC-compliant ACL data

            """
            try:
                # OpenLDAP ACLs don't have direct RFC equivalent
                rfc_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: "openldap2",
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 2.x ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OpenLDAP 2.x-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextCore.Result with OpenLDAP 2.x ACL data

            """
            try:
                # Convert RFC ACL to OpenLDAP 2.x format
                openldap_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: "openldap2",
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.OLCACCESS,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextCore.Result[FlextLdifTypes.Dict].ok(openldap_data)

            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"RFC→OpenLDAP 2.x ACL conversion failed: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """OpenLDAP 2.x entry quirk (nested).

        Handles OpenLDAP 2.x-specific entry transformations:
        - cn=config hierarchy entries
        - olc* operational attributes
        - Database and overlay configuration entries

        Example:
            quirk = FlextLdifQuirksServersOpenldap.EntryQuirk(server_type="openldap2")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default="openldap2", description="OpenLDAP 2.x server type"
        )
        priority: int = Field(
            default=10, description="High priority for OpenLDAP 2.x entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OpenLDAP 2.x entry quirk."""

        def can_handle_entry(
            self, entry_dn: str, attributes: FlextCore.Types.Dict
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                True if this is an OpenLDAP 2.x-specific entry

            """
            # Check for cn=config DN or olc* attributes
            is_config_dn = "cn=config" in entry_dn.lower()

            # Check for olc* attributes
            has_olc_attrs = any(attr.startswith("olc") for attr in attributes)

            # Check for OpenLDAP 2.x object classes
            object_classes = attributes.get(FlextLdifConstants.DictKeys.OBJECTCLASS, [])
            if not isinstance(object_classes, list):
                object_classes = [object_classes]

            has_olc_classes = any(
                oc in FlextLdifConstants.LdapServers.OPENLDAP_2_OBJECTCLASSES
                for oc in object_classes
            )

            return is_config_dn or has_olc_attrs or has_olc_classes

        def process_entry(
            self, entry_dn: str, attributes: FlextCore.Types.Dict
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Process entry for OpenLDAP 2.x format.

            Args:
                entry_dn: Entry distinguished name
                attributes: Entry attributes

            Returns:
                FlextCore.Result with processed entry data

            """
            try:
                # OpenLDAP 2.x entries are RFC-compliant
                # Add OpenLDAP-specific processing if needed
                processed_entry: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap2",
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=config"
                    in entry_dn.lower(),
                }
                processed_entry.update(attributes)

                return FlextCore.Result[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 2.x entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Dict
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific entry data

            Returns:
                FlextCore.Result with RFC-compliant entry data

            """
            try:
                # OpenLDAP 2.x entries are already RFC-compliant
                return FlextCore.Result[FlextLdifTypes.Dict].ok(entry_data)
            except Exception as e:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 2.x entry→RFC conversion failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOpenldap"]
