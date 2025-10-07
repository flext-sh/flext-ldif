"""OpenLDAP 1.x Legacy Quirks - Complete Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides OpenLDAP 1.x-specific quirks for schema, ACL, and entry processing.
OpenLDAP 1.x uses slapd.conf based configuration with traditional attribute formats.

This implementation handles:
- attributetype: Traditional slapd.conf attribute definitions
- objectclass: Traditional slapd.conf object class definitions
- access: OpenLDAP 1.x ACL format (access to <what> by <who> <access>)
- Traditional DIT: Non-cn=config directory structure
"""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOpenldap1(FlextLdifQuirksBaseSchemaQuirk):
    """OpenLDAP 1.x schema quirk.

    Extends RFC 4512 schema parsing with OpenLDAP 1.x-specific features:
    - Traditional attributetype format from slapd.conf
    - Traditional objectclass format from slapd.conf
    - No olc* prefixes (pre-cn=config era)
    - Legacy OpenLDAP directives

    Example:
        quirk = FlextLdifQuirksServersOpenldap1(server_type="openldap1")
        if quirk.can_handle_attribute(attr_def):
            result = quirk.parse_attribute(attr_def)

    """

    server_type: str = Field(
        default="openldap1", description="OpenLDAP 1.x server type"
    )
    priority: int = Field(
        default=20, description="Lower priority than OpenLDAP 2.x (fallback)"
    )

    # OpenLDAP 1.x traditional attribute pattern (no olc* prefix)
    OPENLDAP1_ATTRIBUTE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*attributetype\s+", re.IGNORECASE
    )

    # OpenLDAP 1.x traditional objectclass pattern
    OPENLDAP1_OBJECTCLASS_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"^\s*objectclass\s+", re.IGNORECASE
    )

    def model_post_init(self, _context: object, /) -> None:
        """Initialize OpenLDAP 1.x schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if this is an OpenLDAP 1.x attribute.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            True if this contains OpenLDAP 1.x markers

        """
        # Check for traditional attributetype directive (not olc*)
        has_attributetype = bool(
            self.OPENLDAP1_ATTRIBUTE_PATTERN.match(attr_definition)
        )
        has_olc = "olc" in attr_definition.lower()

        return has_attributetype and not has_olc

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse OpenLDAP 1.x attribute definition.

        OpenLDAP 1.x uses RFC 4512 compliant schema format in slapd.conf.

        Args:
            attr_definition: AttributeType definition string

        Returns:
            FlextResult with parsed OpenLDAP 1.x attribute data

        """
        try:
            # Remove attributetype prefix if present
            attr_content = attr_definition
            if attr_definition.lower().startswith("attributetype"):
                attr_content = attr_definition[len("attributetype") :].strip()

            # Parse RFC 4512 compliant structure
            oid_match = re.search(r"^\s*\(\s*([\d.]+)", attr_content)
            name_match = re.search(r"NAME\s+'([^']+)'", attr_content, re.IGNORECASE)
            desc_match = re.search(r"DESC\s+'([^']+)'", attr_content, re.IGNORECASE)
            syntax_match = re.search(r"SYNTAX\s+([\d.]+)", attr_content)
            equality_match = re.search(r"EQUALITY\s+(\w+)", attr_content, re.IGNORECASE)
            single_value = bool(re.search(r"\bSINGLE-VALUE\b", attr_content))

            if not oid_match:
                return FlextResult[FlextLdifTypes.Dict].fail(
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
                FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap1",
            }

            return FlextResult[FlextLdifTypes.Dict].ok(attr_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 1.x attribute parsing failed: {e}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Check if this is an OpenLDAP 1.x objectClass.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            True if this contains OpenLDAP 1.x markers

        """
        # Check for traditional objectclass directive (not olc*)
        has_objectclass = bool(self.OPENLDAP1_OBJECTCLASS_PATTERN.match(oc_definition))
        has_olc = "olc" in oc_definition.lower()

        return has_objectclass and not has_olc

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse OpenLDAP 1.x objectClass definition.

        OpenLDAP 1.x uses RFC 4512 compliant schema format in slapd.conf.

        Args:
            oc_definition: ObjectClass definition string

        Returns:
            FlextResult with parsed OpenLDAP 1.x objectClass data

        """
        try:
            # Remove objectclass prefix if present
            oc_content = oc_definition
            if oc_definition.lower().startswith("objectclass"):
                oc_content = oc_definition[len("objectclass") :].strip()

            # Parse RFC 4512 compliant structure
            oid_match = re.search(r"^\s*\(\s*([\d.]+)", oc_content)
            name_match = re.search(r"NAME\s+'([^']+)'", oc_content, re.IGNORECASE)
            desc_match = re.search(r"DESC\s+'([^']+)'", oc_content, re.IGNORECASE)
            sup_match = re.search(r"SUP\s+(\w+)", oc_content, re.IGNORECASE)

            # Extract MUST attributes
            must_match = re.search(r"MUST\s+\(([^)]+)\)", oc_content, re.IGNORECASE)
            must_attrs = (
                [attr.strip() for attr in must_match.group(1).split("$")]
                if must_match
                else []
            )

            # Extract MAY attributes
            may_match = re.search(r"MAY\s+\(([^)]+)\)", oc_content, re.IGNORECASE)
            may_attrs = (
                [attr.strip() for attr in may_match.group(1).split("$")]
                if may_match
                else []
            )

            # Determine kind (STRUCTURAL, AUXILIARY, ABSTRACT)
            if re.search(r"\bSTRUCTURAL\b", oc_content):
                kind = "STRUCTURAL"
            elif re.search(r"\bAUXILIARY\b", oc_content):
                kind = "AUXILIARY"
            elif re.search(r"\bABSTRACT\b", oc_content):
                kind = "ABSTRACT"
            else:
                kind = "STRUCTURAL"  # Default

            if not oid_match:
                return FlextResult[FlextLdifTypes.Dict].fail(
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
                FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap1",
            }

            return FlextResult[FlextLdifTypes.Dict].ok(oc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 1.x objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OpenLDAP 1.x attribute to RFC-compliant format.

        OpenLDAP 1.x attributes are already RFC-compliant.

        Args:
            attr_data: OpenLDAP 1.x attribute data

        Returns:
            FlextResult with RFC-compliant attribute data

        """
        try:
            # OpenLDAP 1.x attributes are RFC-compliant
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: attr_data.get("oid"),
                FlextLdifConstants.DictKeys.NAME: attr_data.get("name"),
                FlextLdifConstants.DictKeys.DESC: attr_data.get("desc"),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get("syntax"),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get("equality"),
                "single_value": attr_data.get("single_value"),
            }

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as e:
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"OpenLDAP 1.x→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert OpenLDAP 1.x objectClass to RFC-compliant format.

        OpenLDAP 1.x objectClasses are already RFC-compliant.

        Args:
            oc_data: OpenLDAP 1.x objectClass data

        Returns:
            FlextResult with RFC-compliant objectClass data

        """
        try:
            # OpenLDAP 1.x objectClasses are RFC-compliant
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
                f"OpenLDAP 1.x→RFC conversion failed: {e}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """OpenLDAP 1.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 1.x-specific ACL formats:
        - access: OpenLDAP 1.x access control directives from slapd.conf
        - Format: access to <what> by <who> <access>

        Example:
            quirk = FlextLdifQuirksServersOpenldap1.AclQuirk(server_type="openldap1")
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: str = Field(
            default="openldap1", description="OpenLDAP 1.x server type"
        )
        priority: int = Field(
            default=20, description="Lower priority for OpenLDAP 1.x ACL parsing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OpenLDAP 1.x ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an OpenLDAP 1.x ACL.

            Args:
                acl_line: ACL definition line

            Returns:
                True if this is OpenLDAP 1.x ACL format

            """
            # OpenLDAP 1.x ACLs start with "access to"
            return bool(re.match(r"^\s*access\s+to\s+", acl_line, re.IGNORECASE))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse OpenLDAP 1.x ACL definition.

            Format: access to <what> by <who> <access>
            Example: access to attrs=userPassword by self write by * auth

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OpenLDAP 1.x ACL data

            """
            try:
                # Remove FlextLdifConstants.DictKeys.ACCESS prefix
                acl_content = acl_line
                if acl_line.lower().startswith(FlextLdifConstants.DictKeys.ACCESS):
                    acl_content = acl_line[
                        len(FlextLdifConstants.DictKeys.ACCESS) :
                    ].strip()

                # Parse "to <what>" clause
                to_match = re.match(r"^to\s+(.+?)\s+by\s+", acl_content, re.IGNORECASE)
                if not to_match:
                    return FlextResult[FlextLdifTypes.Dict].fail(
                        "Invalid OpenLDAP 1.x ACL format: missing 'to' clause"
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

                openldap1acl_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.AclFormats.OPENLDAP1_ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.DictKeys.ACCESS,
                    "what": what,
                    "by_clauses": by_clauses,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(openldap1acl_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 1.x ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert OpenLDAP 1.x ACL to RFC-compliant format.

            Args:
                acl_data: OpenLDAP 1.x ACL data

            Returns:
                FlextResult with RFC-compliant ACL data

            """
            try:
                # OpenLDAP ACLs don't have direct RFC equivalent
                rfc_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: "openldap1",
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 1.x ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifTypes.Dict
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Convert RFC ACL to OpenLDAP 1.x-specific format.

            Args:
                acl_data: RFC-compliant ACL data

            Returns:
                FlextResult with OpenLDAP 1.x ACL data

            """
            try:
                # Convert RFC ACL to OpenLDAP 1.x format
                openldap1_data: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: "openldap1",
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.ACCESS,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextResult[FlextLdifTypes.Dict].ok(openldap1_data)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→OpenLDAP 1.x ACL conversion failed: {e}"
                )

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """OpenLDAP 1.x entry quirk (nested).

        Handles OpenLDAP 1.x-specific entry transformations:
        - Traditional DIT structure (no cn=config)
        - Legacy OpenLDAP attributes
        - Pre-cn=config era entries

        Example:
            quirk = FlextLdifQuirksServersOpenldap1.EntryQuirk(server_type="openldap1")
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: str = Field(
            default="openldap1", description="OpenLDAP 1.x server type"
        )
        priority: int = Field(
            default=20, description="Lower priority for OpenLDAP 1.x entry processing"
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize OpenLDAP 1.x entry quirk."""

        def can_handle_entry(
            self, _entry_dn: str, _attributes: dict[str, object]
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                _entry_dn: Entry distinguished name
                _attributes: Entry _attributes

            Returns:
                True if this is an OpenLDAP 1.x-specific entry

            """
            # OpenLDAP 1.x entries do NOT have cn=config or olc* _attributes
            is_config_dn = "cn=config" in _entry_dn.lower()
            has_olc_attrs = any(attr.startswith("olc") for attr in _attributes)

            # Handle traditional entries (not config, not olc)
            return not is_config_dn and not has_olc_attrs

        def process_entry(
            self, _entry_dn: str, _attributes: dict[str, object]
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Process entry for OpenLDAP 1.x format.

            Args:
                _entry_dn: Entry distinguished name
                _attributes: Entry _attributes

            Returns:
                FlextResult with processed entry data

            """
            try:
                # OpenLDAP 1.x entries are RFC-compliant
                processed_entry: FlextLdifTypes.Dict = {
                    "dn": _entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap1",
                    "is_traditional_dit": True,
                }
                processed_entry.update(_attributes)

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 1.x entry processing failed: {e}"
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
                # OpenLDAP 1.x entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Dict].ok(_entry_data)
            except Exception as e:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"OpenLDAP 1.x entry→RFC conversion failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOpenldap1"]
