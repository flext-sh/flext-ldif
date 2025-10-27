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

from flext_core import FlextResult

# Pydantic removed
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    BaseAclQuirk,
    BaseEntryQuirk,
    BaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersOpenldap(BaseSchemaQuirk):
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

    # OpenLDAP 2.x olc* attribute pattern
    OPENLDAP_OLC_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\bolc[A-Z][a-zA-Z]*\b"
    )

    # OpenLDAP cn=config DN pattern
    OPENLDAP_CONFIG_DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"cn=config", re.IGNORECASE
    )

    def __init__(
        self,
        server_type: str = "openldap2",
        priority: int = 10,
    ) -> None:
        """Initialize OpenLDAP 2.x schema quirk.

        Args:
            server_type: OpenLDAP 2.x server type
            priority: High priority for OpenLDAP 2.x-specific parsing

        """
        super().__init__(server_type=server_type, priority=priority)

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
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse OpenLDAP 2.x attribute definition.

        OpenLDAP 2.x uses RFC 4512 compliant schema format, so we can
        parse with RFC parser and add OpenLDAP-specific metadata.

        Args:
        attr_definition: AttributeType definition string

        Returns:
        FlextResult with parsed OpenLDAP 2.x attribute data

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
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    "No OID found in attribute definition"
                )

            # Build SchemaAttribute model directly (NO dict building)
            attribute = FlextLdifModels.SchemaAttribute(
                oid=oid_match.group(1),
                name=name_match.group(1) if name_match else "",
                desc=desc_match.group(1) if desc_match else None,
                syntax=syntax_match.group(1) if syntax_match else None,
                equality=equality_match.group(1) if equality_match else None,
                sup=None,  # OpenLDAP 2.x attributes don't use SUP
                ordering=None,  # Not extracted by OpenLDAP parser
                substr=None,  # Not extracted by OpenLDAP parser
                length=None,  # Not extracted by OpenLDAP parser
                usage=None,  # Not extracted by OpenLDAP parser
                single_value=single_value,
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type="openldap2", original_format=attr_definition.strip()
                ),
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
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
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse OpenLDAP 2.x objectClass definition.

        OpenLDAP 2.x uses RFC 4512 compliant schema format.

        Args:
        oc_definition: ObjectClass definition string

        Returns:
        FlextResult with parsed OpenLDAP 2.x objectClass data

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
                kind = FlextLdifConstants.Schema.STRUCTURAL
            elif re.search(r"\bAUXILIARY\b", oc_definition):
                kind = FlextLdifConstants.Schema.AUXILIARY
            elif re.search(r"\bABSTRACT\b", oc_definition):
                kind = FlextLdifConstants.Schema.ABSTRACT
            else:
                kind = FlextLdifConstants.Schema.STRUCTURAL  # Default

            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "No OID found in objectClass definition"
                )

            # Build SchemaObjectClass model directly (NO dict building)
            objectclass = FlextLdifModels.SchemaObjectClass(
                oid=oid_match.group(1),
                name=name_match.group(1) if name_match else None,
                desc=desc_match.group(1) if desc_match else None,
                sup=sup_match.group(1) if sup_match else None,
                kind=kind,
                must=must_attrs,
                may=may_attrs,
                metadata=FlextLdifModels.QuirkMetadata(
                    quirk_type="openldap2", original_format=oc_definition.strip()
                ),
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"OpenLDAP 2.x objectClass parsing failed: {e}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert OpenLDAP 2.x attribute to RFC-compliant format.

        OpenLDAP 2.x attributes are already RFC-compliant.

        Args:
        attr_data: OpenLDAP 2.x attribute model

        Returns:
        FlextResult with RFC-compliant attribute model

        """
        try:
            # OpenLDAP 2.x attributes are RFC-compliant - just return as-is
            # (Already a SchemaAttribute model)
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attr_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"OpenLDAP 2.x→RFC conversion failed: {e}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert OpenLDAP 2.x objectClass to RFC-compliant format.

        OpenLDAP 2.x objectClasses are already RFC-compliant.

        Args:
        oc_data: OpenLDAP 2.x objectClass model

        Returns:
        FlextResult with RFC-compliant objectClass model

        """
        try:
            # OpenLDAP 2.x objectClasses are RFC-compliant - just return as-is
            # (Already a SchemaObjectClass model)
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

        except Exception as e:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"OpenLDAP 2.x→RFC conversion failed: {e}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to OpenLDAP 2.x-specific format.

        OpenLDAP 2.x attributes are already RFC-compliant, so minimal conversion needed.

        Args:
        rfc_data: RFC-compliant attribute model

        Returns:
        FlextResult with OpenLDAP 2.x attribute model

        """
        # OpenLDAP 2.x uses RFC format - just return the model as-is
        # (models don't have server_type field, so no conversion needed)
        return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to OpenLDAP 2.x-specific format.

        OpenLDAP 2.x objectClasses are already RFC-compliant, so minimal conversion needed.

        Args:
        rfc_data: RFC-compliant objectClass model

        Returns:
        FlextResult with OpenLDAP 2.x objectClass model

        """
        # OpenLDAP 2.x uses RFC format - just return the model as-is
        # (models don't have server_type field, so no conversion needed)
        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format.

        Args:
        attr_data: SchemaAttribute model

        Returns:
        FlextResult with RFC-compliant attribute string

        """
        try:
            # Check for original_format in metadata (round-trip preservation)
            if attr_data.metadata and attr_data.metadata.original_format:
                return FlextResult[str].ok(attr_data.metadata.original_format)

            # Access model fields (NO .get())
            oid = attr_data.oid
            name = attr_data.name
            desc = attr_data.desc
            syntax = attr_data.syntax
            equality = attr_data.equality
            single_value = attr_data.single_value or False

            # Build attribute string
            attr_str = f"( {oid}"
            if name:
                attr_str += f" NAME '{name}'"
            if desc:
                attr_str += f" DESC '{desc}'"
            if syntax:
                attr_str += f" SYNTAX {syntax}"
            if equality:
                attr_str += f" EQUALITY {equality}"
            if single_value:
                attr_str += " SINGLE-VALUE"
            attr_str += " )"

            return FlextResult[str].ok(attr_str)

        except Exception as e:
            return FlextResult[str].fail(f"OpenLDAP 2.x attribute write failed: {e}")

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format.

        Args:
        oc_data: SchemaObjectClass model

        Returns:
        FlextResult with RFC-compliant objectClass string

        """
        try:
            # Check for original_format in metadata (round-trip preservation)
            if oc_data.metadata and oc_data.metadata.original_format:
                return FlextResult[str].ok(oc_data.metadata.original_format)

            # Access model fields (NO .get())
            oid = oc_data.oid
            name = oc_data.name
            desc = oc_data.desc
            sup = oc_data.sup
            kind = oc_data.kind or "STRUCTURAL"
            must = oc_data.must or []
            may = oc_data.may or []

            # Build objectClass string
            oc_str = f"( {oid}"
            if name:
                oc_str += f" NAME '{name}'"
            if desc:
                oc_str += f" DESC '{desc}'"
            if sup:
                oc_str += f" SUP {sup}"
            oc_str += f" {kind}"
            if must and isinstance(must, list):
                must_attrs = " $ ".join(must)
                oc_str += f" MUST ( {must_attrs} )"
            if may and isinstance(may, list):
                may_attrs = " $ ".join(may)
                oc_str += f" MAY ( {may_attrs} )"
            oc_str += " )"

            return FlextResult[str].ok(oc_str)

        except Exception as e:
            return FlextResult[str].fail(f"OpenLDAP 2.x objectClass write failed: {e}")

    class AclQuirk(BaseAclQuirk):
        """OpenLDAP 2.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 2.x-specific ACL formats:
        - olcAccess: OpenLDAP 2.x access control directives
        - Format: to <what> by <who> <access>

        Example:
            quirk = FlextLdifQuirksServersOpenldap.AclQuirk()
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        def __init__(
            self,
            server_type: str = "openldap2",
            priority: int = 10,
        ) -> None:
            """Initialize OpenLDAP 2.x ACL quirk.

            Args:
                server_type: OpenLDAP 2.x server type
                priority: High priority for OpenLDAP 2.x ACL parsing

            """
            super().__init__(server_type=server_type, priority=priority)

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

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OpenLDAP 2.x ACL definition.

            Format: to <what> by <who> <access>
            Example: to attrs=userPassword by self write by anonymous auth by * none

            Args:
            acl_line: ACL definition line

            Returns:
            FlextResult with parsed OpenLDAP 2.x ACL data

            """
            try:
                # Remove olcAccess: prefix if present
                acl_content = acl_line
                if acl_line.startswith(f"{FlextLdifConstants.DictKeys.OLCACCESS}:"):
                    acl_content = acl_line[len("olcAccess:") :].strip()

                # Remove {n} index if present
                index_match = re.match(r"^\{(\d+)\}\s*(.+)", acl_content)
                if index_match:
                    acl_content = index_match.group(2)

                # Parse "to <what>" clause
                to_match = re.match(r"^to\s+(.+?)\s+by\s+", acl_content, re.IGNORECASE)
                if not to_match:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        "Invalid OpenLDAP ACL format: missing 'to' clause"
                    )

                what = to_match.group(1).strip()

                # Parse "by <who> <access>" clauses - extract first by clause for model
                by_pattern = re.compile(r"by\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
                by_matches = list(by_pattern.finditer(acl_content))

                # Extract subject from first by clause
                subject_value = by_matches[0].group(1) if by_matches else "anonymous"

                # Extract access permissions from first by clause
                access = by_matches[0].group(2) if by_matches else "none"

                # Build Acl model
                acl = FlextLdifModels.Acl(
                    name="access",
                    target=FlextLdifModels.AclTarget(
                        target_dn=what,  # OpenLDAP: "what" is target
                        attributes=[],  # OpenLDAP stub - not extracted from what clause
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="who",
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read="read" in access,
                        write="write" in access,
                        add="write" in access,  # OpenLDAP: write includes add
                        delete="write" in access,  # OpenLDAP: write includes delete
                        search="read" in access,  # OpenLDAP: read includes search
                        compare="read" in access,  # OpenLDAP: read includes compare
                    ),
                    server_type="openldap",
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OpenLDAP 2.x ACL parsing failed: {e}"
                )

        def convert_acl_to_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert OpenLDAP 2.x ACL to RFC-compliant format.

            Args:
            acl_data: OpenLDAP 2.x ACL data

            Returns:
            FlextResult with RFC-compliant ACL data

            """
            try:
                # Convert OpenLDAP ACL to RFC format using model_copy
                rfc_acl = acl_data.model_copy(update={"server_type": "rfc"})
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OpenLDAP 2.x ACL→RFC conversion failed: {e}"
                )

        def convert_acl_from_rfc(
            self, acl_data: FlextLdifModels.Acl
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL to OpenLDAP 2.x-specific format.

            Args:
            acl_data: RFC-compliant ACL data

            Returns:
            FlextResult with OpenLDAP 2.x ACL data

            """
            try:
                # Convert RFC ACL to OpenLDAP format using model_copy
                openldap_acl = acl_data.model_copy(update={"server_type": "openldap"})
                return FlextResult[FlextLdifModels.Acl].ok(openldap_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→OpenLDAP 2.x ACL conversion failed: {e}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Args:
            acl_data: Acl model

            Returns:
            FlextResult with RFC-compliant ACL string

            """
            try:
                # If raw_acl is available, use it
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Otherwise reconstruct from model fields (OpenLDAP 2.x format)
                what = acl_data.target.target_dn if acl_data.target else "*"
                who = acl_data.subject.subject_value if acl_data.subject else "*"

                # Format as OpenLDAP 2.x ACL
                acl_parts = [f"to {what}"]
                acl_parts.append(f"by {who}")

                if acl_data.permissions:
                    # Add permissions if available
                    perms = []
                    if acl_data.permissions.read:
                        perms.append("read")
                    if acl_data.permissions.write:
                        perms.append("write")
                    if perms:
                        acl_parts.append(",".join(perms))

                acl_str = " ".join(acl_parts)
                return FlextResult[str].ok(acl_str)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP 2.x ACL write failed: {e}")

    class EntryQuirk(BaseEntryQuirk):
        """OpenLDAP 2.x entry quirk (nested).

        Handles OpenLDAP 2.x-specific entry transformations:
        - cn=config hierarchy entries
        - olc* operational attributes
        - Database and overlay configuration entries

        Example:
            quirk = FlextLdifQuirksServersOpenldap.EntryQuirk()
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        def __init__(
            self,
            server_type: str = "openldap2",
            priority: int = 10,
        ) -> None:
            """Initialize OpenLDAP 2.x entry quirk.

            Args:
                server_type: OpenLDAP 2.x server type
                priority: High priority for OpenLDAP 2.x entry processing

            """
            super().__init__(server_type=server_type, priority=priority)

        def can_handle_entry(
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
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
            self, entry_dn: str, attributes: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry for OpenLDAP 2.x format.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

            Returns:
            FlextResult with processed entry data

            """
            try:
                # OpenLDAP 2.x entries are RFC-compliant
                # Add OpenLDAP-specific processing if needed
                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "openldap2",
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=config"
                    in entry_dn.lower(),
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 2.x entry processing failed: {e}"
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifTypes.Models.EntryAttributesDict
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
            entry_data: Server-specific entry data

            Returns:
            FlextResult with RFC-compliant entry data

            """
            try:
                # OpenLDAP 2.x entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    entry_data
                )
            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 2.x entry→RFC conversion failed: {e}"
                )


__all__ = ["FlextLdifQuirksServersOpenldap"]
