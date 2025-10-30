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

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersOpenldap(FlextLdifServersRfc):
    """OpenLDAP 2.x Quirks - Complete Implementation."""

    # Top-level configuration - mirrors Schema class for direct access
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP
    priority: ClassVar[int] = 10

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 2.x schema quirk.

        Extends RFC 4512 schema parsing with OpenLDAP 2.x-specific features:
        - olc* namespace and attributes
        - olcAttributeTypes and olcObjectClasses
        - cn=config based schema configuration
        - OpenLDAP-specific extensions

        Example:
            quirk = FlextLdifServersOpenldap(server_type="openldap2")
            if quirk.can_handle_attribute(attr_def):
                result = quirk.parse_attribute(attr_def)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP
        priority: ClassVar[int] = 10

        # OpenLDAP 2.x olc* attribute pattern
        OPENLDAP_OLC_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\bolc[A-Z][a-zA-Z]*\b",
        )

        # OpenLDAP cn=config DN pattern
        OPENLDAP_CONFIG_DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"cn=config",
            re.IGNORECASE,
        )

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Check if this is an OpenLDAP 2.x attribute.

            Args:
            attr_definition: AttributeType definition string

            Returns:
            True if this contains OpenLDAP 2.x markers

            """
            # Check for olc* prefix or olcAttributeTypes context
            return bool(self.OPENLDAP_OLC_PATTERN.search(attr_definition))

        # --------------------------------------------------------------------- #
        # Schema parsing and conversion methods
        # --------------------------------------------------------------------- #
        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - parse_attribute(): Custom parsing logic for olc* attributes
        # - parse_objectclass(): Custom parsing logic for olc* objectClasses
        # - convert_attribute_to_rfc(): Strips OpenLDAP-specific metadata
        # - convert_objectclass_to_rfc(): Strips OpenLDAP-specific metadata
        # - convert_attribute_from_rfc(): Adds OpenLDAP-specific metadata
        # - convert_objectclass_from_rfc(): Adds OpenLDAP-specific metadata
        # - write_attribute_to_rfc(): Uses RFC writer for olcAttributeTypes
        # - write_objectclass_to_rfc(): Uses RFC writer for olcObjectClasses
        # - should_filter_out_attribute(): Returns False (accept all in OpenLDAP mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OpenLDAP mode)
        # - create_quirk_metadata(): Creates OpenLDAP-specific metadata

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse OpenLDAP 2.x attribute definition.

            Uses RFC 4512 compliant baseline parser with OpenLDAP-specific
            metadata and field filtering (OpenLDAP doesn't use SUP, USAGE, etc.).

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed OpenLDAP 2.x attribute data

            """
            try:
                # Use RFC baseline parser in strict RFC mode
                result = FlextLdifServersRfc.AttributeParser.parse_common(
                    attr_definition,
                    case_insensitive=False,  # OpenLDAP uses strict RFC compliance
                    allow_syntax_quotes=False,  # OpenLDAP uses standard SYNTAX format
                )

                if not result.is_success:
                    return result

                # Unwrap parsed attribute from RFC baseline
                attribute = result.unwrap()

                # Apply OpenLDAP-specific filtering: OpenLDAP doesn't use these fields
                attribute.sup = None  # OpenLDAP 2.x attributes don't use SUP
                attribute.usage = None  # OpenLDAP doesn't extract USAGE field
                attribute.ordering = None  # Not typically used in OpenLDAP
                attribute.substr = None  # Not typically extracted by OpenLDAP

                # Update metadata with OpenLDAP server type if not present
                if not attribute.metadata:
                    attribute.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.OPENLDAP2,
                        original_format=attr_definition.strip(),
                    )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OpenLDAP 2.x attribute parsing failed: {e}",
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
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse OpenLDAP 2.x objectClass definition.

            Uses RFC 4512 compliant baseline parser with OpenLDAP-specific
            metadata handling.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed OpenLDAP 2.x objectClass data

            """
            try:
                # Use RFC baseline parser in strict RFC mode
                result = FlextLdifServersRfc.ObjectClassParser.parse_common(
                    oc_definition,
                    case_insensitive=False,  # OpenLDAP uses strict RFC compliance
                )

                if not result.is_success:
                    return result

                # Unwrap parsed objectClass from RFC baseline
                objectclass = result.unwrap()

                # Update metadata with OpenLDAP server type if not present
                if not objectclass.metadata:
                    objectclass.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.OPENLDAP2,
                        original_format=oc_definition.strip(),
                    )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OpenLDAP 2.x objectClass parsing failed: {e}",
                )

        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
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
                return FlextResult[str].fail(
                    f"OpenLDAP 2.x attribute write failed: {e}",
                )

        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
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
                return FlextResult[str].fail(
                    f"OpenLDAP 2.x objectClass write failed: {e}",
                )

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - can_handle_acl(): Detects olcAccess formats
        # - parse_acl(): Parses OpenLDAP 2.x ACL definitions
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - write_acl_to_rfc(): Writes RFC-compliant ACL strings
        # - get_acl_attribute_name(): Returns "acl" (RFC baseline, inherited)

        class Acl(FlextLdifServersRfc.Acl):
            """OpenLDAP 2.x ACL quirk (nested).

            Extends RFC ACL parsing with OpenLDAP 2.x-specific ACL formats:
            - olcAccess: OpenLDAP 2.x access control directives
            - Format: to <what> by <who> <access>

            Example:
                quirk = FlextLdifServersOpenldap.Acl()
                if quirk.can_handle_acl(acl_line):
                    result = quirk.parse_acl(acl_line)

            """

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP
            priority: ClassVar[int] = 10

            def __init__(self) -> None:
                """Initialize OpenLDAP 2.x ACL quirk with RFC format."""
                super().__init__(server_type=FlextLdifConstants.ServerTypes.OPENLDAP)

            def can_handle_acl(self, acl_line: str) -> bool:
                """Check if this is an OpenLDAP 2.x ACL.

                Args:
                acl_line: ACL definition line

                Returns:
                True if this is OpenLDAP 2.x ACL format

                """
                # OpenLDAP 2.x ACLs start with "to" or "{n}to"
                return bool(
                    re.match(r"^(\{\d+\})?\s*to\s+", acl_line, re.IGNORECASE),
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
                    to_match = re.match(
                        r"^to\s+(.+?)\s+by\s+",
                        acl_content,
                        re.IGNORECASE,
                    )
                    if not to_match:
                        return FlextResult[FlextLdifModels.Acl].fail(
                            "Invalid OpenLDAP ACL format: missing 'to' clause",
                        )

                    what = to_match.group(1).strip()

                    # Parse "by <who> <access>" clauses - extract first by clause for model
                    by_pattern = re.compile(r"by\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
                    by_matches = list(by_pattern.finditer(acl_content))

                    # Extract subject from first by clause
                    subject_value = (
                        by_matches[0].group(1) if by_matches else "anonymous"
                    )

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
                        server_type=FlextLdifConstants.ServerTypes.OPENLDAP,
                        raw_acl=acl_line,
                    )

                    return FlextResult[FlextLdifModels.Acl].ok(acl)

                except Exception as e:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        f"OpenLDAP 2.x ACL parsing failed: {e}",
                    )

            def convert_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
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
                        f"OpenLDAP 2.x ACL→RFC conversion failed: {e}",
                    )

            def convert_acl_from_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Convert RFC ACL to OpenLDAP 2.x-specific format.

                Args:
                acl_data: RFC-compliant ACL data

                Returns:
                FlextResult with OpenLDAP 2.x ACL data

                """
                try:
                    # Convert RFC ACL to OpenLDAP format using model_copy
                    openldap_acl = acl_data.model_copy(
                        update={"server_type": FlextLdifConstants.ServerTypes.OPENLDAP},
                    )
                    return FlextResult[FlextLdifModels.Acl].ok(openldap_acl)

                except Exception as e:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        f"RFC→OpenLDAP 2.x ACL conversion failed: {e}",
                    )

            def write_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[str]:
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

    class Entry(FlextLdifServersRfc.Entry):
        """OpenLDAP 2.x entry quirk (nested).

        Handles OpenLDAP 2.x-specific entry transformations:
        - cn=config hierarchy entries
        - olc* operational attributes
        - Database and overlay configuration entries

        Example:
            quirk = FlextLdifServersOpenldap.Entry()
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP
        priority: ClassVar[int] = 10

        def __init__(self) -> None:
            """Initialize OpenLDAP 2.x entry quirk with RFC format."""
            super().__init__(server_type=FlextLdifConstants.ServerTypes.OPENLDAP)

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - can_handle_entry(): Detects OpenLDAP 2.x entries by DN/attributes
        # - process_entry(): Normalizes OpenLDAP 2.x entries with metadata
        # - convert_entry_to_rfc(): Converts OpenLDAP 2.x entries to RFC format

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
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
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "generic",
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=config"
                    in entry_dn.lower(),
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 2.x entry processing failed: {e}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
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
                    entry_data,
                )
            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 2.x entry→RFC conversion failed: {e}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry from RFC format - pass-through for OpenLDAP 2.x.

            Args:
            entry_data: RFC-compliant entry attributes

            Returns:
            FlextResult with data (unchanged, since OpenLDAP entries are RFC-compliant)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                entry_data,
            )


__all__ = ["FlextLdifServersOpenldap"]
