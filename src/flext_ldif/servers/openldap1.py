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

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersOpenldap1(FlextLdifServersRfc):
    """OpenLDAP 1.x Legacy Quirks - Complete Implementation."""

    # Top-level configuration - mirrors Schema class for direct access
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
    priority: ClassVar[int] = 20

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 1.x schema quirk.

        Extends RFC 4512 schema parsing with OpenLDAP 1.x-specific features:
        - Traditional attributetype format from slapd.conf
        - Traditional objectclass format from slapd.conf
        - No olc* prefixes (pre-cn=config era)
        - Legacy OpenLDAP directives

        Example:
            quirk = FlextLdifServersOpenldap1()
            if quirk.can_handle_attribute(attr_def):
                result = quirk.parse_attribute(attr_def)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
        priority: ClassVar[int] = 20

        # OpenLDAP 1.x traditional attribute pattern (no olc* prefix)
        OPENLDAP1_ATTRIBUTE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^\s*attributetype\s+",
            re.IGNORECASE,
        )

        # OpenLDAP 1.x traditional objectclass pattern
        OPENLDAP1_OBJECTCLASS_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^\s*objectclass\s+",
            re.IGNORECASE,
        )

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Check if this is an OpenLDAP 1.x attribute.

            Args:
            attr_definition: AttributeType definition string

            Returns:
            True if this contains OpenLDAP 1.x markers

            """
            # Check for traditional attributetype directive (not olc*)
            has_attributetype = bool(
                self.OPENLDAP1_ATTRIBUTE_PATTERN.match(attr_definition),
            )
            has_olc = "olc" in attr_definition.lower()

            return has_attributetype and not has_olc

        # --------------------------------------------------------------------- #
        # Schema parsing and conversion methods
        # --------------------------------------------------------------------- #
        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - parse_attribute(): Custom parsing logic for slapd.conf format
        # - parse_objectclass(): Custom parsing logic for slapd.conf format
        # - convert_attribute_to_rfc(): Strips OpenLDAP 1.x-specific metadata
        # - convert_objectclass_to_rfc(): Strips OpenLDAP 1.x-specific metadata
        # - convert_attribute_from_rfc(): Adds OpenLDAP 1.x-specific metadata
        # - convert_objectclass_from_rfc(): Adds OpenLDAP 1.x-specific metadata
        # - write_attribute_to_rfc(): Uses RFC writer for attributeType format
        # - write_objectclass_to_rfc(): Uses RFC writer for objectClass format
        # - should_filter_out_attribute(): Returns False (accept all in OpenLDAP 1.x mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OpenLDAP 1.x mode)
        # - create_quirk_metadata(): Creates OpenLDAP 1.x-specific metadata

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse OpenLDAP 1.x attribute definition.

            Uses RFC 4512 compliant baseline parser (after stripping slapd.conf prefix)
            with OpenLDAP 1.x-specific field filtering.

            Args:
                attr_definition: AttributeType definition string

            Returns:
                FlextResult with parsed OpenLDAP 1.x attribute data

            """
            try:
                # Remove attributetype prefix if present (OpenLDAP 1.x slapd.conf format)
                attr_content = attr_definition
                if attr_definition.lower().startswith("attributetype"):
                    attr_content = attr_definition[len("attributetype") :].strip()

                # Use RFC baseline parser in strict RFC mode
                result = FlextLdifServersRfc.AttributeParser.parse_common(
                    attr_content,
                    case_insensitive=False,  # OpenLDAP 1.x uses strict RFC compliance
                    allow_syntax_quotes=False,  # Standard SYNTAX format
                )

                if not result.is_success:
                    return result

                # Unwrap parsed attribute from RFC baseline
                attribute = result.unwrap()

                # Apply OpenLDAP 1.x-specific filtering: fields not extracted from slapd.conf
                attribute.sup = None  # Not extracted in OpenLDAP 1.x slapd.conf
                attribute.ordering = None  # Not extracted
                attribute.substr = None  # Not extracted
                attribute.length = None  # Not extracted
                attribute.usage = None  # Not extracted

                # Update metadata with OpenLDAP 1.x server type if not present
                if not attribute.metadata:
                    attribute.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.OPENLDAP1,
                        original_format=attr_definition.strip(),
                    )

                return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    f"OpenLDAP 1.x attribute parsing failed: {e}",
                )

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Check if this is an OpenLDAP 1.x objectClass.

            Args:
            oc_definition: ObjectClass definition string

            Returns:
            True if this contains OpenLDAP 1.x markers

            """
            # Check for traditional objectclass directive (not olc*)
            has_objectclass = bool(
                self.OPENLDAP1_OBJECTCLASS_PATTERN.match(oc_definition),
            )
            has_olc = "olc" in oc_definition.lower()

            return has_objectclass and not has_olc

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse OpenLDAP 1.x objectClass definition.

            Uses RFC 4512 compliant baseline parser (after stripping slapd.conf prefix)
            with OpenLDAP 1.x-specific metadata handling.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with parsed OpenLDAP 1.x objectClass data

            """
            try:
                # Remove objectclass prefix if present (OpenLDAP 1.x slapd.conf format)
                oc_content = oc_definition
                if oc_definition.lower().startswith(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                ):
                    oc_content = oc_definition[
                        len(FlextLdifConstants.DictKeys.OBJECTCLASS) :
                    ].strip()

                # Use RFC baseline parser in strict RFC mode
                result = FlextLdifServersRfc.ObjectClassParser.parse_common(
                    oc_content,
                    case_insensitive=False,  # OpenLDAP 1.x uses strict RFC compliance
                )

                if not result.is_success:
                    return result

                # Unwrap parsed objectClass from RFC baseline
                objectclass = result.unwrap()

                # Update metadata with OpenLDAP 1.x server type if not present
                if not objectclass.metadata:
                    objectclass.metadata = FlextLdifModels.QuirkMetadata(
                        quirk_type=FlextLdifConstants.ServerTypes.OPENLDAP1,
                        original_format=oc_definition.strip(),
                    )

                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(objectclass)

            except Exception as e:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    f"OpenLDAP 1.x objectClass parsing failed: {e}",
                )

        def write_attribute_to_rfc(
            self,
            attr_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[str]:
            """Write attribute data to RFC-compliant string format.

            Args:
            attr_data: Attribute data dictionary

            Returns:
            FlextResult with RFC-compliant attribute string

            """
            try:
                # Build RFC 4512 compliant attribute definition from model
                oid = attr_data.oid
                name = attr_data.name
                desc = attr_data.desc
                syntax = attr_data.syntax
                equality = attr_data.equality
                single_value = attr_data.single_value or False

                # Build attribute string (attributetype prefix for OpenLDAP 1.x)
                attr_str = f"attributetype ( {oid}"
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
                    f"OpenLDAP 1.x attribute write failed: {e}",
                )

        def write_objectclass_to_rfc(
            self,
            oc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write objectClass data to RFC-compliant string format.

            Args:
            oc_data: ObjectClass data dictionary

            Returns:
            FlextResult with RFC-compliant objectClass string

            """
            try:
                # Build RFC 4512 compliant objectClass definition from model
                oid = oc_data.oid
                name = oc_data.name
                desc = oc_data.desc
                sup = oc_data.sup
                kind = oc_data.kind or "STRUCTURAL"
                must = oc_data.must or []
                may = oc_data.may or []

                # Build objectClass string (objectclass prefix for OpenLDAP 1.x)
                oc_str = f"objectclass ( {oid}"
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
                    f"OpenLDAP 1.x objectClass write failed: {e}",
                )

        # Nested class references for Schema - allows Schema().Acl() and Schema().Entry() pattern
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
            priority: ClassVar[int] = 20

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

            def can_handle_acl(self, acl_line: str) -> bool:
                """Check if this is an OpenLDAP 1.x ACL.

                OpenLDAP 1.x ACLs start with 'access' directive.
                """
                return "access" in acl_line.lower()

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
            priority: ClassVar[int] = 20

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

            def can_handle_entry(
                self,
                entry_dn: str,
                attributes: FlextLdifTypes.Models.EntryAttributesDict,
            ) -> bool:
                """Check if this quirk should handle the entry.

                OpenLDAP 1.x entries do NOT have cn=config or olc* attributes.
                """
                is_config_dn = "cn=config" in entry_dn.lower()
                has_olc_attrs = any(attr.startswith("olc") for attr in attributes)
                return not is_config_dn and not has_olc_attrs

            def process_entry(
                self,
                entry_dn: str,
                attributes: FlextLdifTypes.Models.EntryAttributesDict,
            ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
                """Process entry for OpenLDAP 1.x format.

                OpenLDAP 1.x entries are RFC-compliant.
                """
                try:
                    processed_entry: dict[str, object] = {
                        FlextLdifConstants.DictKeys.DN: entry_dn,
                        FlextLdifConstants.DictKeys.SERVER_TYPE: "generic",
                        FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT: True,
                    }
                    processed_entry.update(attributes)
                    return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                        processed_entry
                    )
                except Exception as e:
                    return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                        f"OpenLDAP 1.x entry processing failed: {e}"
                    )

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - can_handle_acl(): Detects access directive formats
        # - parse_acl(): Parses OpenLDAP 1.x ACL definitions
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - write_acl_to_rfc(): Writes RFC-compliant ACL strings
        # - get_acl_attribute_name(): Returns "acl" (RFC baseline, inherited)

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 1.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 1.x-specific ACL formats:
        - access: OpenLDAP 1.x access control directives from slapd.conf
        - Format: access to <what> by <who> <access>

        Example:
            quirk = FlextLdifServersOpenldap1.Acl()
            if quirk.can_handle_acl(acl_line):
                result = quirk.parse_acl(acl_line)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
        priority: ClassVar[int] = 20

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check if this is an OpenLDAP 1.x ACL.

            Args:
            acl_line: ACL definition line

            Returns:
            True if this is OpenLDAP 1.x ACL format

            """
            # OpenLDAP 1.x ACLs start with "access to"
            return bool(re.match(r"^\s*access\s+to\s+", acl_line, re.IGNORECASE))

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
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
                    return FlextResult[FlextLdifModels.Acl].fail(
                        "Invalid OpenLDAP 1.x ACL format: missing 'to' clause",
                    )

                what = to_match.group(1).strip()

                # Parse "by <who> <access>" clauses
                by_pattern = re.compile(r"by\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
                by_matches = list(by_pattern.finditer(acl_content))

                # Extract first by clause for model (or use default)
                first_who = by_matches[0].group(1) if by_matches else "*"
                first_access = by_matches[0].group(2).lower() if by_matches else "none"

                # Parse target (what) - could be dn, attrs, or filter
                target_dn = ""
                target_attrs: list[str] = []

                if what.lower().startswith("dn="):
                    target_dn = what[3:].strip().strip('"')
                elif what.lower().startswith("attrs="):
                    attrs_str = what[6:].strip()
                    target_attrs = [a.strip() for a in attrs_str.split(",")]

                # Map access to permissions (read/write map to multiple flags)
                permissions = FlextLdifModels.AclPermissions(
                    read="read" in first_access or "write" in first_access,
                    write="write" in first_access,
                    add="write" in first_access,
                    delete="write" in first_access,
                    search="read" in first_access or "auth" in first_access,
                    compare="read" in first_access or "auth" in first_access,
                )

                # Build Acl model
                acl = FlextLdifModels.Acl(
                    name="access",
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="userdn",
                        subject_value=first_who,
                    ),
                    permissions=permissions,
                    server_type=FlextLdifConstants.ServerTypes.OPENLDAP1,
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OpenLDAP 1.x ACL parsing failed: {e}",
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert OpenLDAP 1.x ACL to RFC-compliant format.

            Args:
            acl_data: OpenLDAP 1.x ACL data

            Returns:
            FlextResult with RFC-compliant ACL data

            """
            try:
                # Convert server_type to generic (RFC-compliant) using model_copy()
                rfc_acl = acl_data.model_copy(update={"server_type": "generic"})
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OpenLDAP 1.x ACL→RFC conversion failed: {e}",
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL to OpenLDAP 1.x-specific format.

            Args:
            acl_data: RFC-compliant ACL data

            Returns:
            FlextResult with OpenLDAP 1.x ACL data

            """
            try:
                # Convert server_type to openldap1 using model_copy()
                openldap1_acl = acl_data.model_copy(update={"server_type": "generic"})
                return FlextResult[FlextLdifModels.Acl].ok(openldap1_acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→OpenLDAP 1.x ACL conversion failed: {e}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            OpenLDAP 1.x ACL format: access to <what> by <who> <access>

            Args:
            acl_data: Acl model

            Returns:
            FlextResult with ACL string in OpenLDAP 1.x format

            """
            try:
                # If raw_acl is available, use it
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Otherwise reconstruct from model fields
                what = acl_data.target.target_dn if acl_data.target else "*"
                who = acl_data.subject.subject_value if acl_data.subject else "*"

                # Format as OpenLDAP 1.x ACL
                acl_str = f"access to {what} by {who}"
                if acl_data.permissions:
                    # Add permissions if available
                    perms = []
                    if acl_data.permissions.read:
                        perms.append("read")
                    if acl_data.permissions.write:
                        perms.append("write")
                    if perms:
                        acl_str += f" {','.join(perms)}"

                return FlextResult[str].ok(acl_str)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP 1.x ACL write failed: {e}")

    class Entry(FlextLdifServersRfc.Entry):
        """OpenLDAP 1.x entry quirk (nested).

        Handles OpenLDAP 1.x-specific entry transformations:
        - Traditional DIT structure (no cn=config)
        - Legacy OpenLDAP attributes
        - Pre-cn=config era entries

        Example:
            quirk = FlextLdifServersOpenldap1.Entry()
            if quirk.can_handle_entry(dn, attributes):
                result = quirk.process_entry(dn, attributes)

        """

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
        priority: ClassVar[int] = 20

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - can_handle_entry(): Detects OpenLDAP 1.x entries by DN/attributes
        # - process_entry(): Normalizes OpenLDAP 1.x entries with metadata
        # - convert_entry_to_rfc(): Converts OpenLDAP 1.x entries to RFC format

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
            True if this is an OpenLDAP 1.x-specific entry

            """
            # OpenLDAP 1.x entries do NOT have cn=config or olc* attributes
            is_config_dn = "cn=config" in entry_dn.lower()
            has_olc_attrs = any(attr.startswith("olc") for attr in attributes)

            # Handle traditional entries (not config, not olc)
            return not is_config_dn and not has_olc_attrs

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Process entry for OpenLDAP 1.x format.

            Args:
            entry_dn: Entry distinguished name
            attributes: Entry attributes

            Returns:
            FlextResult with processed entry data

            """
            try:
                # OpenLDAP 1.x entries are RFC-compliant
                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: "generic",
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT: True,
                }
                processed_entry.update(attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 1.x entry processing failed: {e}",
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
                # OpenLDAP 1.x entries are already RFC-compliant
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    entry_data,
                )
            except Exception as e:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"OpenLDAP 1.x entry→RFC conversion failed: {e}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry from RFC format - pass-through for OpenLDAP 1.x.

            Args:
            entry_data: RFC-compliant entry attributes

            Returns:
            FlextResult with data (unchanged, since OpenLDAP entries are RFC-compliant)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                entry_data,
            )


__all__ = ["FlextLdifServersOpenldap1"]
