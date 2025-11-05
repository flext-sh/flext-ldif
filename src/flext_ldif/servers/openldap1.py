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
from collections.abc import Mapping
from typing import ClassVar, Final, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOpenldap1(FlextLdifServersRfc):
    """OpenLDAP 1.x Legacy Quirks - Complete Implementation."""

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 1.x quirk."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP1
        CANONICAL_NAME: ClassVar[str] = "openldap1"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        PRIORITY: ClassVar[int] = 20
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap1", "rfc"])

        # OpenLDAP 1.x ACL format constants
        ACL_FORMAT: ClassVar[str] = "access"  # OpenLDAP 1.x slapd.conf ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "access"  # ACL attribute name

        # OpenLDAP 1.x detection patterns (traditional slapd.conf)
        OPENLDAP_1_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "attributetype",
            "objectclass",
            "access",
            "rootdn",
            "rootpw",
            "suffix",
        ])

        # OpenLDAP 1.x detection constants (migrated from FlextLdifConstants.LdapServerDetection)
        DETECTION_OID_PATTERN: Final[str] = r"1\.3\.6\.1\.4\.1\.4203\."
        DETECTION_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "attributetype",
            "objectclass",
            "access",
            "rootdn",
        ])
        DETECTION_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "top",
            "domain",
            "organizationalunit",
            "person",
            "groupofnames",
        ])
        DETECTION_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "dc=",
            "ou=",
        ])

        # Schema-specific constants (migrated from nested Schema class)
        SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN: Final[str] = r"^\s*attributetype\s+"
        SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN: Final[str] = r"^\s*objectclass\s+"

        # ACL-specific constants (migrated from nested Acl class)
        ACL_BY_PATTERN: Final[str] = r"by\s+([^\s]+)\s+([^\s]+)"
        ACL_ACCESS_TO_PATTERN: Final[str] = r"^\s*access\s+to\s+"

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize OpenLDAP 1.x quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Nested classes no longer require server_type and priority parameters
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 1.x schema quirk.

        Extends RFC 4512 schema parsing with OpenLDAP 1.x-specific features:
        - Traditional attributetype format from slapd.conf
        - Traditional objectclass format from slapd.conf
        - No olc* prefixes (pre-cn=config era)
        - Legacy OpenLDAP directives

        Example:
            quirk = FlextLdifServersOpenldap1()
            if quirk.schema._can_handle_attribute(attr_def):
                result = quirk.schema._parse_attribute(attr_def)

        """

        # Use patterns from Constants

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this is an OpenLDAP 1.x attribute.

            Args:
                attr_definition: Attribute definition string or SchemaAttribute model

            Returns:
                True if this contains OpenLDAP 1.x markers

            """
            # For string input, check if it starts with "attributetype" and doesn't have "olc"
            if isinstance(attr_definition, str):
                # Must start with "attributetype" pattern
                if not re.match(
                    FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                ):
                    return False
                # OpenLDAP 1.x does not use olc* prefix (that's OpenLDAP 2.x)
                # Check for "olc" in the attribute name (NAME 'olc...')
                has_olc = "olc" in attr_definition.lower()
                return not has_olc  # OpenLDAP 1.x should not have olc* prefix
            # For model input, check OID or other markers
            # OpenLDAP 1.x does not use olc* prefix (that's OpenLDAP 2.x)
            has_olc = "olc" in attr_definition.oid.lower() if attr_definition.oid else False
            if not has_olc and attr_definition.name:
                has_olc = "olc" in attr_definition.name.lower()
            return not has_olc  # OpenLDAP 1.x should not have olc* in OID or name

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - _parse_attribute(): Custom parsing logic for slapd.conf format
        # - _parse_objectclass(): Custom parsing logic for slapd.conf format
        # - convert_attribute_from_rfc(): Adds OpenLDAP 1.x-specific metadata
        # - convert_objectclass_from_rfc(): Adds OpenLDAP 1.x-specific metadata
        # - _write_attribute(): Uses RFC writer for attributeType format
        # - _write_objectclass(): Uses RFC writer for objectClass format
        # - create_quirk_metadata(): Creates OpenLDAP 1.x-specific metadata

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this is an OpenLDAP 1.x objectClass.

            Args:
                oc_definition: ObjectClass definition string or SchemaObjectClass model

            Returns:
                True if this contains OpenLDAP 1.x markers

            """
            # For string input, check if it starts with "objectclass" and doesn't have "olc"
            if isinstance(oc_definition, str):
                # Must start with "objectclass" pattern
                if not re.match(
                    FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN,
                    oc_definition,
                    re.IGNORECASE,
                ):
                    return False
                # OpenLDAP 1.x does not use olc* prefix (that's OpenLDAP 2.x)
                # Check for "olc" in the objectClass name (NAME 'olc...')
                has_olc = "olc" in oc_definition.lower()
                return not has_olc  # OpenLDAP 1.x should not have olc* prefix
            # For model input, check OID or other markers
            has_olc = "olc" in oc_definition.oid.lower() if oc_definition.oid else False
            if not has_olc and oc_definition.name:
                has_olc = "olc" in oc_definition.name.lower()
            return not has_olc  # OpenLDAP 1.x should not have olc* in OID or name

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition, strip OpenLDAP1 prefix, and add metadata.

            Args:
                attr_definition: Attribute definition string (with "attributetype" prefix)

            Returns:
                FlextResult with SchemaAttribute marked with OpenLDAP1 metadata

            """
            # Strip "attributetype" prefix for RFC parser
            stripped = re.sub(
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN,
                "",
                attr_definition,
                flags=re.IGNORECASE,
            ).strip()

            result = super()._parse_attribute(stripped)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("openldap1")
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add OpenLDAP1 metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with OpenLDAP1 metadata

            """
            # Strip OpenLDAP1 "objectclass" prefix before RFC parsing
            stripped = re.sub(
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN,
                "",
                oc_definition,
            ).strip()
            result = super()._parse_objectclass(stripped)
            if result.is_success:
                oc_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("openldap1")
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to OpenLDAP1 format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with OpenLDAP1 metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("openldap1")
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to OpenLDAP1 format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with OpenLDAP1 metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("openldap1")
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(result_data)

        def _write_attribute(
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

        def _write_objectclass(
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

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - _can_handle_acl(): Detects access directive formats
        # - _parse_acl(): Parses OpenLDAP 1.x ACL definitions
        # - convert_acl_to_rfc(): Converts to RFC format
        # - convert_acl_from_rfc(): Converts from RFC format
        # - _write_acl(): Writes RFC-compliant ACL strings
        # - get_acl_attribute_name(): Returns "acl" (RFC baseline, inherited)

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 1.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 1.x-specific ACL formats:
        - access: OpenLDAP 1.x access control directives from slapd.conf
        - Format: access to <what> by <who> <access>

        Example:
            quirk = FlextLdifServersOpenldap1.Acl()
            if quirk._can_handle_acl(acl_line):
                result = quirk._parse_acl(acl_line)

        """

        def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an OpenLDAP 1.x ACL.

            Args:
                acl_line: ACL definition string or Acl model

            Returns:
                True if this is OpenLDAP 1.x ACL format

            """
            if isinstance(acl_line, str):
                # OpenLDAP 1.x ACLs start with "access to"
                return bool(
                    re.match(
                        FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_PATTERN,
                        acl_line,
                        re.IGNORECASE,
                    )
                )
            if not isinstance(acl_line, FlextLdifModels.Acl) or not acl_line.raw_acl:
                return False
            # OpenLDAP 1.x ACLs start with "access to"
            return bool(
                re.match(
                    FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_PATTERN,
                    acl_line.raw_acl,
                    re.IGNORECASE,
                )
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse OpenLDAP 1.x ACL definition.

            Format: access to <what> by <who> <access>
            Example: access to attrs=userPassword by self write by * auth

            Args:
            acl_line: ACL definition line

            Returns:
            FlextResult with parsed OpenLDAP 1.x ACL data

            """
            try:
                # Remove FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME prefix
                acl_content = acl_line
                if acl_line.lower().startswith(
                    FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME
                ):
                    acl_content = acl_line[
                        len(FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME) :
                    ].strip()

                # Parse "to <what>" clause
                to_match = re.match(r"^to\s+(.+?)\s+by\s+", acl_content, re.IGNORECASE)
                if not to_match:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        "Invalid OpenLDAP 1.x ACL format: missing 'to' clause",
                    )

                what = to_match.group(1).strip()

                # Parse "by <who> <access>" clauses
                by_matches = list(re.finditer(
                    FlextLdifServersOpenldap1.Constants.ACL_BY_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                ))

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
                # Note: ACL_ATTRIBUTE_NAME is OpenLDAP 1.x format from Constants
                acl = FlextLdifModels.Acl(
                    name=FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="userdn",
                        subject_value=first_who,
                    ),
                    permissions=permissions,
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        FlextLdifServersOpenldap1.Constants.SERVER_TYPE,
                    ),
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
                # Convert server_type to RFC (generic) format
                # Note: server_type is now derived from Constants, not stored in model
                rfc_acl = acl_data.model_copy()
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

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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
                    # Use constants for permission names
                    if acl_data.permissions.read:
                        perms.append(FlextLdifConstants.PermissionNames.READ)
                    if acl_data.permissions.write:
                        perms.append(FlextLdifConstants.PermissionNames.WRITE)
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
            if quirk._can_handle_entry(dn, attributes):
                result = quirk.process_entry(entry)

        """

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - _can_handle_entry(): Detects OpenLDAP 1.x entries by DN/attributes
        # - process_entry(): Normalizes OpenLDAP 1.x entries with metadata
        # - convert_entry_to_rfc(): Converts OpenLDAP 1.x entries to RFC format

        def _can_handle_entry(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry_dn: Entry distinguished name (raw string from LDIF)
                attributes: Entry attributes mapping (raw from LDIF parser)

            Returns:
                True if this is an OpenLDAP 1.x-specific entry

            """
            if not entry_dn:
                return False

            # OpenLDAP 1.x entries do NOT have cn=config or olc* attributes
            # Note: cn=config is OpenLDAP 2.x specific, not used in OpenLDAP 1.x
            # Check against OpenLDAP 2.x markers (which OpenLDAP 1.x should NOT match)
            is_config_dn = "cn=config" in entry_dn.lower()  # OpenLDAP 2.x marker, not used in 1.x
            # OpenLDAP 1.x does not use olc* attributes (that's OpenLDAP 2.x)
            # Check for olc* attributes in the attributes dict
            has_olc_attrs = any(
                attr_name.lower().startswith("olc") for attr_name in attributes.keys()
            )

            # Handle traditional entries (not config, not olc)
            return not is_config_dn and not has_olc_attrs

        def process_entry(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Process entry for OpenLDAP 1.x format.

            Args:
                entry: The entry model to process.

            Returns:
                FlextResult with processed entry data

            """
            try:
                # OpenLDAP 1.x entries are RFC-compliant
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata()
                metadata.extensions[
                    FlextLdifConstants.QuirkMetadataKeys.IS_TRADITIONAL_DIT
                ] = True

                processed_entry = FlextLdifModels.Entry(
                    dn=entry.dn,
                    attributes=entry.attributes,
                    metadata=metadata,
                )

                return FlextResult[FlextLdifModels.Entry].ok(
                    processed_entry,
                )

            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"OpenLDAP 1.x entry processing failed: {e}",
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert server-specific entry to RFC-compliant format.

            Args:
                entry_data: Server-specific entry data

            Returns:
                FlextResult with RFC-compliant entry data

            """
            try:
                # OpenLDAP 1.x entries are already RFC-compliant
                return FlextResult[FlextLdifModels.Entry].ok(
                    entry_data,
                )
            except Exception as e:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"OpenLDAP 1.x entry→RFC conversion failed: {e}",
                )

        def convert_entry_from_rfc(
            self, entry_data: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert entry from RFC format - pass-through for OpenLDAP 1.x.

            Args:
                entry_data: RFC-compliant entry attributes

            Returns:
                FlextResult with data (unchanged, since OpenLDAP entries are RFC-compliant)

            """
            return FlextResult[FlextLdifModels.Entry].ok(
                entry_data,
            )


__all__ = ["FlextLdifServersOpenldap1"]
