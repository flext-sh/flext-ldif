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


class FlextLdifServersOpenldap(FlextLdifServersRfc):
    """OpenLDAP 2.x Quirks - Complete Implementation."""

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 2.x quirk."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.OPENLDAP
        CANONICAL_NAME: ClassVar[str] = "openldap"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap", "openldap2"])
        PRIORITY: ClassVar[int] = 20
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap", "rfc"])

        # OpenLDAP specific operational attributes
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "structuralObjectClass",
            "contextCSN",
            "entryCSN",
        ])

        # OpenLDAP 2.x ACL format constants
        ACL_FORMAT: ClassVar[str] = "olcAccess"  # OpenLDAP cn=config ACL attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "olcAccess"  # ACL attribute name

        # OpenLDAP 2.x detection patterns (cn=config based)
        OPENLDAP_2_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "olcAccess",
            "olcAttributeTypes",
            "olcObjectClasses",
            "olcDatabase",
            "olcBackend",
            "olcOverlay",
            "olcRootDN",
            "olcRootPW",
            "olcSuffix",
        ])

        OPENLDAP_2_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=config",
            "olcDatabase=",
            "olcOverlay=",
        ])

        # OpenLDAP DN patterns
        OPENLDAP_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "cn=",
            "ou=",
            "dc=",
            "o=",
            "l=",
            "st=",
            "c=",
            "uid=",
        ])

        # OpenLDAP operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "structuralObjectClass",
            "contextCSN",
            "entryCSN",
        ])

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

        # OpenLDAP 2.x olc* attribute pattern
        OPENLDAP_OLC_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\bolc[A-Z][a-zA-Z]*\b",
        )

        # OpenLDAP cn=config DN pattern - use constant
        OPENLDAP_CONFIG_DN_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            FlextLdifConstants.DnPatterns.CN_CONFIG,
            re.IGNORECASE,
        )

        def can_handle_attribute(
            self, attribute: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Check if this is an OpenLDAP 2.x attribute.

            Args:
                attribute: Attribute definition string or model

            Returns:
                True if this contains OpenLDAP 2.x markers

            """
            # Check for olc* prefix or olcAttributeTypes context
            if isinstance(attribute, str):
                return bool(self.OPENLDAP_OLC_PATTERN.search(attribute))
            if isinstance(attribute, FlextLdifModels.SchemaAttribute):
                return bool(self.OPENLDAP_OLC_PATTERN.search(attribute.oid))
            return False

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - parse(): Delegates to RFC parser (inherited from base)
        # - write(): Writes RFC-compliant schema strings
        # - convert_attribute_to_rfc(): Strips OpenLDAP-specific metadata
        # - convert_objectclass_to_rfc(): Strips OpenLDAP-specific metadata
        # - convert_attribute_from_rfc(): Adds OpenLDAP-specific metadata
        # - convert_objectclass_from_rfc(): Adds OpenLDAP-specific metadata
        # - should_filter_out_attribute(): Returns False (accept all in OpenLDAP mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OpenLDAP mode)
        # - create_quirk_metadata(): Creates OpenLDAP-specific metadata

        def can_handle_objectclass(
            self, objectclass: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Check if this is an OpenLDAP 2.x objectClass.

            Args:
                objectclass: ObjectClass definition string or model

            Returns:
                True if this contains OpenLDAP 2.x markers

            """
            if isinstance(objectclass, str):
                return bool(self.OPENLDAP_OLC_PATTERN.search(objectclass))
            if isinstance(objectclass, FlextLdifModels.SchemaObjectClass):
                return bool(self.OPENLDAP_OLC_PATTERN.search(objectclass.oid))
            return False

        def write(
            self,
            model: FlextLdifModels.SchemaAttribute | FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[str]:
            """Write schema model to RFC-compliant string format.

            Args:
                model: SchemaAttribute or SchemaObjectClass model

            Returns:
                FlextResult with RFC-compliant schema string

            """
            try:
                # Check for original_format in metadata (round-trip preservation)
                if model.metadata and model.metadata.original_format:
                    return FlextResult[str].ok(model.metadata.original_format)

                # Handle SchemaAttribute
                if isinstance(model, FlextLdifModels.SchemaAttribute):
                    # Access model fields (NO .get())
                    oid = model.oid
                    name = model.name
                    desc = model.desc
                    syntax = model.syntax
                    equality = model.equality
                    single_value = model.single_value or False

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

                # Handle SchemaObjectClass
                if isinstance(model, FlextLdifModels.SchemaObjectClass):
                    # Access model fields (NO .get())
                    oid = model.oid
                    name = model.name
                    desc = model.desc
                    sup = model.sup
                    kind = model.kind or FlextLdifConstants.Schema.STRUCTURAL
                    must = model.must or []
                    may = model.may or []

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

                return FlextResult[str].fail(
                    f"Unknown schema model type: {type(model).__name__}"
                )

            except Exception as e:
                return FlextResult[str].fail(
                    f"OpenLDAP 2.x schema write failed: {e}",
                )

    class Acl(FlextLdifServersRfc.Acl):
        """OpenLDAP 2.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 2.x-specific ACL formats:
        - olcAccess: OpenLDAP 2.x access control directives
        - Format: to <what> by <who> <access>

        Example:
            quirk = FlextLdifServersOpenldap.Acl()
            if quirk._can_handle(acl_line):
                result = quirk.parse(acl_line)

        """

        # OVERRIDE: OpenLDAP 2.x uses "olcAccess" for ACL attribute names
        acl_attribute_name = "olcAccess"

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize OpenLDAP 2.x ACL quirk with RFC format.

            Args:
                server_type: Optional server type (inherited from parent)
                priority: Optional priority (inherited from parent)

            """
            super().__init__(server_type=server_type, priority=priority)

        def _can_handle(self, acl: FlextLdifModels.Acl) -> bool:
            """Check if this is an OpenLDAP 2.x ACL.

            Args:
                acl: The ACL model to check.

            Returns:
                True if this is OpenLDAP 2.x ACL format

            """
            if not isinstance(acl, FlextLdifModels.Acl) or not acl.raw_acl:
                return False
            # OpenLDAP 2.x ACLs start with "to" or "{n}to"
            return bool(
                re.match(r"^(\{\d+\})?\s*to\s+", acl.raw_acl, re.IGNORECASE),
            ) or acl.raw_acl.startswith(f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:")

        def parse(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
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
                if acl_line.startswith(f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:"):
                    acl_content = acl_line[len(FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME + ":") :].strip()

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

                # Extract attributes from "what" clause if present
                # OpenLDAP ACLs can specify: "to attrs=attr1,attr2 by ..."
                attributes: list[str] = []
                attrs_match = re.search(
                    r"attrs?\s*=\s*([^,\s]+(?:\s*,\s*[^,\s]+)*)",
                    what,
                    re.IGNORECASE,
                )
                if attrs_match:
                    attr_string = attrs_match.group(1)
                    attributes = [attr.strip() for attr in attr_string.split(",")]

                # Parse "by <who> <access>" clauses - extract first by clause for model
                by_pattern = re.compile(r"by\s+([^\s]+)\s+([^\s]+)", re.IGNORECASE)
                by_matches = list(by_pattern.finditer(acl_content))

                # Extract subject from first by clause
                subject_value = (
                    by_matches[0].group(1)
                    if by_matches
                    else FlextLdifConstants.AclSubjectTypes.ANONYMOUS
                )

                # Extract access permissions from first by clause
                access = by_matches[0].group(2) if by_matches else "none"

                # Build Acl model
                acl = FlextLdifModels.Acl(
                    name="access",
                    target=FlextLdifModels.AclTarget(
                        target_dn=what,  # OpenLDAP: "what" is target
                        attributes=attributes,  # OpenLDAP: extracted from what clause
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="who",
                        subject_value=subject_value,
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read=FlextLdifConstants.PermissionNames.READ in access,
                        write=FlextLdifConstants.PermissionNames.WRITE in access,
                        add=FlextLdifConstants.PermissionNames.WRITE
                        in access,  # OpenLDAP: write includes add
                        delete=FlextLdifConstants.PermissionNames.WRITE
                        in access,  # OpenLDAP: write includes delete
                        search=FlextLdifConstants.PermissionNames.READ
                        in access,  # OpenLDAP: read includes search
                        compare=FlextLdifConstants.PermissionNames.READ
                        in access,  # OpenLDAP: read includes compare
                    ),
                    server_type="openldap",
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as e:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"OpenLDAP 2.x ACL parsing failed: {e}",
                )

        def _write_acl(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format (internal).

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
                        perms.append(FlextLdifConstants.PermissionNames.READ)
                    if acl_data.permissions.write:
                        perms.append(FlextLdifConstants.PermissionNames.WRITE)
                    if perms:
                        acl_parts.append(",".join(perms))

                acl_str = " ".join(acl_parts)
                return FlextResult[str].ok(acl_str)

            except Exception as e:
                return FlextResult[str].fail(f"OpenLDAP 2.x ACL write failed: {e}")

    def get_acl_attribute_name(self) -> str:
        """Get OpenLDAP-specific ACL attribute name.

        OpenLDAP 2.x uses 'olcAccess' for ACL configuration in cn=config.

        Returns:
            'olcAccess' - OpenLDAP-specific ACL attribute name

        """
        return "olcAccess"

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

        def __init__(
            self,
            server_type: str | None = None,
            priority: int | None = None,
        ) -> None:
            """Initialize OpenLDAP 2.x entry quirk with RFC format.

            Args:
                server_type: Optional server type (inherited from parent)
                priority: Optional priority (inherited from parent)

            """
            super().__init__(server_type=server_type, priority=priority)

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - can_handle_entry(): Detects OpenLDAP 2.x entries by DN/attributes
        # - process_entry(): Normalizes OpenLDAP 2.x entries with metadata
        # - convert_entry_to_rfc(): Converts OpenLDAP 2.x entries to RFC format

        def can_handle_entry(self, entry: FlextLdifModels.Entry) -> bool:
            """Check if this quirk should handle the entry.

            Args:
                entry: The entry model to check.

            Returns:
                True if this is an OpenLDAP 2.x-specific entry

            """
            if not isinstance(entry, FlextLdifModels.Entry):
                return False

            attributes = entry.attributes.attributes
            entry_dn = entry.dn.value

            if not entry_dn:
                return False

            # Check for cn=config DN or olc* attributes
            is_config_dn = (
                FlextLdifConstants.DnPatterns.CN_CONFIG.lower() in entry_dn.lower()
            )

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


__all__ = ["FlextLdifServersOpenldap"]
