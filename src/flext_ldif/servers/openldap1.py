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
from typing import ClassVar, cast

from flext_core import FlextResult

from flext_ldif._models.metadata import FlextLdifModelsMetadata
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.protocols import p
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t


class FlextLdifServersOpenldap1(FlextLdifServersRfc):
    """OpenLDAP 1.x Legacy Quirks - Complete Implementation."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 1.x quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "openldap1"
        PRIORITY: ClassVar[int] = 10

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        CANONICAL_NAME: ClassVar[str] = "openldap1"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap1"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap1", "rfc"])

        # OpenLDAP 1.x ACL format constants
        ACL_FORMAT: ClassVar[str] = "access"  # OpenLDAP 1.x slapd.conf ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "access"  # ACL attribute name

        # NOTE: OpenLDAP 1.x inherits RFC baseline for:
        # - OPERATIONAL_ATTRIBUTES, PRESERVE_ON_MIGRATION, ATTRIBUTE_ALIASES,
        #   ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS

        # === OpenLDAP1-SPECIFIC PERMISSIONS ===
        # OpenLDAP 1.x extends RFC permissions with "auth"
        ACL_PERMISSION_AUTH: ClassVar[str] = "auth"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset([ACL_PERMISSION_AUTH])
        )

        # OpenLDAP 1.x detection patterns (traditional slapd.conf)
        OPENLDAP_1_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                c.Ldif.DictKeys.OBJECTCLASS.lower(),
                "access",
                "rootdn",
                "rootpw",
                "suffix",
            ],
        )

        # OpenLDAP 1.x detection constants
        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.4203\."
        OBJECTCLASS_KEYWORD: ClassVar[str] = "objectclass"
        DETECTION_PATTERN: ClassVar[str] = r"\b(attributetype|objectclass|access)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                "objectclass",
                "access",
                "rootdn",
                "rootpw",
                "suffix",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "attributetype",
                "objectclass",
                "access",
                "rootdn",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "domain",
                "organizationalunit",
                "person",
                "groupofnames",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "dc=",
                "ou=",
            ],
        )

        # ACL parsing constants (migrated from _parse_acl method)
        ACL_TARGET_DN_PREFIX: ClassVar[str] = "dn="
        ACL_TARGET_ATTRS_PREFIX: ClassVar[str] = "attrs="

        # Schema-specific constants (migrated from nested Schema class)
        SCHEMA_OPENLDAP1_ATTRIBUTE_PATTERN: ClassVar[str] = r"^\s*attributetype\s+"
        SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN: ClassVar[str] = r"^\s*objectclass\s+"

        # ACL-specific constants (migrated from nested Acl class)
        ACL_BY_PATTERN: ClassVar[str] = r"by\s+([^\s]+)\s+([^\s]+)"
        ACL_ACCESS_TO_PATTERN: ClassVar[str] = r"^\s*access\s+to\s+"

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_TO_BY_PATTERN: ClassVar[str] = r"^to\s+(.+?)\s+by\s+"
        ACL_SUBJECT_TYPE_USERDN: ClassVar[str] = "userdn"

        # ACL target parsing constants (migrated from _parse_acl method)
        ACL_OPS_SEPARATOR: ClassVar[str] = ","

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.Ldif.AclPermission,
        # c.Ldif.AclAction, and c.Ldif.Encoding directly

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

    class Schema(FlextLdifServersRfc.Schema):
        """OpenLDAP 1.x schema quirk.

        Extends RFC 4512 schema parsing with OpenLDAP 1.x-specific features:
        - Traditional attributetype format from slapd.conf
        - Traditional objectclass format from slapd.conf
        - No olc* prefixes (pre-cn=config era)
        - Legacy OpenLDAP directives

        Example:
            quirk = FlextLdifServersOpenldap1()
            if quirk.schema.can_handle_attribute(attr_def):
                result = quirk.schema._parse_attribute(attr_def)

        """

        # Use patterns from Constants

        def can_handle_attribute(
            self,
            attr_definition: str | p.Ldif.SchemaAttributeProtocol,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x attribute.

            Args:
                attr_definition: Attribute definition string or SchemaAttribute model

            Returns:
                True if this contains OpenLDAP 1.x markers

            """
            # For string input, check if it starts with "attributetype"
            # and doesn't have "olc"
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
            has_olc = (
                "olc" in attr_definition.oid.lower() if attr_definition.oid else False
            )
            if not has_olc and attr_definition.name:
                has_olc = "olc" in attr_definition.name.lower()
            return not has_olc  # OpenLDAP 1.x should not have olc* in OID or name

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - _parse_attribute(): Custom parsing logic for slapd.conf format
        # - _parse_objectclass(): Custom parsing logic for slapd.conf format
        # - _write_attribute(): Uses RFC writer for attributeType format
        # - _write_objectclass(): Uses RFC writer for objectClass format
        # - create_metadata(): Creates OpenLDAP 1.x-specific metadata

        def can_handle_objectclass(
            self,
            oc_definition: str | p.Ldif.SchemaObjectClassProtocol,
        ) -> bool:
            """Check if this is an OpenLDAP 1.x objectClass.

            Args:
                oc_definition: ObjectClass definition string or SchemaObjectClass model

            Returns:
                True if this contains OpenLDAP 1.x markers

            """
            # For string input, check if it starts with objectClass keyword
            # and doesn't have "olc"
            if isinstance(oc_definition, str):
                # Must start with objectClass pattern (from Constants.OBJECTCLASS_KEYWORD)
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
        ) -> FlextResult[p.Ldif.SchemaAttributeProtocol]:
            """Parse attribute definition, strip OpenLDAP1 prefix, and add metadata.

            Args:
                attr_definition: Attribute definition string
                    (with "attributetype" prefix)

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
                metadata = m.Ldif.QuirkMetadata.create_for("openldap1")
                return FlextResult[p.Ldif.SchemaAttributeProtocol].ok(
                    attr_data.model_copy(
                        update=cast("dict[str, object]", {"metadata": metadata}),
                    ),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[p.Ldif.SchemaObjectClassProtocol]:
            """Parse objectClass definition and add OpenLDAP1 metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with OpenLDAP1 metadata

            """
            # Strip OpenLDAP1 objectClass prefix before RFC parsing
            stripped = re.sub(
                FlextLdifServersOpenldap1.Constants.SCHEMA_OPENLDAP1_OBJECTCLASS_PATTERN,
                "",
                oc_definition,
            ).strip()
            result = super()._parse_objectclass(stripped)
            if result.is_success:
                oc_data = result.unwrap()
                metadata = m.Ldif.QuirkMetadata.create_for("openldap1")
                return FlextResult[p.Ldif.SchemaObjectClassProtocol].ok(
                    oc_data.model_copy(
                        update=cast("dict[str, object]", {"metadata": metadata}),
                    ),
                )
            return result

        def _write_attribute(
            self,
            attr_data: p.Ldif.SchemaAttributeProtocol,
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
            oc_data: p.Ldif.SchemaObjectClassProtocol,
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
                # NO FALLBACKS - explicit checks
                kind: str
                kind = oc_data.kind or "STRUCTURAL"
                must: list[str]
                must = oc_data.must if oc_data.must is not None else []
                may: list[str]
                may = oc_data.may if oc_data.may is not None else []

                # Build objectClass string (objectclass prefix for OpenLDAP 1.x)
                oc_str = f"objectclass ( {oid}"
                if name:
                    oc_str += f" NAME '{name}'"
                if desc:
                    oc_str += f" DESC '{desc}'"
                if sup:
                    oc_str += f" SUP {sup}"
                oc_str += f" {kind}"
                if must and isinstance(must, (list, tuple)):
                    if not isinstance(must, list):
                        msg = f"Expected list, got {type(must)}"
                        raise TypeError(msg)
                    must_list_str: list[str] = [str(item) for item in must]
                    must_attrs = " $ ".join(must_list_str)
                    oc_str += f" MUST ( {must_attrs} )"
                if may and isinstance(may, (list, tuple)):
                    if not isinstance(may, list):
                        msg = f"Expected list, got {type(may)}"
                        raise TypeError(msg)
                    may_list_str: list[str] = [str(item) for item in may]
                    may_attrs = " $ ".join(may_list_str)
                    oc_str += f" MAY ( {may_attrs} )"
                oc_str += " )"

                return FlextResult[str].ok(oc_str)

            except Exception as e:
                return FlextResult[str].fail(
                    f"OpenLDAP 1.x objectClass write failed: {e}",
                )

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Acl)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - can_handle_acl(): Detects access directive formats
        # - _parse_acl(): Parses OpenLDAP 1.x ACL definitions
        # - _write_acl(): Writes RFC-compliant ACL strings

    class Acl(FlextLdifServersRfcAcl):
        """OpenLDAP 1.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 1.x-specific ACL formats:
        - access: OpenLDAP 1.x access control directives from slapd.conf
        - Format: access to <what> by <who> <access>

        Example:
            quirk = FlextLdifServersOpenldap1.Acl()
            if quirk.can_handle(acl_line):
                result = quirk._parse_acl(acl_line)

        """

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is an OpenLDAP 1.x ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is OpenLDAP 1.x ACL format

            """
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            # acl_line is AclProtocol (object)
            # Check if it's a m.Ldif.Acl instance
            if isinstance(acl_line, m.Ldif.Acl):
                return self.can_handle_acl(acl_line)
            # For other AclProtocol implementations, extract raw_acl string if available
            if isinstance(acl_line, object):
                raw_acl = getattr(acl_line, "raw_acl", None)
                if isinstance(raw_acl, str):
                    return self.can_handle_acl(raw_acl)
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
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
                    ),
                )
            if not isinstance(acl_line, m.Ldif.Acl) or not acl_line.raw_acl:
                return False
            # OpenLDAP 1.x ACLs start with "access to"
            return bool(
                re.match(
                    FlextLdifServersOpenldap1.Constants.ACL_ACCESS_TO_PATTERN,
                    acl_line.raw_acl,
                    re.IGNORECASE,
                ),
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
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
                    FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                ):
                    acl_content = acl_line[
                        len(FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME) :
                    ].strip()

                # Parse "to <what>" clause
                to_match = re.match(
                    FlextLdifServersOpenldap1.Constants.ACL_TO_BY_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                )
                if not to_match:
                    return FlextResult[m.Ldif.Acl].fail(
                        "Invalid OpenLDAP 1.x ACL format: missing 'to' clause",
                    )

                what = to_match.group(1).strip()

                # Parse "by <who> <access>" clauses
                by_matches = list(
                    re.finditer(
                        FlextLdifServersOpenldap1.Constants.ACL_BY_PATTERN,
                        acl_content,
                        re.IGNORECASE,
                    ),
                )

                # Extract first by clause for model (or use default)
                first_who = by_matches[0].group(1) if by_matches else "*"
                first_access = by_matches[0].group(2).lower() if by_matches else "none"

                # Parse target (what) - could be dn, attrs, or filter
                target_dn = ""
                target_attrs: list[str] = []

                dn_prefix = FlextLdifServersOpenldap1.Constants.ACL_TARGET_DN_PREFIX
                attrs_prefix = (
                    FlextLdifServersOpenldap1.Constants.ACL_TARGET_ATTRS_PREFIX
                )
                if what.lower().startswith(dn_prefix):
                    target_dn = what[len(dn_prefix) :].strip().strip('"')
                elif what.lower().startswith(attrs_prefix):
                    attrs_str = what[len(attrs_prefix) :].strip()
                    target_attrs = [
                        a.strip()
                        for a in attrs_str.split(
                            FlextLdifServersOpenldap1.Constants.ACL_OPS_SEPARATOR,
                        )
                    ]

                # Map access to permissions (read/write map to multiple flags)
                read_perm = FlextLdifServersRfc.Constants.PERMISSION_READ
                write_perm = FlextLdifServersRfc.Constants.PERMISSION_WRITE
                auth_perm = FlextLdifServersOpenldap1.Constants.ACL_PERMISSION_AUTH
                permissions = m.Ldif.AclPermissions(
                    read=read_perm in first_access or write_perm in first_access,
                    write=write_perm in first_access,
                    add=write_perm in first_access,
                    delete=write_perm in first_access,
                    search=read_perm in first_access or auth_perm in first_access,
                    compare=read_perm in first_access or auth_perm in first_access,
                )

                # Map who clause to subject_type
                # OpenLDAP 1.x uses "self", "*", "anonymous", etc. as who values
                first_who_lower = first_who.lower().strip()
                subject_type: c.Ldif.LiteralTypes.AclSubjectTypeLiteral
                if first_who_lower == "self":
                    subject_type = "self"
                elif first_who_lower in {"*", "all"}:
                    subject_type = "all"
                elif first_who_lower == "anonymous":
                    subject_type = "anonymous"
                elif first_who_lower == "authenticated":
                    subject_type = "authenticated"
                else:
                    # Default to userdn for DN-based subjects
                    subject_type = "userdn"

                # Build Acl model
                # Note: ACL_ATTRIBUTE_NAME is OpenLDAP 1.x format from Constants
                acl_extensions_dict: dict[str, object] = {
                    "original_format": acl_line,
                }
                acl = m.Ldif.Acl(
                    name=FlextLdifServersOpenldap1.Constants.ACL_ATTRIBUTE_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=target_dn,
                        attributes=target_attrs,
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type=subject_type,
                        subject_value=first_who,
                    ),
                    permissions=permissions,
                    metadata=m.Ldif.QuirkMetadata.create_for(
                        quirk_type=self._get_server_type(),
                        extensions=FlextLdifModelsMetadata.DynamicMetadata(
                            **acl_extensions_dict
                        ),
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[m.Ldif.Acl].ok(acl)

            except Exception as e:
                return FlextResult[m.Ldif.Acl].fail(
                    f"OpenLDAP 1.x ACL parsing failed: {e}",
                )

        def _write_acl(self, acl_data: m.Ldif.Acl) -> FlextResult[str]:
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
                        perms.append(
                            FlextLdifServersOpenldap1.Constants.PERMISSION_READ,
                        )
                    if acl_data.permissions.write:
                        perms.append(
                            FlextLdifServersOpenldap1.Constants.PERMISSION_WRITE,
                        )
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
            if quirk.can_handle(dn, attributes):
                result = quirk.process_entry(entry)

        """

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with OpenLDAP 1.x-specific logic:
        # - can_handle(): Detects OpenLDAP 1.x entries by DN/attributes
        # - _parse_entry(): Normalizes OpenLDAP 1.x entries with metadata

        def can_handle(
            self,
            entry_dn: str,
            attributes: t.Ldif.CommonDict.AttributeDictGeneric,
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
            config_marker = "cn=config"  # OpenLDAP 2.x marker, not used in 1.x
            is_config_dn = config_marker in entry_dn.lower()
            # OpenLDAP 1.x does not use olc* attributes (that's OpenLDAP 2.x)
            # Check for olc* attributes in the attributes dict
            has_olc_attrs = any(
                attr_name.lower().startswith("olc") for attr_name in attributes
            )

            # Handle traditional entries (not config, not olc)
            return not is_config_dn and not has_olc_attrs

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> FlextResult[m.Ldif.Entry]:
            """Process entry for OpenLDAP 1.x format.

            Args:
                entry: The entry model to process.

            Returns:
                FlextResult with processed entry data

            """
            try:
                # OpenLDAP 1.x entries are RFC-compliant
                metadata = entry.metadata or m.Ldif.QuirkMetadata(
                    quirk_type=FlextLdifServersOpenldap1.Constants.SERVER_TYPE,
                )
                metadata.extensions[c.QuirkMetadataKeys.IS_TRADITIONAL_DIT] = True

                processed_entry = m.Ldif.Entry(
                    dn=entry.dn,
                    attributes=entry.attributes,
                    metadata=metadata,
                )

                return FlextResult[m.Ldif.Entry].ok(
                    processed_entry,
                )

            except Exception as e:
                return FlextResult[m.Ldif.Entry].fail(
                    f"OpenLDAP 1.x entry processing failed: {e}",
                )
