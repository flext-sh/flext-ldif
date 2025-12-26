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

import json
import re
from collections.abc import Mapping
from typing import ClassVar

from flext_core import FlextLogger, FlextResult

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._rfc import FlextLdifServersRfcAcl
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t

logger = FlextLogger(__name__)


class FlextLdifServersOpenldap(FlextLdifServersRfc):
    """OpenLDAP 2.x Quirks - Complete Implementation."""

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for OpenLDAP 2.x quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "openldap2"
        PRIORITY: ClassVar[int] = 20

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        CANONICAL_NAME: ClassVar[str] = "openldap"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["openldap", "openldap2"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["openldap"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["openldap", "rfc"])

        # OpenLDAP 2.x ACL format constants
        ACL_FORMAT: ClassVar[str] = "olcAccess"  # OpenLDAP cn=config ACL attribute
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "olcAccess"  # ACL attribute name

        # Server detection patterns and weights
        DETECTION_PATTERN: ClassVar[str] = r"\b(olc[A-Z][a-zA-Z]+|cn=config)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcDatabase",
                "olcAccess",
                "olcOverlay",
                "olcModule",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 8

        # OpenLDAP 2.x detection patterns (cn=config based)
        OPENLDAP_2_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcAccess",
                "olcAttributeTypes",
                "olcObjectClasses",
                "olcDatabase",
                "olcBackend",
                "olcOverlay",
                "olcRootDN",
                "olcRootPW",
                "olcSuffix",
            ],
        )

        OPENLDAP_2_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=config",
                "olcDatabase=",
                "olcOverlay=",
            ],
        )

        # OpenLDAP DN patterns
        OPENLDAP_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=",
                "ou=",
                "dc=",
                "o=",
                "l=",
                "st=",
                "c=",
                "uid=",
            ],
        )

        # OpenLDAP DN prefix constants
        OLCDATABASE_PREFIX: ClassVar[str] = "olcDatabase="
        OLCOVERLAY_PREFIX: ClassVar[str] = "olcOverlay="

        # NOTE: Permission names inherited from RFC.Constants

        # ACL subject types specific to OpenLDAP
        ACL_SUBJECT_ANONYMOUS: ClassVar[str] = "*"
        ACL_SUBJECT_TYPE_DN: ClassVar[str] = "dn"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"

        # OpenLDAP 2.x object classes (cn=config based)
        OPENLDAP_2_OBJECTCLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcDatabaseConfig",
                "olcBackendConfig",
                "olcOverlayConfig",
                "olcSchemaConfig",
            ],
        )

        # OpenLDAP 2.x extends RFC operational attributes
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.OPERATIONAL_ATTRIBUTES
            | frozenset(["entryUUID", "entryCSN", "contextCSN", "hasSubordinates"])
        )

        # OpenLDAP extends RFC permissions with "auth"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS | frozenset(["auth"])
        )

        # NOTE: OpenLDAP inherits RFC baseline for:
        # - PRESERVE_ON_MIGRATION (createTimestamp, modifyTimestamp)
        # - ATTRIBUTE_ALIASES (empty)

        # Schema attribute fields specific to OpenLDAP
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin", "ordering"])

        # ObjectClass requirements (extends RFC - allows multiple SUP)
        OBJECTCLASS_REQUIREMENTS: ClassVar[Mapping[str, bool]] = {
            "requires_sup_for_auxiliary": True,
            "allows_multiple_sup": True,  # OpenLDAP allows multiple SUP
            "requires_explicit_structural": False,
        }

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.3\.6\.1\.4\.1\.4203\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "olc",
                "structuralobjectclass",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "olcglobal",
                "olcdatabaseconfig",
                "olcldapconfig",
                "olcmdbconfig",
                "olcbdbconfig",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=config",
                "cn=schema",
                "cn=monitor",
            ],
        )

        # OpenLDAP required object classes for valid entries
        REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "person",
                "organizationalPerson",
                "inetOrgPerson",
            ],
        )

        # Schema-specific regex patterns (migrated from nested Schema class)
        SCHEMA_OPENLDAP_OLC_PATTERN: ClassVar[str] = r"\bolc[A-Z][a-zA-Z]*\b"

        # ACL parsing patterns (migrated from nested Acl class)
        ACL_BY_PATTERN: ClassVar[str] = r"by\s+([^\s]+)\s+([^\s]+)"
        ACL_DEFAULT_NAME: ClassVar[str] = "access"  # Internal name for compatibility

        # ACL parsing patterns (migrated from _parse_acl method)
        ACL_INDEX_PATTERN: ClassVar[str] = r"^\{(\d+)\}\s*(.+)"
        ACL_TO_BY_PATTERN: ClassVar[str] = r"^to\s+(.+?)\s+by\s+"
        ACL_ATTRS_PATTERN: ClassVar[str] = r"attrs?\s*=\s*([^,\s]+(?:\s*,\s*[^,\s]+)*)"
        ACL_SUBJECT_TYPE_WHO: ClassVar[c.Ldif.LiteralTypes.AclSubjectTypeLiteral] = (
            "all"  # OpenLDAP "who" maps to "all" in normalized model
        )

        # ACL detection patterns (migrated from can_handle_acl method)
        ACL_INDEX_PREFIX_PATTERN: ClassVar[str] = r"^(\{\d+\})?\s*to\s+"
        ACL_START_PREFIX: ClassVar[str] = "to"

        # ACL parsing constants (migrated from _parse_acl method)
        ACL_ATTRS_SEPARATOR: ClassVar[str] = ","
        ACL_PREFIX_TO: ClassVar[str] = "to "  # OpenLDAP ACL "to" clause prefix
        ACL_PREFIX_BY: ClassVar[str] = "by "  # OpenLDAP ACL "by" clause prefix
        ACL_WILDCARD_TARGET: ClassVar[str] = "*"  # Wildcard target/subject
        ACL_DEFAULT_ACCESS: ClassVar[str] = "none"  # Default access level
        ACL_OLCACCESS_PREFIX: ClassVar[str] = "olcAccess:"  # olcAccess attribute prefix
        ACL_ERROR_MISSING_TO: ClassVar[str] = (
            "Invalid OpenLDAP ACL format: missing 'to' clause"
        )

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
        """OpenLDAP 2.x schema quirk.

        Extends RFC 4512 schema parsing with OpenLDAP 2.x-specific features:
        - olc* namespace and attributes
        - olcAttributeTypes and olcObjectClasses
        - cn=config based schema configuration
        - OpenLDAP-specific extensions

        Example:
            quirk = FlextLdifServersOpenldap()
            if quirk.schema_quirk.can_handle_attribute(attr_def):
                result = quirk.schema_quirk.parse(attr_def)

        """

        # Schema patterns moved to Constants.SCHEMA_OPENLDAP_OLC_PATTERN

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Check if this is an OpenLDAP 2.x attribute (PRIVATE).

            OpenLDAP 2.x can handle both:
            - OpenLDAP-specific attributes (olc* prefix)
            - Standard RFC attributes (inherits from RFC base)

            Args:
                attr_definition: Attribute definition string or model

            Returns:
                True if this is an OpenLDAP 2.x or RFC attribute

            """
            # Check for olc* prefix or olcAttributeTypes context
            if isinstance(attr_definition, str):
                # Reject empty strings
                if not attr_definition or not attr_definition.strip():
                    return False
                # Check if it contains OpenLDAP-specific markers
                if re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    attr_definition,
                    re.IGNORECASE,
                ):
                    return True
                # Otherwise, delegate to RFC base (RFC attributes are also valid)
                return super().can_handle_attribute(attr_definition)
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                # Check if it contains OpenLDAP-specific markers
                if attr_definition.oid and re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    attr_definition.oid,
                    re.IGNORECASE,
                ):
                    return True
                # Otherwise, delegate to RFC base (RFC attributes are also valid)
                return super().can_handle_attribute(attr_definition)
            return False

        # Schema parsing and conversion methods
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Schema)
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - _parse_attribute(): Private - strips OpenLDAP-specific metadata
        # - _parse_objectclass(): Private - strips OpenLDAP-specific metadata
        # - should_filter_out_attribute(): Returns False (accept all in OpenLDAP mode)
        # - should_filter_out_objectclass(): Returns False (accept all in OpenLDAP mode)
        # - create_metadata(): Creates OpenLDAP-specific metadata

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Check if this is an OpenLDAP 2.x objectClass (PRIVATE).

            OpenLDAP 2.x can handle both:
            - OpenLDAP-specific objectClasses (olc* prefix)
            - Standard RFC objectClasses (inherits from RFC base)

            Args:
                oc_definition: ObjectClass definition string or model

            Returns:
                True if this is an OpenLDAP 2.x or RFC objectClass

            """
            if isinstance(oc_definition, str):
                # Check if it contains OpenLDAP-specific markers
                if re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    oc_definition,
                    re.IGNORECASE,
                ):
                    return True
                # Otherwise, delegate to RFC base (RFC objectClasses are also valid)
                return super().can_handle_objectclass(oc_definition)
            if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
                # Check if it contains OpenLDAP-specific markers
                if oc_definition.oid and re.search(
                    FlextLdifServersOpenldap.Constants.SCHEMA_OPENLDAP_OLC_PATTERN,
                    oc_definition.oid,
                    re.IGNORECASE,
                ):
                    return True
                # Otherwise, delegate to RFC base (RFC objectClasses are also valid)
                return super().can_handle_objectclass(oc_definition)
            return False

        def _transform_attribute_for_write(
            self,
            attr_data: m.Ldif.SchemaAttribute,
        ) -> m.Ldif.SchemaAttribute:
            """Transform attribute before writing (hook from base.py).

            OpenLDAP 2.x can use this hook to transform attributes before writing.
            Currently no transformation needed - just pass through.

            Args:
                attr_data: SchemaAttribute model to transform

            Returns:
                Transformed SchemaAttribute model

            """
            # OpenLDAP 2.x doesn't need special transformations
            # Just pass through to parent
            return super()._transform_attribute_for_write(attr_data)

        def _transform_objectclass_for_write(
            self,
            oc_data: m.Ldif.SchemaObjectClass,
        ) -> m.Ldif.SchemaObjectClass:
            """Transform objectClass before writing (hook from base.py).

            OpenLDAP 2.x can use this hook to transform objectClasses before writing.
            Currently no transformation needed - just pass through.

            Args:
                oc_data: SchemaObjectClass model to transform

            Returns:
                Transformed SchemaObjectClass model

            """
            # OpenLDAP 2.x doesn't need special transformations
            # Just pass through to parent
            return super()._transform_objectclass_for_write(oc_data)

    class Acl(FlextLdifServersRfcAcl):  # type: ignore[override]
        """OpenLDAP 2.x ACL quirk (nested).

        Extends RFC ACL parsing with OpenLDAP 2.x-specific ACL formats:
        - olcAccess: OpenLDAP 2.x access control directives
        - Format: to <what> by <who> <access>

        Example:
            quirk = FlextLdifServersOpenldap.Acl()
            if quirk.can_handle(acl_line):
                result = quirk.parse(acl_line)

        """

        # No __init__ override needed - parent class FlextLdifServersRfcAcl.__new__
        # handles all initialization via Dependency Injection pattern

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is an OpenLDAP 2.x ACL.

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is OpenLDAP 2.x ACL format

            """
            # Type narrowing: acl_line is t.Ldif.AclOrString (str | AclProtocol)
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            # acl_line is AclProtocol (which includes m.Ldif.Acl)
            # Use hasattr check for protocol compatibility
            if hasattr(acl_line, "raw_acl"):
                raw_acl_value = getattr(acl_line, "raw_acl", None)
                if not raw_acl_value:
                    return False
                return self.can_handle_acl(str(raw_acl_value))
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an OpenLDAP 2.x ACL (internal).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is OpenLDAP 2.x ACL format

            """
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                acl_line = acl_line.raw_acl
            if not isinstance(acl_line, str) or not acl_line:
                return False
            # Remove "olcAccess: " prefix if present
            acl_content = acl_line
            olc_prefix = FlextLdifServersOpenldap.Constants.ACL_OLCACCESS_PREFIX
            if acl_line.startswith(olc_prefix):
                acl_content = acl_line[len(olc_prefix) :].strip()
            # OpenLDAP 2.x ACLs start with "to" or "{n}to"
            return bool(
                re.match(
                    FlextLdifServersOpenldap.Constants.ACL_INDEX_PREFIX_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                ),
            ) or acl_content.startswith(
                FlextLdifServersOpenldap.Constants.ACL_START_PREFIX
                + f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:",
            )

        def _write_acl(
            self,
            acl_data: FlextLdifModelsDomains.Acl,
        ) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format (internal).

            Accepts base Acl type for polymorphism - all Acl subclasses are valid.

            Args:
                acl_data: Acl model (base or derived type)

            Returns:
                FlextResult with RFC-compliant ACL string

            """
            try:
                # If raw_acl is available, use it
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Otherwise reconstruct from model fields (OpenLDAP 2.x format)
                constants = FlextLdifServersOpenldap.Constants
                what = (
                    acl_data.target.target_dn
                    if acl_data.target
                    else constants.ACL_WILDCARD_TARGET
                )
                who = (
                    acl_data.subject.subject_value
                    if acl_data.subject
                    else constants.ACL_WILDCARD_TARGET
                )

                # Format as OpenLDAP 2.x ACL
                acl_parts = [
                    f"{constants.ACL_PREFIX_TO}{what}",
                ]
                acl_parts.append(f"{constants.ACL_PREFIX_BY}{who}")

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

        # ===== _parse_acl HELPER METHODS (DRY refactoring) =====

        def _strip_acl_prefix_and_index(self, acl_line: str) -> str:
            """Remove olcAccess: prefix and {n} index from ACL line.

            Args:
                acl_line: Raw ACL line

            Returns:
                ACL content without prefix and index

            """
            acl_content = acl_line
            if acl_line.startswith(
                f"{FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME}:",
            ):
                acl_content = acl_line[
                    len(
                        FlextLdifServersOpenldap.Constants.ACL_ATTRIBUTE_NAME + ":",
                    ) :
                ].strip()

            # Remove {n} index if present
            index_match = re.match(
                FlextLdifServersOpenldap.Constants.ACL_INDEX_PATTERN,
                acl_content,
            )
            if index_match:
                acl_content = index_match.group(2)

            return acl_content

        def _parse_what_clause(self, acl_content: str) -> tuple[str | None, list[str]]:
            """Parse "to <what>" clause and extract attributes.

            Args:
                acl_content: ACL content without prefix

            Returns:
                Tuple of (what_clause, attributes_list) or (None, []) if no match

            """
            to_match = re.match(
                FlextLdifServersOpenldap.Constants.ACL_TO_BY_PATTERN,
                acl_content,
                re.IGNORECASE,
            )
            if not to_match:
                return None, []

            what = to_match.group(1).strip()

            # Extract attributes from "what" clause
            attributes: list[str] = []
            attrs_match = re.search(
                FlextLdifServersOpenldap.Constants.ACL_ATTRS_PATTERN,
                what,
                re.IGNORECASE,
            )
            if attrs_match:
                attr_string = attrs_match.group(1)
                attributes = [
                    attr.strip()
                    for attr in attr_string.split(
                        FlextLdifServersOpenldap.Constants.ACL_ATTRS_SEPARATOR,
                    )
                ]

            return what, attributes

        def _parse_by_clauses(self, acl_content: str) -> tuple[str, str]:
            """Parse "by <who> <access>" clauses.

            Args:
                acl_content: ACL content without prefix

            Returns:
                Tuple of (subject_value, access)

            """
            by_matches = list(
                re.finditer(
                    FlextLdifServersOpenldap.Constants.ACL_BY_PATTERN,
                    acl_content,
                    re.IGNORECASE,
                ),
            )

            subject_value = (
                by_matches[0].group(1)
                if by_matches
                else FlextLdifServersOpenldap.Constants.ACL_SUBJECT_ANONYMOUS
            )

            access = (
                by_matches[0].group(2)
                if by_matches
                else FlextLdifServersOpenldap.Constants.ACL_DEFAULT_ACCESS
            )

            return subject_value, access

        def _build_openldap_acl_model(
            self,
            what: str,
            attributes: list[str],
            subject_value: str,
            access: str,
            acl_line: str,
        ) -> m.Ldif.Acl:
            """Build OpenLDAP Acl model from parsed components.

            Args:
                what: Target DN/what clause
                attributes: Target attributes list
                subject_value: Subject who clause
                access: Access permissions string
                acl_line: Original ACL line

            Returns:
                Acl model

            """
            return m.Ldif.Acl(
                name=FlextLdifServersOpenldap.Constants.ACL_DEFAULT_NAME,
                target=m.Ldif.AclTarget(
                    target_dn=what,
                    attributes=attributes,
                ),
                subject=m.Ldif.AclSubject(
                    subject_type="all",  # Map "anyone" to "all" (valid AclSubjectTypeLiteral)
                    subject_value=subject_value,
                ),
                permissions=m.Ldif.AclPermissions(
                    read="read" in access,
                    write="write" in access,
                    add="write" in access,
                    delete="write" in access,
                    search="read" in access,
                    compare="read" in access,
                ),
                metadata=m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                    extensions={"original_format": acl_line},
                ),
                raw_acl=acl_line,
            )

        def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
            """Parse OpenLDAP 2.x ACL definition (internal).

            Format: to <what> by <who> <access>
            Example: to attrs=userPassword by self write by anonymous auth by * none

            Args:
                acl_line: ACL definition line

            Returns:
                FlextResult with parsed OpenLDAP 2.x ACL data

            """
            try:
                # Strip prefix and index using helper (DRY refactoring)
                acl_content = self._strip_acl_prefix_and_index(acl_line)

                # Parse "to <what>" clause using helper (DRY refactoring)
                what, attributes = self._parse_what_clause(acl_content)

                if what is None:
                    # ACL parser accepts incomplete ACLs and stores as raw
                    acl_minimal = m.Ldif.Acl(
                        name=FlextLdifServersOpenldap.Constants.ACL_DEFAULT_NAME,
                        target=m.Ldif.AclTarget(
                            target_dn=FlextLdifServersOpenldap.Constants.ACL_WILDCARD_TARGET,
                            attributes=[],
                        ),
                        subject=m.Ldif.AclSubject(
                            subject_type=FlextLdifServersOpenldap.Constants.ACL_SUBJECT_TYPE_WHO,
                            subject_value=FlextLdifServersOpenldap.Constants.ACL_WILDCARD_TARGET,
                        ),
                        permissions=m.Ldif.AclPermissions(),
                        raw_acl=acl_line,
                        metadata=self.create_metadata(acl_line),
                    )
                    # acl_minimal is already m.Ldif.Acl from m.Ldif.Acl()
                    return FlextResult[m.Ldif.Acl].ok(acl_minimal)

                # Parse "by <who> <access>" using helper (DRY refactoring)
                subject_value, access = self._parse_by_clauses(acl_content)

                # Build Acl model using helper (DRY refactoring)
                acl = self._build_openldap_acl_model(
                    what,
                    attributes,
                    subject_value,
                    access,
                    acl_line,
                )

                # acl is already m.Ldif.Acl from _build_openldap_acl_model
                return FlextResult[m.Ldif.Acl].ok(acl)

            except Exception as e:
                return FlextResult[m.Ldif.Acl].fail(
                    f"OpenLDAP 2.x ACL parsing failed: {e}",
                )

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

        # No __init__ override needed - parent class FlextLdifServersRfc.Entry.__new__
        # handles all initialization via Dependency Injection pattern

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with OpenLDAP 2.x-specific logic:
        # - can_handle(): PRIVATE - Detects OpenLDAP 2.x entries by DN/attributes
        # - _parse_entry(): Normalizes OpenLDAP 2.x entries with metadata

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Check if this quirk should handle the entry (PRIVATE).

            Args:
                entry_dn: Entry distinguished name (raw string from LDIF)
                attributes: Entry attributes mapping (raw from LDIF parser)

            Returns:
                True if this is an OpenLDAP 2.x-specific entry

            """
            if not entry_dn:
                return False

            # Check for cn=config DN or olc* attributes
            # Use Constants.DETECTION_DN_MARKERS which includes "cn=config"
            is_config_dn = any(
                marker in entry_dn.lower()
                for marker in FlextLdifServersOpenldap.Constants.DETECTION_DN_MARKERS
            )

            # Check for olc* attributes
            has_olc_attrs = any(attr.startswith("olc") for attr in attributes)

            # Check for OpenLDAP 2.x object classes
            object_classes_raw = attributes.get(
                c.Ldif.DictKeys.OBJECTCLASS,
                [],
            )
            # Type narrowing: convert to list[str] for consistent iteration
            object_classes_list: list[str] = []
            if isinstance(object_classes_raw, (list, tuple)):
                # Already list-like - convert each element to string
                # Type assertion for type checker (is_list_like confirms iterable)
                for item in (
                    object_classes_raw
                    if isinstance(object_classes_raw, list)
                    else [object_classes_raw]
                ):
                    if isinstance(item, str):
                        object_classes_list.append(item)
                    elif item is not None:
                        object_classes_list.append(str(item))
            elif isinstance(object_classes_raw, str):
                object_classes_list = [object_classes_raw]
            elif object_classes_raw is not None:
                # Fallback for any other type
                object_classes_list = [str(object_classes_raw)]

            has_olc_classes = any(
                oc in FlextLdifServersOpenldap.Constants.OPENLDAP_2_OBJECTCLASSES
                for oc in object_classes_list
            )

            return is_config_dn or has_olc_attrs or has_olc_classes

        def _inject_validation_rules(
            self,
            entry: m.Ldif.Entry,
        ) -> m.Ldif.Entry:
            """Inject OpenLDAP-specific validation rules into Entry metadata via DI.

            Architecture (Dependency Injection Pattern):
            - Reads ServerValidationRules frozensets from FlextLdifConstants
            - Determines OpenLDAP requirements dynamically (NO hard-coded logic)
            - Injects rules via metadata.extensions["validation_rules"]
            - Entry.validate_server_specific_rules() applies rules dynamically

            OpenLDAP-specific characteristics:
            - Multiple encodings: UTF-8, Latin-1, ISO-8859-1 (flexible)
            - Flexible schema: objectClass optional (lenient mode)
            - ACL format: olcAccess (OpenLDAP-specific)
            - Dynamic configuration: cn=config support
            - Case preservation: preserves original DN case

            This enables:
            - Dynamic validation based on server requirements
            - ZERO hard-coded validation logic in Entry model
            - ZERO DATA LOSS through metadata tracking
            - Bidirectional conversion support (OpenLDAP ↔ other servers)

            Args:
                entry: Entry to inject validation rules into

            Returns:
                Entry with validation_rules in metadata.extensions

            """
            # Determine server type from constants
            server_type = c.Ldif.ServerTypes.OPENLDAP.value

            # Build validation rules dictionary by reading frozensets
            # ZERO hard-coded values - all from Constants!
            validation_rules: dict[
                str,
                str
                | int
                | float
                | bool
                | dict[str, str | int | float | bool | list[str] | None]
                | list[str]
                | None,
            ] = {
                # OBJECTCLASS requirement (OpenLDAP is flexible - check frozenset)
                "requires_objectclass": (
                    server_type
                    in c.Ldif.ServerValidationRules.OBJECTCLASS_REQUIRED_SERVERS
                ),
                # NAMING ATTRIBUTE requirement (OpenLDAP is flexible - check frozenset)
                "requires_naming_attr": (
                    server_type
                    in c.Ldif.ServerValidationRules.NAMING_ATTR_REQUIRED_SERVERS
                ),
                # BINARY OPTION requirement (OpenLDAP 2.x requires ;binary)
                "requires_binary_option": (
                    server_type
                    in c.Ldif.ServerValidationRules.BINARY_OPTION_REQUIRED_SERVERS
                ),
                # ENCODING RULES (OpenLDAP supports multiple encodings)
                "encoding_rules": {
                    "default_encoding": "utf-8",
                    "allowed_encodings": [
                        "utf-8",
                        "latin-1",
                        "iso-8859-1",
                        "ascii",
                    ],
                },
                # DN CASE RULES (OpenLDAP-specific: preserve original case)
                "dn_case_rules": {
                    "preserve_case": True,  # OpenLDAP preserves DN case
                    "normalize_to": None,  # No case normalization
                },
                # ACL FORMAT RULES (OpenLDAP uses olcAccess format)
                "acl_format_rules": {
                    "format": "olcAccess",  # OpenLDAP-specific ACL format
                    "attribute_name": "olcAccess",  # OpenLDAP ACL attribute
                    "requires_target": True,  # olcAccess requires target
                    "requires_subject": True,  # olcAccess requires subject
                },
                # ZERO DATA LOSS tracking flags
                "track_deletions": True,  # Track deleted attributes in metadata
                "track_modifications": True,  # Track original values before modifications
                "track_conversions": True,  # Track format conversions
            }

            # Ensure entry has metadata
            if entry.metadata is None:
                entry = entry.model_copy(
                    update={
                        "metadata": m.Ldif.QuirkMetadata.create_for(
                            "openldap",  # Literal string for ServerTypeLiteral
                            extensions=m.Ldif.DynamicMetadata(),
                        ),
                    },
                )

            # Metadata is guaranteed to be non-None after creation above
            # Type narrowing: entry.metadata is non-None after model_copy
            # Defensive check with proper error instead of assert
            # NOTE: This method returns Entry directly, not FlextResult
            # If metadata is None, we cannot inject validation rules, so return entry as-is
            if entry.metadata is None:
                # Cannot inject validation rules without metadata
                # Return entry as-is (caller should handle this case)
                return entry
            # Inject validation rules via metadata.extensions (DI pattern)
            # Serialize to JSON string to satisfy MetadataAttributeValue type constraint
            # (nested dicts with lists don't fit Mapping[str, ScalarValue])

            entry.metadata.extensions["validation_rules"] = json.dumps(validation_rules)

            logger.debug(
                "Injected OpenLDAP validation rules into Entry metadata",
                entry_dn=entry.dn.value if entry.dn else None,
                requires_objectclass=validation_rules["requires_objectclass"],
                server_type=c.Ldif.ServerTypes.OPENLDAP.value,
                requires_naming_attr=validation_rules["requires_naming_attr"],
                requires_binary_option=validation_rules["requires_binary_option"],
                acl_format=validation_rules["acl_format_rules"],
            )

            return entry


__all__ = ["FlextLdifServersOpenldap"]
