"""389 Directory Server Quirks - Stub Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides 389 Directory Server-specific quirks for schema, ACL, and entry processing.
Inherits from RFC baseline without server-specific conversions.

Architecture:
- Parsers: LDIF → RFC parse_entry() → Entry Model RFC (inherited, no overrides)
- Writers: Entry Model RFC → RFC _write_entry() → LDIF (inherited, no conversions)
- RFC baseline: 100% RFC 2849/4512 compliance without 389-specific transformations
- Auto-discovery: Server detection via quirks metadata only

This is a stub implementation. Server-specific conversions can be added in _write_entry()
when 389 Directory Server-specific LDIF format requirements are identified.
"""

from __future__ import annotations

import re
from typing import ClassVar, Literal

from flext_core import FlextResult, u

from flext_ldif._utilities.acl import FlextLdifUtilitiesACL
from flext_ldif._utilities.schema import FlextLdifUtilitiesSchema
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for 389 Directory Server quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "ds389"
        PRIORITY: ClassVar[int] = 30

        CANONICAL_NAME: ClassVar[str] = "389ds"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["389ds", "rfc"])

        # 389 Directory Server ACL format constants
        ACL_FORMAT: ClassVar[str] = (
            "aci"  # RFC 4876 ACI attribute (389 DS uses standard ACI)
        )
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # 389 Directory Server operational attributes (server-specific)
        # Migrated from c.OperationalAttributeMappings
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "createTimestamp",
                "modifyTimestamp",
                "creatorsName",
                "modifiersName",
                "nsUniqueId",
                "entryid",
                "dncomp",
                "parentid",
                "passwordExpirationTime",
                "passwordHistory",
                "nscpEntryDN",
                "nsds5ReplConflict",
            ],
        )

        # 389DS extends RFC permissions with "proxy" and "all"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["proxy", "all"])
        )

        # Detection constants (server-specific)
        # Migrated from c.LdapServerDetection
        DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113730\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "nsslapd-",
                "nsds",
                "nsuniqueid",
            ],
        )

        # Server detection patterns and weights
        # Migrated from c.ServerDetection
        DETECTION_PATTERN: ClassVar[str] = r"\b(389ds|redhat-ds|dirsrv)\b"
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "nsuniqueId",
                "nsslapd-",
                "nsds5replica",
                "nsds5replicationagreement",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "nscontainer",
                "nsperson",
                "nsds5replica",
                "nsds5replicationagreement",
                "nsorganizationalunit",
                "nsorganizationalperson",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=config",
                "cn=monitor",
                "cn=changelog",
            ],
        )

        # Schema DN for 389 DS (RFC 4512 standard)
        SCHEMA_DN: ClassVar[str] = "cn=subschemasubentry"

        # Schema attribute fields that are server-specific
        # (migrated from c.SchemaConversionMappings)
        ATTRIBUTE_FIELDS: ClassVar[frozenset[str]] = frozenset(["x_origin", "x_ds_use"])

        # NOTE: Permission names inherited from RFC.Constants

        # ACL subject types specific to 389 DS
        ACL_SUBJECT_TYPE_USER: ClassVar[str] = "user"
        ACL_SUBJECT_TYPE_GROUP: ClassVar[str] = "group"
        ACL_SUBJECT_TYPE_SELF: ClassVar[str] = "self"
        ACL_SUBJECT_TYPE_ANONYMOUS: ClassVar[str] = "anyone"

        # 389 Directory Server specific attributes (migrated from FlextLdifConstants)
        DS_389_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                "nsuniqueId",
                "nscpentrydn",
                "nsds5replconflict",
                "nsds5replicareferencen",
                "nsds5beginreplicarefresh",
                "nsds7windowsreplicasubentry",
                "nsds7DirectoryReplicaSubentry",
            ],
        )

        # Schema attribute/objectClass parsing patterns
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+['\"]([\w-]+)['\"]"
        SCHEMA_OBJECTCLASS_NAME_REGEX: ClassVar[str] = r"NAME\s+['\"](\w+)['\"]"

        # ACL-specific constants (migrated from nested Acl class)
        ACL_CLAUSE_PATTERN: ClassVar[str] = r"\([^()]+\)"

        # 389 DS ACI parsing patterns (migrated from Acl class)
        ACL_NAME_PATTERN: ClassVar[str] = r"acl\s+\"([^\"]+)\""
        ACL_ALLOW_PATTERN: ClassVar[str] = r"allow\s*\(([^)]+)\)"
        ACL_TARGETATTR_PATTERN: ClassVar[str] = r"targetattr\s*=\s*\"([^\"]+)\""
        # Override RFC pattern with 389DS-specific syntax
        ACL_USERDN_PATTERN: ClassVar[str] = r"userdn\s*=\s*\"([^\"]+)\""
        ACL_TARGET_PATTERN: ClassVar[str] = r"target\s*=\s*\"([^\"]+)\""
        ACL_DEFAULT_NAME: ClassVar[str] = "389 DS ACL"
        ACL_TARGET_DN_PREFIX: ClassVar[str] = "dn:"
        # Default anonymous subject for 389 DS
        ACL_ANONYMOUS_SUBJECT: ClassVar[str] = "ldap:///anyone"
        ACL_VERSION_PREFIX: ClassVar[str] = "(version 3.0)"
        ACL_TARGETATTR_SEPARATOR: ClassVar[str] = ","
        ACL_TARGETATTR_SPACE_REPLACEMENT: ClassVar[str] = " "
        ACL_ACI_PREFIX: ClassVar[str] = "aci:"  # ACL attribute prefix for 389 DS
        ACL_ALLOW_PREFIX: ClassVar[str] = (
            "allow"  # ACL allow clause prefix (without parentheses)
        )
        ACL_TARGETATTR_PREFIX: ClassVar[str] = (
            "targetattr"  # ACL targetattr prefix (without =)
        )
        ACL_USERDN_PREFIX: ClassVar[str] = "userdn"  # ACL userdn prefix (without =)
        ACL_TARGET_PREFIX: ClassVar[str] = 'target = "'  # ACL target prefix
        ACL_WILDCARD_ATTRIBUTE: ClassVar[str] = "*"  # Wildcard for all attributes

        # Error messages
        ERROR_ACL_PARSING_FAILED: ClassVar[str] = (
            "389 Directory Server ACL parsing failed: {exc}"
        )
        ERROR_ACL_WRITE_FAILED: ClassVar[str] = (
            "389 Directory Server ACL write failed: {exc}"
        )
        ERROR_ENTRY_PROCESSING_FAILED: ClassVar[str] = (
            "389 Directory Server entry processing failed: {exc}"
        )

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.Ldif.AclPermission,
        # c.Ldif.AclAction, and c.Ldif.Encoding directly

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Red Hat / 389 Directory Server."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect 389 DS attribute definitions using centralized constants."""
            if isinstance(attr_definition, m.Ldif.SchemaAttribute):
                return FlextLdifUtilitiesServer.matches_server_patterns(
                    value=attr_definition,
                    oid_pattern=FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    use_prefix_match=True,
                )
            # For string definitions, extract NAME and check prefix match
            if re.search(
                FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                attr_definition,
            ):
                return True
            name_match = re.search(
                FlextLdifServersDs389.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                attr_definition,
                re.IGNORECASE,
            )
            if name_match:
                attr_name = name_match.group(1).lower()
                return any(
                    attr_name.startswith(prefix)
                    for prefix in (
                        FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES
                    )
                )
            return False

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect 389 DS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, m.Ldif.SchemaObjectClass):
                return FlextLdifUtilitiesServer.matches_server_patterns(
                    value=oc_definition,
                    oid_pattern=FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    detection_names=FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES,
                )
            # For string definitions, extract NAME and check exact match
            if re.search(
                FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                oc_definition,
            ):
                return True
            name_match = re.search(
                FlextLdifServersDs389.Constants.SCHEMA_OBJECTCLASS_NAME_REGEX,
                oc_definition,
                re.IGNORECASE,
            )
            if name_match:
                oc_name = name_match.group(1).lower()
                return (
                    oc_name
                    in FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add 389 DS metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with 389 DS metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add 389 DS metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with 389 DS metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilitiesSchema.fix_missing_sup(oc_data)
                FlextLdifUtilitiesSchema.fix_kind_mismatch(oc_data)
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

    class Acl(FlextLdifServersRfcAcl):
        """389 Directory Server ACI quirk."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is a 389 Directory Server ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is 389 Directory Server ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Detect 389 DS ACI lines."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                if (
                    attr_name.strip().lower()
                    == FlextLdifServersDs389.Constants.ACL_ATTRIBUTE_NAME
                ):
                    return True
                return normalized.lower().startswith("(version")
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False

                attr_name, _, _ = normalized.partition(":")
                if (
                    attr_name.strip().lower()
                    == FlextLdifServersDs389.Constants.ACL_ATTRIBUTE_NAME
                ):
                    return True

                return normalized.lower().startswith("(version")
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[m.Ldif.Acl]:
            """Parse 389 DS ACI definition."""
            try:
                attr_name, content = FlextLdifUtilitiesACL.split_acl_line(acl_line)
                _ = attr_name  # Unused but required for tuple unpacking
                acl_name_match = re.search(
                    FlextLdifServersDs389.Constants.ACL_NAME_PATTERN,
                    content,
                    re.IGNORECASE,
                )
                permissions_match = re.search(
                    FlextLdifServersDs389.Constants.ACL_ALLOW_PATTERN,
                    content,
                    re.IGNORECASE,
                )
                permissions = (
                    [
                        perm.strip()
                        for perm in permissions_match.group(1).split(
                            FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR,
                        )
                    ]
                    if permissions_match
                    else []
                )
                target_attr_match = re.search(
                    FlextLdifServersDs389.Constants.ACL_TARGETATTR_PATTERN,
                    content,
                    re.IGNORECASE,
                )
                userdn_matches = re.findall(
                    FlextLdifServersDs389.Constants.ACL_USERDN_PATTERN,
                    content,
                    re.IGNORECASE,
                )

                # Parse target attributes, handling both space and comma separation
                target_attributes: list[str] = []
                if target_attr_match:
                    # Replace commas with spaces and split
                    attr_string = target_attr_match.group(1).replace(
                        FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR,
                        FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT,
                    )
                    target_attributes = [
                        attr.strip() for attr in attr_string.split() if attr.strip()
                    ]

                # Extract target DN from the ACI target clause
                # 389 DS ACLs use: target = "dn:<dn_pattern>"
                target_dn = "*"  # Default wildcard
                target_match = re.search(
                    FlextLdifServersDs389.Constants.ACL_TARGET_PATTERN,
                    content,
                    re.IGNORECASE,
                )
                if target_match:
                    target_clause = target_match.group(1)
                    # Parse DN from "dn:<dn_pattern>" format
                    dn_prefix = FlextLdifServersDs389.Constants.ACL_TARGET_DN_PREFIX
                    if target_clause.lower().startswith(dn_prefix):
                        # Extract after "dn:"
                        target_dn = target_clause[len(dn_prefix) :]
                    else:
                        target_dn = target_clause

                # Build metadata
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                metadata.extensions["original_format"] = acl_line.strip()

                # Build Acl model
                acl_name = (
                    acl_name_match.group(1)
                    if acl_name_match
                    else FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME
                )
                # DS389: set permissions based on parsed permission list
                perm_read = "read" in permissions
                perm_write = "write" in permissions
                perm_add = "add" in permissions
                perm_delete = "delete" in permissions
                perm_search = "search" in permissions
                perm_compare = "compare" in permissions
                permissions_data = m.Ldif.AclPermissions(
                    read=perm_read,
                    write=perm_write,
                    add=perm_add,
                    delete=perm_delete,
                    search=perm_search,
                    compare=perm_compare,
                )
                acl = m.Ldif.Acl(
                    name=acl_name,
                    target=m.Ldif.AclTarget(
                        target_dn=target_dn,  # DS389: extracted from target clause
                        attributes=target_attributes,
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type="user",
                        subject_value=(
                            userdn_matches[0]
                            if userdn_matches
                            else FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT
                        ),
                    ),
                    permissions=permissions_data,
                    metadata=metadata,
                    raw_acl=acl_line,
                )

                return FlextResult[m.Ldif.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[m.Ldif.Acl].fail(
                    FlextLdifServersDs389.Constants.ERROR_ACL_PARSING_FAILED.format(
                        exc=exc,
                    ),
                )

        def _write_acl(self, acl_data: m.Ldif.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            389 Directory Server ACLs use ACI format with structured clauses.
            """
            try:
                # Use raw_acl if available (preserves original format)
                if acl_data.raw_acl:
                    acl_str = (
                        f"{FlextLdifServersDs389.Constants.ACL_ACI_PREFIX} "
                        f"{acl_data.raw_acl}"
                    )
                    return FlextResult[str].ok(acl_str)

                # Build from model fields
                acl_name = (
                    acl_data.name or FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME
                )
                # Type narrowing: ensure correct types for ACL methods
                permissions_raw = acl_data.permissions
                if not isinstance(
                    permissions_raw,
                    (m.Ldif.AclPermissions, type(None)),
                ):
                    msg = f"Expected AclPermissions | None, got {type(permissions_raw)}"
                    raise TypeError(msg)
                permissions = self._extract_acl_permissions(permissions_raw)

                target_raw = acl_data.target
                if not isinstance(target_raw, (m.Ldif.AclTarget, type(None))):
                    msg = f"Expected AclTarget | None, got {type(target_raw)}"
                    raise TypeError(msg)
                targetattr = self._resolve_acl_targetattr(target_raw)

                subject_raw = acl_data.subject
                if not isinstance(
                    subject_raw,
                    (m.Ldif.AclSubject, type(None)),
                ):
                    msg = f"Expected AclSubject | None, got {type(subject_raw)}"
                    raise TypeError(msg)
                userdn = self._resolve_acl_userdn(subject_raw)

                # Build ACI string from structured fields
                return self._build_acl_string(acl_name, permissions, targetattr, userdn)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    FlextLdifServersDs389.Constants.ERROR_ACL_WRITE_FAILED.format(
                        exc=exc,
                    ),
                )

        def _extract_acl_permissions(
            self,
            permissions_data: m.Ldif.AclPermissions | None,
        ) -> list[str]:
            """Extract permission names from Permissions model flags."""
            permissions: list[str] = []
            if not permissions_data:
                return permissions

            if permissions_data.read:
                permissions.append("read")
            if permissions_data.write:
                permissions.append("write")
            if permissions_data.add:
                permissions.append("add")
            if permissions_data.delete:
                permissions.append("delete")
            if permissions_data.search:
                permissions.append("search")
            if permissions_data.compare:
                permissions.append("compare")

            return permissions

        @staticmethod
        def _resolve_acl_targetattr(target: m.Ldif.AclTarget | None) -> str:
            """Resolve target attributes to formatted string."""
            if target and target.attributes:
                separator = (
                    FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT
                )
                return separator.join(target.attributes)
            return FlextLdifServersDs389.Constants.ACL_WILDCARD_ATTRIBUTE

        @staticmethod
        def _resolve_acl_userdn(subject: m.Ldif.AclSubject | None) -> str:
            """Resolve subject to userdn string."""
            if subject and subject.subject_value:
                return subject.subject_value
            return FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT

        def _build_acl_string(
            self,
            acl_name: str,
            permissions: list[str],
            targetattr: str,
            userdn: str,
        ) -> FlextResult[str]:
            """Build ACI string from components."""
            version_prefix = FlextLdifServersDs389.Constants.ACL_VERSION_PREFIX
            parts = [version_prefix, f'acl "{acl_name}"']

            if permissions:
                perms = FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR.join(
                    permissions,
                )
                parts.append(
                    f"{FlextLdifServersDs389.Constants.ACL_ALLOW_PREFIX} ({perms})",
                )
            if targetattr:
                prefix = FlextLdifServersDs389.Constants.ACL_TARGETATTR_PREFIX
                parts.append(f'{prefix} = "{targetattr}"')
            if userdn:
                parts.append(
                    f'{FlextLdifServersDs389.Constants.ACL_USERDN_PREFIX} = "{userdn}"',
                )

            acl_separator = FlextLdifServersDs389.Constants.ACL_TARGETATTR_SEPARATOR
            acl_content = f"{acl_separator} ".join(parts) if parts else ""
            acl_str = (
                f"{FlextLdifServersDs389.Constants.ACL_ACI_PREFIX} {acl_content}"
                if acl_content
                else FlextLdifServersDs389.Constants.ACL_ACI_PREFIX
            )

            return FlextResult[str].ok(acl_str)

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for 389 Directory Server."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Detect 389 DS-specific entries."""
            if not entry_dn:
                return False

            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersDs389.Constants.DETECTION_DN_MARKERS
            ):
                return True

            normalized_attrs = {
                name.lower(): value
                for name, value in u.mapper().to_dict(attributes).items()
            }
            if any(
                attr.startswith(
                    tuple(FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES),
                )
                for attr in normalized_attrs
            ):
                return True

            # Use lowercase objectClass key for normalized attributes
            objectclass_key = c.Ldif.DictKeys.OBJECTCLASS.lower()
            object_classes_result = u.mapper().get(
                normalized_attrs, objectclass_key, default=[]
            )
            object_classes_raw = (
                object_classes_result.value if object_classes_result.is_success else []
            )
            object_classes = (
                object_classes_raw
                if isinstance(object_classes_raw, (list, tuple))
                else [object_classes_raw]
            )
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> FlextResult[m.Ldif.Entry]:
            """Normalise 389 DS entries and attach metadata."""
            try:
                # Check if entry has attributes and DN
                if not entry.attributes or not entry.dn:
                    return FlextResult[m.Ldif.Entry].ok(entry)

                attributes = entry.attributes.attributes.copy()
                entry_dn = entry.dn.value
                dn_lower = entry_dn.lower()

                # Store metadata in extensions
                server_type_lit: Literal["ds389"] = FlextLdifServersDs389.Constants.SERVER_TYPE.value
                metadata = entry.metadata or m.Ldif.QuirkMetadata(
                    quirk_type=server_type_lit,
                )
                metadata.extensions[c.Ldif.QuirkMetadataKeys.IS_CONFIG_ENTRY] = any(
                    marker in dn_lower
                    for marker in FlextLdifServersDs389.Constants.DETECTION_DN_MARKERS
                )

                processed_entry = m.Ldif.Entry(
                    dn=entry.dn,
                    attributes=m.Ldif.Attributes(attributes=attributes),
                    metadata=metadata,
                )

                return FlextResult[m.Ldif.Entry].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[m.Ldif.Entry].fail(
                    FlextLdifServersDs389.Constants.ERROR_ENTRY_PROCESSING_FAILED.format(
                        exc=exc,
                    ),
                )


__all__ = ["FlextLdifServersDs389"]
