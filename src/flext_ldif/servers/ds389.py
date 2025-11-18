"""389 Directory Server quirks implementation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import ClassVar, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for 389 Directory Server quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
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
        # Migrated from FlextLdifConstants.OperationalAttributeMappings
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
        # Migrated from FlextLdifConstants.LdapServerDetection
        DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113730\."
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "nsslapd-",
                "nsds",
                "nsuniqueid",
            ],
        )

        # Server detection patterns and weights
        # Migrated from FlextLdifConstants.ServerDetection
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
        # (migrated from FlextLdifConstants.SchemaConversionMappings)
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

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(StrEnum):
            """389 Directory Server-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            ADD = "add"
            DELETE = "delete"
            SEARCH = "search"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(StrEnum):
            """389 Directory Server ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """389 Directory Server-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16 = "utf-16"
            ASCII = "ascii"
            LATIN_1 = "latin-1"

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Red Hat / 389 Directory Server."""

        def can_handle_attribute(
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Detect 389 DS attribute definitions using centralized constants."""
            if isinstance(attr_definition, str):
                # Check OID pattern first
                if re.search(
                    FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    attr_definition,
                ):
                    return True
                # Extract attribute name from string definition.
                # Look for NAME 'attributename' pattern
                # (supports hyphens and underscores)
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
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                if re.search(
                    FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    attr_definition.oid,
                ):
                    return True
                attr_name_lower = attr_definition.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in (
                        FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES
                    )
                )
            return False

        def can_handle_objectclass(
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Detect 389 DS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
                # Check OID pattern first
                if re.search(
                    FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    oc_definition,
                ):
                    return True
                # Extract objectClass name from string definition
                # Look for NAME 'objectclassname' pattern
                name_match = re.search(
                    FlextLdifServersDs389.Constants.SCHEMA_OBJECTCLASS_NAME_REGEX,
                    oc_definition,
                    re.IGNORECASE,
                )
                if name_match:
                    oc_name = name_match.group(1).lower()
                    return oc_name in (
                        FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
                    )
                return False
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                if re.search(
                    FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    oc_definition.oid,
                ):
                    return True
                oc_name_lower = oc_definition.name.lower() if oc_definition.name else ""
                return (
                    oc_name_lower
                    in FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
            *,
            case_insensitive: bool = False,
            allow_syntax_quotes: bool = False,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add 389 DS metadata.

            Args:
                attr_definition: Attribute definition string
                case_insensitive: Whether to use case-insensitive pattern matching
                allow_syntax_quotes: Whether to allow quoted syntax values

            Returns:
                FlextResult with SchemaAttribute marked with 389 DS metadata

            """
            result = super()._parse_attribute(
                attr_definition,
                case_insensitive=case_insensitive,
                allow_syntax_quotes=allow_syntax_quotes,
            )
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add 389 DS metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with 389 DS metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilities.ObjectClass.fix_missing_sup(oc_data)
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(oc_data)
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI quirk."""

        def can_handle(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
            """Check if this is a 389 Directory Server ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is 389 Directory Server ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: FlextLdifTypes.AclOrString) -> bool:
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
            if isinstance(acl_line, FlextLdifModels.Acl):
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

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse 389 DS ACI definition."""
            try:
                attr_name, content = self._splitacl_line(acl_line)
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
                metadata = FlextLdifModels.QuirkMetadata.create_for(
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
                permissions_data = FlextLdifModels.AclPermissions(
                    read=perm_read,
                    write=perm_write,
                    add=perm_add,
                    delete=perm_delete,
                    search=perm_search,
                    compare=perm_compare,
                )
                acl = FlextLdifModels.Acl(
                    name=acl_name,
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,  # DS389: extracted from target clause
                        attributes=target_attributes,
                    ),
                    subject=FlextLdifModels.AclSubject(
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

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    FlextLdifServersDs389.Constants.ERROR_ACL_PARSING_FAILED.format(
                        exc=exc,
                    ),
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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
                permissions = self._extract_acl_permissions(
                    cast("FlextLdifModels.AclPermissions | None", acl_data.permissions),
                )
                targetattr = self._resolve_acl_targetattr(
                    cast("FlextLdifModels.AclTarget | None", acl_data.target),
                )
                userdn = self._resolve_acl_userdn(
                    cast("FlextLdifModels.AclSubject | None", acl_data.subject),
                )

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
            permissions_data: FlextLdifModels.AclPermissions | None,
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
        def _resolve_acl_targetattr(target: FlextLdifModels.AclTarget | None) -> str:
            """Resolve target attributes to formatted string."""
            if target and target.attributes:
                separator = (
                    FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT
                )
                return separator.join(target.attributes)
            return FlextLdifServersDs389.Constants.ACL_WILDCARD_ATTRIBUTE

        @staticmethod
        def _resolve_acl_userdn(subject: FlextLdifModels.AclSubject | None) -> str:
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

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for 389 Directory Server."""

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
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
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(
                    tuple(FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES),
                )
                for attr in normalized_attrs
            ):
                return True

            # Use lowercase objectClass key for normalized attributes
            objectclass_key = FlextLdifConstants.DictKeys.OBJECTCLASS.lower()
            object_classes_raw = normalized_attrs.get(
                objectclass_key,
                [],
            )
            object_classes = (
                object_classes_raw
                if isinstance(object_classes_raw, list)
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
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise 389 DS entries and attach metadata."""
            try:
                # Check if entry has attributes and DN
                if not entry.attributes or not entry.dn:
                    return FlextResult[FlextLdifModels.Entry].ok(entry)

                attributes = entry.attributes.attributes.copy()
                entry_dn = entry.dn.value
                dn_lower = entry_dn.lower()

                # Store metadata in extensions
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata(
                    quirk_type=FlextLdifServersDs389.Constants.SERVER_TYPE,
                )
                metadata.extensions[
                    FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY
                ] = any(
                    marker in dn_lower
                    for marker in FlextLdifServersDs389.Constants.DETECTION_DN_MARKERS
                )

                processed_entry = FlextLdifModels.Entry(
                    dn=entry.dn,
                    attributes=FlextLdifModels.LdifAttributes(attributes=attributes),
                    metadata=metadata,
                )

                return FlextResult[FlextLdifModels.Entry].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    FlextLdifServersDs389.Constants.ERROR_ENTRY_PROCESSING_FAILED.format(
                        exc=exc,
                    ),
                )


__all__ = ["FlextLdifServersDs389"]
