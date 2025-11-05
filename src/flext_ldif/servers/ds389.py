"""389 Directory Server quirks implementation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar, Final, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for 389 Directory Server quirk."""

        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
        CANONICAL_NAME: ClassVar[str] = "389ds"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["389ds"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["389ds", "rfc"])

        # 389 Directory Server ACL format constants
        ACL_FORMAT: ClassVar[str] = (
            "aci"  # RFC 4876 ACI attribute (389 DS uses standard ACI)
        )
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # 389 Directory Server operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "nsUniqueId",
            "nscpEntryDN",
            "nsds5ReplConflict",
        ])

        # Detection constants (server-specific) - migrated from FlextLdifConstants.LdapServerDetection
        DETECTION_OID_PATTERN: Final[str] = r"2\.16\.840\.1\.113730\."
        DETECTION_ATTRIBUTE_PREFIXES: Final[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])
        DETECTION_OBJECTCLASS_NAMES: Final[frozenset[str]] = frozenset([
            "nscontainer",
            "nsperson",
            "nsds5replica",
            "nsds5replicationagreement",
            "nsorganizationalunit",
            "nsorganizationalperson",
        ])
        DETECTION_DN_MARKERS: Final[frozenset[str]] = frozenset([
            "cn=config",
            "cn=monitor",
            "cn=changelog",
        ])

        # 389 Directory Server specific attributes (migrated from FlextLdifConstants)
        DS_389_SPECIFIC: Final[frozenset[str]] = frozenset([
            "nsuniqueId",
            "nscpentrydn",
            "nsds5replconflict",
            "nsds5replicareferencen",
            "nsds5beginreplicarefresh",
            "nsds7windowsreplicasubentry",
            "nsds7DirectoryReplicaSubentry",
        ])

        # ACL-specific constants (migrated from nested Acl class)
        ACL_CLAUSE_PATTERN: Final[str] = r"\([^()]+\)"

        # 389 DS ACI parsing patterns (migrated from Acl class)
        ACL_NAME_PATTERN: Final[str] = r"acl\s+\"([^\"]+)\""
        ACL_ALLOW_PATTERN: Final[str] = r"allow\s*\(([^)]+)\)"
        ACL_TARGETATTR_PATTERN: Final[str] = r"targetattr\s*=\s*\"([^\"]+)\""
        ACL_USERDN_PATTERN: Final[str] = r"userdn\s*=\s*\"([^\"]+)\""
        ACL_TARGET_PATTERN: Final[str] = r"target\s*=\s*\"([^\"]+)\""
        ACL_DEFAULT_NAME: Final[str] = "389 DS ACL"
        ACL_TARGET_DN_PREFIX: Final[str] = "dn:"
        ACL_ANONYMOUS_SUBJECT: Final[str] = "ldap:///anyone"  # Default anonymous subject for 389 DS
        ACL_VERSION_PREFIX: Final[str] = "(version 3.0)"
        ACL_TARGETATTR_SEPARATOR: Final[str] = ","
        ACL_TARGETATTR_SPACE_REPLACEMENT: Final[str] = " "
        ACL_ACI_PREFIX: Final[str] = "aci:"  # 389 DS ACI attribute prefix

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize 389 Directory Server quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Nested classes no longer require server_type and priority parameters
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

    def __getattr__(self, name: str) -> object:
        """Delegate method calls to nested Schema, Acl, or Entry instances.

        This enables calling schema/acl/entry methods directly on the main server instance.

        Args:
            name: Method or attribute name to look up

        Returns:
            Method or attribute from nested instance

        Raises:
            AttributeError: If attribute not found in any nested instance

        """
        # Try schema methods first (most common)
        if hasattr(self.schema, name):
            return getattr(self.schema, name)
        # Try acl methods
        if hasattr(self.acl, name):
            return getattr(self.acl, name)
        # Try entry methods
        if hasattr(self.entry, name):
            return getattr(self.entry, name)
        # Not found in any nested instance
        msg = f"'{type(self).__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Red Hat / 389 Directory Server."""

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect 389 DS attribute definitions using centralized constants."""
            if isinstance(attr_definition, str):
                # Check OID pattern first
                if re.search(
                    FlextLdifServersDs389.Constants.DETECTION_OID_PATTERN,
                    attr_definition,
                ):
                    return True
                # Extract attribute name from string definition
                # Look for NAME 'attributename' pattern (supports hyphens and underscores)
                name_match = re.search(r"NAME\s+['\"]([\w-]+)['\"]", attr_definition, re.IGNORECASE)
                if name_match:
                    attr_name = name_match.group(1).lower()
                    return any(
                        attr_name.startswith(prefix)
                        for prefix in FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES
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
                    for prefix in FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES
                )
            return False

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
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
                name_match = re.search(r"NAME\s+['\"](\w+)['\"]", oc_definition, re.IGNORECASE)
                if name_match:
                    oc_name = name_match.group(1).lower()
                    return oc_name in FlextLdifServersDs389.Constants.DETECTION_OBJECTCLASS_NAMES
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
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add 389 DS metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with 389 DS metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifServersDs389.Constants.SERVER_TYPE
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
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
                FlextLdifUtilities.ObjectClass.fix_missing_sup(
                    oc_data, server_type=FlextLdifServersDs389.Constants.SERVER_TYPE
                )
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifServersDs389.Constants.SERVER_TYPE
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifServersDs389.Constants.SERVER_TYPE
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI quirk."""

        def _can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
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
                _attr_name, content = self._splitacl_line(acl_line)
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
                    [perm.strip() for perm in permissions_match.group(1).split(",")]
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
                        FlextLdifServersDs389.Constants.ACL_TARGETATTR_SPACE_REPLACEMENT
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
                    if target_clause.lower().startswith(FlextLdifServersDs389.Constants.ACL_TARGET_DN_PREFIX):
                        target_dn = target_clause[len(FlextLdifServersDs389.Constants.ACL_TARGET_DN_PREFIX):]  # Extract after "dn:"
                    else:
                        target_dn = target_clause

                # Build metadata
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifServersDs389.Constants.SERVER_TYPE
                )
                metadata.original_format = acl_line.strip()

                # Build Acl model
                acl = FlextLdifModels.Acl(
                    name=acl_name_match.group(1) if acl_name_match else FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME,
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,  # DS389: extracted from target clause
                        attributes=target_attributes,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=FlextLdifConstants.AclSubjectTypes.USER,
                        subject_value=(
                            userdn_matches[0] if userdn_matches else FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT
                        ),
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        # DS389: set permissions based on parsed permission list
                        read=FlextLdifConstants.PermissionNames.READ in permissions,
                        write=FlextLdifConstants.PermissionNames.WRITE in permissions,
                        add=FlextLdifConstants.PermissionNames.ADD in permissions,
                        delete=FlextLdifConstants.PermissionNames.DELETE in permissions,
                        search=FlextLdifConstants.PermissionNames.SEARCH in permissions,
                        compare=FlextLdifConstants.PermissionNames.COMPARE in permissions,
                    ),
                    metadata=metadata,
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"389 Directory Server ACL parsing failed: {exc}",
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

                # Otherwise build from model fields
                acl_name = acl_data.name or FlextLdifServersDs389.Constants.ACL_DEFAULT_NAME

                # Build permissions list from flags
                permissions: list[str] = []
                if acl_data.permissions:
                    # Use constants for permission names
                    if acl_data.permissions.read:
                        permissions.append(FlextLdifConstants.PermissionNames.READ)
                    if acl_data.permissions.write:
                        permissions.append(FlextLdifConstants.PermissionNames.WRITE)
                    if acl_data.permissions.add:
                        permissions.append(FlextLdifConstants.PermissionNames.ADD)
                    if acl_data.permissions.delete:
                        permissions.append(FlextLdifConstants.PermissionNames.DELETE)
                    if acl_data.permissions.search:
                        permissions.append(FlextLdifConstants.PermissionNames.SEARCH)
                    if acl_data.permissions.compare:
                        permissions.append(FlextLdifConstants.PermissionNames.COMPARE)

                targetattr = (
                    " ".join(acl_data.target.attributes)
                    if acl_data.target and acl_data.target.attributes
                    else "*"
                )
                userdn = (
                    acl_data.subject.subject_value
                    if acl_data.subject and acl_data.subject.subject_value
                    else FlextLdifServersDs389.Constants.ACL_ANONYMOUS_SUBJECT
                )

                # Build ACI string from structured fields
                parts = [FlextLdifServersDs389.Constants.ACL_VERSION_PREFIX, f'acl "{acl_name}"']
                if permissions:
                    perms = ", ".join(permissions)
                    parts.append(f"allow ({perms})")
                if targetattr:
                    parts.append(f'targetattr = "{targetattr}"')
                if userdn:
                    parts.append(f'userdn = "{userdn}"')

                acl_content = "; ".join(parts) if parts else ""
                acl_str = f"aci: {acl_content}" if acl_content else "aci:"

                return FlextResult[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    f"389 Directory Server ACL write failed: {exc}",
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for 389 Directory Server."""

        def _can_handle_entry(
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
                    tuple(FlextLdifServersDs389.Constants.DETECTION_ATTRIBUTE_PREFIXES)
                )
                for attr in normalized_attrs
            ):
                return True

            object_classes_raw = normalized_attrs.get(
                "objectclass",
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
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise 389 DS entries and attach metadata."""
            try:
                attributes = entry.attributes.attributes.copy()
                entry_dn = entry.dn.value
                dn_lower = entry_dn.lower()

                # Store metadata in extensions
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata()
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
                    f"389 Directory Server entry processing failed: {exc}",
                )


__all__ = ["FlextLdifServersDs389"]

__all__ = ["FlextLdifServersDs389"]
