"""389 Directory Server quirks implementation."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar, Final

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # Top-level configuration for 389 DS quirks
    # =========================================================================
    # Class-level attributes for server identification
    # =========================================================================
    server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
    priority: ClassVar[int] = 15

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for 389 Directory Server quirk."""

        CANONICAL_NAME: ClassVar[str] = "389ds"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["389ds"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["389ds"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["389ds", "rfc"])

        # 389 Directory Server ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # RFC 4876 ACI attribute (389 DS uses standard ACI)
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # 389 Directory Server operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "nsUniqueId",
            "nscpEntryDN",
            "nsds5ReplConflict",
        ])

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
                if re.search(
                    FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                    attr_definition,
                ):
                    return True
                attr_lower = attr_definition.lower()
                return any(
                    attr_lower.startswith(prefix)
                    for prefix in FlextLdifConstants.LdapServerDetection.DS389_ATTRIBUTE_PREFIXES
                )
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                if re.search(
                    FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                    attr_definition.oid,
                ):
                    return True
                attr_name_lower = attr_definition.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in FlextLdifConstants.LdapServerDetection.DS389_ATTRIBUTE_PREFIXES
                )
            return False

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect 389 DS objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
                if re.search(
                    FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                    oc_definition,
                ):
                    return True
                oc_lower = oc_definition.lower()
                return oc_lower in FlextLdifConstants.LdapServerDetection.DS389_OBJECTCLASS_NAMES
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                if re.search(
                    FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                    oc_definition.oid,
                ):
                    return True
                oc_name_lower = oc_definition.name.lower()
                return (
                    oc_name_lower
                    in FlextLdifConstants.LdapServerDetection.DS389_OBJECTCLASS_NAMES
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
                    FlextLdifConstants.LdapServers.DS_389
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
                    oc_data, server_type=FlextLdifConstants.LdapServers.DS_389
                )
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifConstants.LdapServers.DS_389
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifConstants.LdapServers.DS_389
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI quirk."""

        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        def _can_handle_acl(
            self, acl_line: str | FlextLdifModels.Acl
        ) -> bool:
            """Detect 389 DS ACI lines."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                if attr_name.strip().lower() == FlextLdifConstants.AclKeys.ACI:
                    return True
                return normalized.lower().startswith("(version")
            if isinstance(acl_line, FlextLdifModels.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False

                attr_name, _, _ = normalized.partition(":")
                if attr_name.strip().lower() == FlextLdifConstants.AclKeys.ACI:
                    return True

                return normalized.lower().startswith("(version")
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse 389 DS ACI definition."""
            try:
                _attr_name, content = self._splitacl_line(acl_line)
                acl_name_match = re.search(
                    r"acl\s+\"([^\"]+)\"",
                    content,
                    re.IGNORECASE,
                )
                permissions_match = re.search(
                    r"allow\s*\(([^)]+)\)",
                    content,
                    re.IGNORECASE,
                )
                permissions = (
                    [perm.strip() for perm in permissions_match.group(1).split(",")]
                    if permissions_match
                    else []
                )
                target_attr_match = re.search(
                    r"targetattr\s*=\s*\"([^\"]+)\"",
                    content,
                    re.IGNORECASE,
                )
                userdn_matches = re.findall(
                    r"userdn\s*=\s*\"([^\"]+)\"",
                    content,
                    re.IGNORECASE,
                )

                # Parse target attributes, handling both space and comma separation
                target_attributes: list[str] = []
                if target_attr_match:
                    # Replace commas with spaces and split
                    attr_string = target_attr_match.group(1).replace(",", " ")
                    target_attributes = [
                        attr.strip() for attr in attr_string.split() if attr.strip()
                    ]

                # Extract target DN from the ACI target clause
                # 389 DS ACLs use: target = "dn:<dn_pattern>"
                target_dn = "*"  # Default wildcard
                target_match = re.search(
                    r"target\s*=\s*\"([^\"]+)\"",
                    content,
                    re.IGNORECASE,
                )
                if target_match:
                    target_clause = target_match.group(1)
                    # Parse DN from "dn:<dn_pattern>" format
                    if target_clause.lower().startswith("dn:"):
                        target_dn = target_clause[3:]  # Extract after "dn:"
                    else:
                        target_dn = target_clause

                # Build Acl model
                acl = FlextLdifModels.Acl(
                    name=acl_name_match.group(1) if acl_name_match else "389 DS ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn=target_dn,  # DS389: extracted from target clause
                        attributes=target_attributes,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="userdn",
                        subject_value=(
                            userdn_matches[0] if userdn_matches else "ldap:///anyone"
                        ),
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        # DS389: set permissions based on parsed permission list
                        read="read" in permissions,
                        write="write" in permissions,
                        add="add" in permissions,
                        delete="delete" in permissions,
                        search="search" in permissions,
                        compare="compare" in permissions,
                    ),
                    server_type=FlextLdifConstants.LdapServers.DS_389,
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
                    acl_str = f"aci: {acl_data.raw_acl}"
                    return FlextResult[str].ok(acl_str)

                # Otherwise build from model fields
                acl_name = acl_data.name or "Anonymous ACL"

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
                    else "ldap:///anyone"
                )

                # Build ACI string from structured fields
                parts = ["(version 3.0)", f'acl "{acl_name}"']
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
                for marker in FlextLdifConstants.LdapServerDetection.DS389_DN_MARKERS
            ):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(
                    tuple(
                        FlextLdifConstants.LdapServerDetection.DS389_ATTRIBUTE_PREFIXES
                    )
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
                    in FlextLdifConstants.LdapServerDetection.DS389_OBJECTCLASS_NAMES
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
                metadata.extensions[FlextLdifConstants.QuirkMetadataKeys.IS_CONFIG_ENTRY] = (
                    FlextLdifConstants.DnPatterns.CN_CONFIG.lower() in dn_lower
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
