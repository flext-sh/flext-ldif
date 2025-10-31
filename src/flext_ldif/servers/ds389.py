"""389 Directory Server quirks implementation."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # Top-level configuration for 389 DS quirks
    server_type = FlextLdifConstants.LdapServers.DS_389
    priority = 15

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

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
        priority: ClassVar[int] = 15

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect 389 DS attribute definitions using centralized constants."""
            if re.search(
                FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                attribute.oid,
            ):
                return True
            attr_name_lower = attribute.name.lower()
            return any(
                attr_name_lower.startswith(prefix)
                for prefix in FlextLdifConstants.LdapServerDetection.DS389_ATTRIBUTE_PREFIXES
            )

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect 389 DS objectClass definitions using centralized constants."""
            if re.search(
                FlextLdifConstants.LdapServerDetection.DS389_OID_PATTERN,
                objectclass.oid,
            ):
                return True
            oc_name_lower = objectclass.name.lower()
            return (
                oc_name_lower
                in FlextLdifConstants.LdapServerDetection.DS389_OBJECTCLASS_NAMES
            )

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add 389 DS metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with 389 DS metadata

            """
            result = super().parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifConstants.LdapServers.DS_389
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add 389 DS metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with 389 DS metadata

            """
            result = super().parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Use FlextLdifUtilities for common objectClass validation
                FlextLdifUtilities.ObjectClassValidator.fix_missing_sup(
                    oc_data, server_type=FlextLdifConstants.LdapServers.DS_389
                )
                FlextLdifUtilities.ObjectClassValidator.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifConstants.LdapServers.DS_389
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    FlextLdifConstants.LdapServers.DS_389
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to 389 DS format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with 389 DS metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                FlextLdifConstants.LdapServers.DS_389
            )
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to 389 DS format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with 389 DS metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                FlextLdifConstants.LdapServers.DS_389
            )
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(result_data)

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
            priority: ClassVar[int] = 15

            def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer 389 DS Acl's parse_acl implementation."""
                # Create an instance of the outer FlextLdifServersDs389.Acl and use its parse_acl
                outer_acl = FlextLdifServersDs389.Acl()
                return outer_acl.parse_acl(acl_line)

            def write_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[str]:
                """Delegate to outer ds389 Acl's write_acl_to_rfc implementation."""
                outer_acl = FlextLdifServersDs389.Acl()
                return outer_acl.write_acl_to_rfc(acl_data)

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
            priority: ClassVar[int] = 15

            def process_entry(
                self, entry: FlextLdifModels.Entry
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer ds389 Entry's process_entry implementation."""
                outer_entry = FlextLdifServersDs389.Entry()
                return outer_entry.process_entry(entry)

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI quirk."""

        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Detect 389 DS ACI lines."""
            if not isinstance(acl, FlextLdifModels.Acl) or not acl.raw_acl:
                return False
            normalized = acl.raw_acl.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if attr_name.strip().lower() == FlextLdifConstants.DictKeys.ACI:
                return True

            return normalized.lower().startswith("(version")

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
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

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert 389 DS ACL to RFC representation."""
            try:
                # Convert 389 DS ACL to RFC format by changing server_type
                # The ACL structure is compatible between 389 DS and RFC
                rfc_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.RFC},
                )
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"389 Directory Server ACL→RFC conversion failed: {exc}",
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert RFC ACL to 389 DS representation."""
            try:
                # Convert RFC to DS389 format by changing server_type
                # The ACL structure is compatible between RFC and 389 DS
                ds_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.DS_389},
                )
                return FlextResult[FlextLdifModels.Acl].ok(ds_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→389 Directory Server ACL conversion failed: {exc}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.DS_389
        priority: ClassVar[int] = 15

        def can_handle_entry(self, entry: FlextLdifModels.Entry) -> bool:
            """Detect 389 DS-specific entries."""
            if not isinstance(entry, FlextLdifModels.Entry):
                return False

            attributes = entry.attributes.attributes
            entry_dn = entry.dn.value

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
                metadata.extensions[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] = (
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

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Strip 389 DS metadata before RFC processing."""
            try:
                attributes = entry_data.attributes.attributes.copy()
                attributes.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                attributes.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)

                rfc_entry = entry_data.model_copy(
                    update={
                        "attributes": FlextLdifModels.LdifAttributes(
                            attributes=attributes
                        )
                    }
                )

                return FlextResult[FlextLdifModels.Entry].ok(
                    rfc_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"389 Directory Server entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersDs389"]
