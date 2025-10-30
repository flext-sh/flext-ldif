"""389 Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersDs389(FlextLdifServersRfc):
    """389 Directory Server quirks implementation."""

    # Top-level configuration for 389 DS quirks
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
    priority: ClassVar[int] = 15

    def __init__(self) -> None:
        """Initialize 389 DS quirks."""
        super().__init__()
        self._schema = self.Schema()

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Delegate to schema instance."""
        return self._schema.can_handle_attribute(attr_definition)

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self._schema.parse_attribute(attr_definition)

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Delegate to schema instance."""
        return self._schema.can_handle_objectclass(oc_definition)

    def parse_objectclass(
        self,
        oc_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self._schema.parse_objectclass(oc_definition)

    def convert_attribute_to_rfc(
        self,
        attribute: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self._schema.convert_attribute_to_rfc(attribute)

    def convert_attribute_from_rfc(
        self,
        attribute: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self._schema.convert_attribute_from_rfc(attribute)

    def convert_objectclass_to_rfc(
        self,
        objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self._schema.convert_objectclass_to_rfc(objectclass)

    def convert_objectclass_from_rfc(
        self,
        objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Delegate to schema instance."""
        return self._schema.convert_objectclass_from_rfc(objectclass)

    def write_attribute_to_rfc(
        self,
        attribute: FlextLdifModels.SchemaAttribute,
    ) -> FlextResult[str]:
        """Delegate to schema instance."""
        return self._schema.write_attribute_to_rfc(attribute)

    def write_objectclass_to_rfc(
        self,
        objectclass: FlextLdifModels.SchemaObjectClass,
    ) -> FlextResult[str]:
        """Delegate to schema instance."""
        return self._schema.write_objectclass_to_rfc(objectclass)

    # Quirk detection patterns and prefixes for 389 DS (shared with Schema and Entry)
    DS389_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b2\.16\.840\.1\.113730\.",
        re.IGNORECASE,
    )
    DS389_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "nsslapd-",
        "nsds",
        "nsuniqueid",
    ])
    DS389_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "nscontainer",
        "nsperson",
        "nsds5replica",
        "nsds5replicationagreement",
    ])

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Red Hat / 389 Directory Server."""

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
        priority: ClassVar[int] = 15

        DS389_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b2\.16\.840\.1\.113730\.",
            re.IGNORECASE,
        )
        DS389_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])
        DS389_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "nscontainer",
            "nsperson",
            "nsds5replica",
            "nsds5replicationagreement",
        ])

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Detect 389 DS attribute definitions."""
            attr_lower = attr_definition.lower()
            if self.DS389_OID_PATTERN.search(attr_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(tuple(self.DS389_ATTRIBUTE_PREFIXES))
                for name in name_matches
            ):
                return True

            return any(prefix in attr_lower for prefix in self.DS389_ATTRIBUTE_PREFIXES)

        # --------------------------------------------------------------------- #
        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
        # --------------------------------------------------------------------- #
        # These methods are inherited from RFC base class:
        # - parse_attribute(): Uses RFC parser
        # - parse_objectclass(): Uses RFC parser
        # - convert_attribute_to_rfc(): RFC conversion
        # - convert_objectclass_to_rfc(): RFC conversion
        # - convert_attribute_from_rfc(): RFC conversion
        # - convert_objectclass_from_rfc(): RFC conversion
        # - write_attribute_to_rfc(): RFC writer
        # - write_objectclass_to_rfc(): RFC writer
        # - should_filter_out_attribute(): Returns False (no filtering)
        # - should_filter_out_objectclass(): Returns False (no filtering)
        #
        # Only can_handle_* methods are overridden with 389DS-specific logic.
        #

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Detect 389 DS objectClass definitions."""
            if self.DS389_OID_PATTERN.search(oc_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower() in self.DS389_OBJECTCLASS_NAMES for name in name_matches
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

    class Acl(FlextLdifServersRfc.Acl):
        """389 Directory Server ACI quirk."""

        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect 389 DS ACI lines."""
            normalized = acl_line.strip()
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

                # Build Acl model (simplified for DS389 stub)
                acl = FlextLdifModels.Acl(
                    name=acl_name_match.group(1) if acl_name_match else "389 DS ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn="*",  # DS389 stub - not extracted, use wildcard
                        attributes=target_attributes,
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="userdn",
                        subject_value=(
                            userdn_matches[0] if userdn_matches else "ldap:///anyone"
                        ),
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        # DS389 stub - set permissions based on parsed list
                        read="read" in permissions,
                        write="write" in permissions,
                        add="add" in permissions,
                        delete="delete" in permissions,
                        search="search" in permissions,
                        compare="compare" in permissions,
                    ),
                    server_type=FlextLdifConstants.ServerTypes.DS_389,
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
                # For stub, pass through Acl model with server_type cleared
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
                # For stub, pass through Acl model with DS389 server_type
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
                # For DS389 stub, use raw_acl if available
                if acl_data.raw_acl:
                    acl_str = f"aci: {acl_data.raw_acl}"
                    return FlextResult[str].ok(acl_str)

                # Otherwise build from model fields
                acl_name = acl_data.name or "Anonymous ACL"

                # Build permissions list from flags
                permissions: list[str] = []
                if acl_data.permissions:
                    if acl_data.permissions.read:
                        permissions.append("read")
                    if acl_data.permissions.write:
                        permissions.append("write")
                    if acl_data.permissions.add:
                        permissions.append("add")
                    if acl_data.permissions.delete:
                        permissions.append("delete")
                    if acl_data.permissions.search:
                        permissions.append("search")
                    if acl_data.permissions.compare:
                        permissions.append("compare")

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

        DS389_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=config",
            "cn=monitor",
            "cn=changelog",
        ])
        DS389_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.DS_389
        priority: ClassVar[int] = 15

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with 389DS-specific logic:
        # - can_handle_entry(): Detects 389DS entries by DN/attributes
        # - process_entry(): Normalizes 389DS entries with metadata
        # - convert_entry_to_rfc(): Converts 389DS entries to RFC format

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Detect 389 DS-specific entries."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.DS389_DN_MARKERS):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(tuple(self.DS389_ATTRIBUTE_PREFIXES))
                for attr in normalized_attrs
            ):
                return True

            object_classes_raw = attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
                [],
            )
            object_classes = (
                object_classes_raw
                if isinstance(object_classes_raw, list)
                else [object_classes_raw]
            )
            return bool(
                any(
                    str(oc).lower() in FlextLdifServersDs389.DS389_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise 389 DS entries and attach metadata."""
            try:
                dn_lower = entry_dn.lower()
                object_classes_raw = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
                )
                object_classes = (
                    object_classes_raw
                    if isinstance(object_classes_raw, list)
                    else [object_classes_raw]
                )

                processed_attributes: dict[str, object] = {}
                for attr_name, attr_value in attributes.items():
                    if isinstance(attr_value, bytes):
                        processed_attributes[attr_name] = base64.b64encode(
                            attr_value,
                        ).decode("ascii")
                    else:
                        processed_attributes[attr_name] = attr_value

                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.DS_389,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=config"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"389 Directory Server entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Strip 389 DS metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"389 Directory Server entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersDs389"]
