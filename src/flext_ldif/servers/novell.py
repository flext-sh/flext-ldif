"""Novell eDirectory Quirks - Stub Implementation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

Provides detection and lightweight parsing for Novell/Micro Focus eDirectory
schema definitions, ACL values, and operational entries. eDirectory uses the
Novell OID namespace (2.16.840.1.113719) and exposes a number of attributes
prefixed with ``nspm`` or ``login`` that do not appear in RFC-compliant LDAP
servers.

Architecture:
- Parsers: LDIF → RFC parse_entry() → Entry Model RFC (inherited, no overrides)
- Writers: Entry Model RFC → RFC _write_entry() → LDIF (inherited, no conversions)
- RFC baseline: 100% RFC 2849/4512 compliance without Novell-specific transformations
- Auto-discovery: Server detection via quirks metadata (Novell OID namespace)

This is a stub implementation. Server-specific conversions can be added in _write_entry()
when Novell eDirectory-specific LDIF format requirements are identified.
"""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory quirks implementation."""

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Novell eDirectory quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "novell"
        PRIORITY: ClassVar[int] = 20

        CANONICAL_NAME: ClassVar[str] = "novell_edirectory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["novell", "novell_edirectory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["novell_edirectory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "novell_edirectory",
                "rfc",
            ],
        )

        # Novell eDirectory ACL format constants
        ACL_FORMAT: ClassVar[str] = "aci"  # Novell uses standard ACI
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "aci"  # ACL attribute name

        # Novell eDirectory operational attributes (server-specific, extends RFC)
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "GUID",
                "createTimestamp",
                "modifyTimestamp",
            ],
        )

        # Detection constants (server-specific)
        DETECTION_OID_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113719\."
        DETECTION_PATTERN: ClassVar[str] = r"2\.16\.840\.1\.113719\."
        DETECTION_WEIGHT: ClassVar[int] = 6
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "guid",
                "logintime",
                "logingraceremaining",
                "ndsloginproperties",
            ],
        )
        DETECTION_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset(
            [
                "nspm",
                "login",
                "dirxml-",
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "ndsperson",
                "nspmpasswordpolicy",
                "ndsserver",
                "ndstree",
                "ndsloginproperties",
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "ou=services",
                "ou=apps",
                "ou=system",
            ],
        )
        DETECTION_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "nspmpasswordpolicy",
                "nspmpasswordpolicydn",
                "logindisabled",
                "loginexpirationtime",
            ],
        )

        # Novell ACL parsing indices (migrated from c.Ldif.Acl)
        # Format: scope#trustee#rights
        # Example: "[Entry Rights]#cn=Admin,o=Example#[BCDRSE]"
        # Index 0 = scope, Index 1 = trustee, Index 2 = rights
        NOVELL_SEGMENT_INDEX_TRUSTEE: ClassVar[int] = 1
        NOVELL_SEGMENT_INDEX_RIGHTS: ClassVar[int] = 2

        # Novell eDirectory specific attributes (migrated from FlextLdifConstants)
        NOVELL_SPECIFIC: ClassVar[frozenset[str]] = frozenset(
            [
                "guid",
                "nspmpasswordpolicy",
                "login",
                "nspmldapaccessgroup",
                "nspmldapuser",
                "ndsserver",
                "ndstree",
                "ndsloginproperties",
            ],
        )

        # Schema-specific constants (migrated from nested Schema class)
        SCHEMA_ATTRIBUTE_NAME_REGEX: ClassVar[str] = r"NAME\s+\(?\s*'([^']+)'"

        # ACL default values (migrated from _parse_acl method)
        ACL_DEFAULT_SUBJECT_TYPE: ClassVar[str] = "trustee"
        ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN: ClassVar[str] = "unknown"

        # ACL attribute name (migrated from _write_acl method)
        ACL_ATTRIBUTE_NAME_WRITE: ClassVar[str] = (
            "acl"  # Novell standard attribute name
        )

        # ACL-specific constants (migrated from nested Acl class)
        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
                "acl",
                "inheritedacl",
            ],
        )
        ACL_SEGMENT_SEPARATOR: ClassVar[str] = "#"
        ACL_DEFAULT_NAME: ClassVar[str] = "Novell eDirectory ACL"

        # Novell rights parsing constants (migrated from _parse_acl method)
        NOVELL_RIGHT_BROWSE: ClassVar[str] = "B"  # Browse permission
        NOVELL_RIGHT_COMPARE: ClassVar[str] = "C"  # Compare permission
        NOVELL_RIGHT_DELETE: ClassVar[str] = "D"  # Delete permission
        NOVELL_RIGHT_READ: ClassVar[str] = "R"  # Read permission
        NOVELL_RIGHT_WRITE: ClassVar[str] = "W"  # Write permission
        NOVELL_RIGHT_ADD: ClassVar[str] = "A"  # Add permission
        NOVELL_RIGHT_SUPERVISOR: ClassVar[str] = "S"  # Supervisor permission
        NOVELL_RIGHT_ENTRY: ClassVar[str] = "E"  # Entry permission
        NOVELL_RIGHTS_BRACKET_OPEN: ClassVar[str] = "["  # Rights bracket start
        NOVELL_RIGHTS_BRACKET_CLOSE: ClassVar[str] = "]"  # Rights bracket end
        NOVELL_PERMISSION_SUPERVISOR: ClassVar[str] = (
            "supervisor"  # Novell-specific permission name
        )
        NOVELL_PERMISSION_ENTRY: ClassVar[str] = (
            "entry"  # Novell-specific permission name
        )

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.Ldif.AclPermission,
        # c.Ldif.AclAction, and c.Ldif.Encoding directly
        # Note: Novell-specific permissions (object_rights, attr_rights) should be
        # added to c.Ldif.AclPermission if needed across the codebase

    # =========================================================================
    # Server identification (defined in Constants nested class above)
    # =========================================================================
    # server_type and priority are accessed via Constants.SERVER_TYPE
    # and Constants.PRIORITY respectively

    class Schema(FlextLdifServersRfc.Schema):
        """Novell eDirectory schema quirk."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect eDirectory attribute definitions using Constants."""
            if not isinstance(attr_definition, str):
                # Check using protocol/structural typing
                if hasattr(attr_definition, "oid") and hasattr(attr_definition, "name"):
                    return u.Ldif.Server.matches_server_patterns(
                        value=attr_definition,
                        oid_pattern=FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                        detection_names=FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                        use_prefix_match=True,
                    )
                return False
            # For string definitions, extract NAME and check prefix match
            attr_lower = attr_definition.lower()
            if re.search(
                FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                attr_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersNovell.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(
                    tuple(
                        FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES,
                    ),
                )
                for name in name_matches
            ):
                return True
            return any(
                prefix in attr_lower
                for prefix in FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_PREFIXES
            )

        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
        # These methods are inherited from RFC base class:
        # - _parse_attribute(): Uses RFC parser
        # - _parse_objectclass(): Uses RFC parser
        # - _write_attribute(): RFC writer
        # - _write_objectclass(): RFC writer
        # - should_filter_out_attribute(): Returns False (no filtering)
        # - should_filter_out_objectclass(): Returns False (no filtering)
        #
        # Only can_handle_* methods are overridden with Novell-specific logic.
        #

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect eDirectory objectClass definitions using Constants."""
            if not isinstance(oc_definition, str):
                if hasattr(oc_definition, "oid") and hasattr(oc_definition, "name"):
                    return u.Ldif.Server.matches_server_patterns(
                        value=oc_definition,
                        oid_pattern=FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                        detection_names=FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES,
                    )
                return False
            # For string definitions, extract NAME and check exact match
            if re.search(
                FlextLdifServersNovell.Constants.DETECTION_OID_PATTERN,
                oc_definition,
            ):
                return True
            name_matches = re.findall(
                FlextLdifServersNovell.Constants.SCHEMA_ATTRIBUTE_NAME_REGEX,
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower()
                in FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES
                for name in name_matches
            )

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add Novell metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                r with SchemaAttribute marked with Novell metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return r[m.Ldif.SchemaAttribute].ok(
                    attr_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add Novell metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                r with SchemaObjectClass marked with Novell metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                return r[m.Ldif.SchemaObjectClass].ok(
                    oc_data.model_copy(
                        update={"metadata": metadata},
                    ),
                )
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL quirk.

        Override: Extends base RFC Acl with Novell eDirectory-specific ACL parsing.
        """

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is a Novell eDirectory ACL.

            Override RFC's always-true behavior to check Novell-specific markers.

            Args:
                acl_line: ACL line string or Acl model

            Returns:
                True if this is Novell eDirectory ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Detect eDirectory ACL values."""
            if isinstance(acl_line, str):
                if not acl_line or not acl_line.strip():
                    return False
                normalized = acl_line.strip()
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAMES
                )
            # Check using duck typing/protocol for Acl model
            if hasattr(acl_line, "raw_acl") and acl_line.raw_acl:
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return (
                    attr_name.strip().lower()
                    in FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAMES
                )
            return False

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse eDirectory ACL definition."""
            try:
                # Use static method correctly
                attr_name, content = self.__class__.splitacl_line(acl_line)
                if not content:
                    return r[m.Ldif.Acl].fail("Empty ACL content")
                segments = [
                    segment
                    for segment in content.split(
                        FlextLdifServersNovell.Constants.ACL_SEGMENT_SEPARATOR,
                    )
                    if segment
                ]

                # Extract scope (target DN) from first segment
                scope = segments[0] if segments else None

                # Extract trustee (subject) from segment at trustee index
                trustee = (
                    segments[
                        FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
                    ]
                    if len(segments)
                    > FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_TRUSTEE
                    else None
                )

                # Extract rights (permissions) from segments at rights index
                # Rights are at index 2, so we get the segment at that index
                rights_str = (
                    segments[
                        FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS
                    ]
                    if len(segments)
                    > FlextLdifServersNovell.Constants.NOVELL_SEGMENT_INDEX_RIGHTS
                    else ""
                )
                # Parse rights string - Novell uses character codes for permissions
                # Business Rule: Novell eDirectory ACLs use single-character codes
                # to represent permissions in rights segments (e.g., "RW" = read+write)
                # Implication: Character-by-character parsing is required for remote
                # auditing to track which permissions were granted/denied
                char_mapping: dict[str, list[str]] = {
                    "B": [c.Ldif.RfcAclPermission.SEARCH],
                    "C": [c.Ldif.RfcAclPermission.COMPARE],
                    "D": [c.Ldif.RfcAclPermission.DELETE],
                    "R": [c.Ldif.RfcAclPermission.READ],
                    "W": [c.Ldif.RfcAclPermission.WRITE],
                    "A": [c.Ldif.RfcAclPermission.ADD],
                    "S": ["supervisor"],  # Novell-specific
                    "E": ["entry"],  # Novell-specific
                }
                # Parse rights string character by character
                rights: list[str] = []
                for char in rights_str:
                    char_upper = char.upper()
                    if char_upper in char_mapping:
                        rights.extend(char_mapping[char_upper])

                # Extract attributes from rights segments
                # Novell eDirectory ACLs may specify attribute names in the rights segments
                attributes: list[str] = []
                for right_segment in rights:
                    # Look for attribute specifications in rights segments
                    # Format might be like "attr:read" or attribute names listed
                    segment_str = str(right_segment).strip()
                    if segment_str and ":" in segment_str:
                        # Parse potential attribute specifications
                        parts = segment_str.split(":")
                        if parts[0].strip():
                            # First part before colon might be attribute name
                            attr_name = parts[0].strip()
                            # Add if it looks like an attribute name (not a permission)
                            if attr_name.lower() not in u.Enum.values(
                                c.Ldif.RfcAclPermission,
                            ):
                                attributes.append(attr_name)

                # Build Acl model with nested models
                acl = m.Ldif.Acl(
                    name=FlextLdifServersNovell.Constants.ACL_DEFAULT_NAME,
                    target=m.Ldif.AclTarget(
                        target_dn=scope or "",  # Novell: scope is target DN
                        attributes=attributes,  # Novell: extracted from rights segments
                    ),
                    subject=m.Ldif.AclSubject(
                        # Business Rule: Novell eDirectory uses "trustee" concept
                        # Trustee is a DN string - use "user" as the subject_type
                        # Implication: Remote auditing can track trustee DNs via subject_value
                        subject_type="user",
                        subject_value=(
                            trustee
                            or FlextLdifServersNovell.Constants.ACL_DEFAULT_SUBJECT_VALUE_UNKNOWN
                        ),
                    ),
                    permissions=m.Ldif.AclPermissions(
                        **self._build_novell_permissions_from_rights(
                            rights,
                            {
                                "read": c.Ldif.RfcAclPermission.READ,
                                "write": c.Ldif.RfcAclPermission.WRITE,
                                "add": c.Ldif.RfcAclPermission.ADD,
                                "delete": c.Ldif.RfcAclPermission.DELETE,
                                "search": c.Ldif.RfcAclPermission.SEARCH,
                                "compare": c.Ldif.RfcAclPermission.COMPARE,
                            },
                        ),
                    ),
                    metadata=m.Ldif.QuirkMetadata.create_for(
                        self._get_server_type(),
                        extensions=m.Ldif.DynamicMetadata(
                            original_format=acl_line,
                        ),
                    ),
                    raw_acl=acl_line,
                )
                return r[m.Ldif.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Acl].fail(
                    f"Novell eDirectory ACL parsing failed: {exc}",
                )

        def _build_novell_permissions_from_rights(
            self,
            rights: list[str],
            permission_name_map: dict[str, str],
        ) -> dict[str, bool]:
            """Build AclPermissions dict from parsed rights list.

            Business Rule: Novell eDirectory permissions are mapped from parsed
            rights strings to boolean flags in AclPermissions model.
            Implication: Remote auditing can track which specific permissions
            were granted by examining the rights list and mapping.

            Args:
                rights: List of permission strings parsed from rights segment
                permission_name_map: Mapping from canonical permission names to values

            Returns:
                Dictionary of permission flags for AclPermissions model

            """
            # Build reverse mapping: permission value -> canonical name
            reverse_map: dict[str, str] = {v: k for k, v in permission_name_map.items()}
            # Initialize all permissions to False
            perms_dict: dict[str, bool] = {
                "read": False,
                "write": False,
                "add": False,
                "delete": False,
                "search": False,
                "compare": False,
            }
            # Set permissions to True if found in rights list
            for right in rights:
                if right in reverse_map:
                    canonical_name = reverse_map[right]
                    if canonical_name in perms_dict:
                        perms_dict[canonical_name] = True
            return perms_dict

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format.

            Novell eDirectory ACLs use "#" delimited segments:
            scope#trustee#rights#...
            Accepts base Acl type for polymorphism - all Acl subclasses are valid.
            """
            try:
                # Use direct field access on Acl model
                acl_attribute = (
                    FlextLdifServersNovell.Constants.ACL_ATTRIBUTE_NAME_WRITE
                )

                # Check for raw_acl first (original ACL string)
                if acl_data.raw_acl:
                    return r[str].ok(acl_data.raw_acl)

                # Build from model fields
                parts: list[str] = []

                # Add scope (target DN)
                if acl_data.target and acl_data.target.target_dn:
                    parts.append(acl_data.target.target_dn)

                # Add trustee (subject value)
                if acl_data.subject and acl_data.subject.subject_value:
                    parts.append(acl_data.subject.subject_value)

                # Add rights - collect active permissions from permissions dict
                # Map canonical permission names to Novell format
                permission_map = {
                    "read": c.Ldif.RfcAclPermission.READ,
                    "write": c.Ldif.RfcAclPermission.WRITE,
                    "add": c.Ldif.RfcAclPermission.ADD,
                    "delete": c.Ldif.RfcAclPermission.DELETE,
                    "search": c.Ldif.RfcAclPermission.SEARCH,
                    "compare": c.Ldif.RfcAclPermission.COMPARE,
                }
                active_perms: list[str] = []
                if acl_data.permissions:
                    # AclPermissions is a Pydantic model, convert to dict for iteration
                    perms_dict = acl_data.permissions.model_dump()
                    for perm_name, perm_value in perms_dict.items():
                        # Only include permissions that are True (allowed)
                        if perm_value is True and perm_name in permission_map:
                            active_perms.append(permission_map[perm_name])
                parts.extend(active_perms)

                # Build ACL string
                acl_content = "#".join(parts) if parts else ""
                acl_str = (
                    f"{acl_attribute}: {acl_content}"
                    if acl_content
                    else f"{acl_attribute}:"
                )

                return r[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return r[str].fail(
                    f"Novell eDirectory ACL write failed: {exc}",
                )

        @staticmethod
        def splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Novell eDirectory entry quirk."""

        # Entry detection uses Constants.DETECTION_DN_MARKERS and Constants.DETECTION_ATTRIBUTE_MARKERS

        def model_post_init(self, _context: object, /) -> None:
            """Initialize eDirectory entry quirk."""

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Novell eDirectory-specific logic:
        # - can_handle(): Detects eDirectory entries by DN/attributes
        # - _parse_entry(): Normalizes eDirectory entries with metadata

        def can_handle(
            self,
            entry_dn: str,
            attributes: dict[str, list[str]],
        ) -> bool:
            """Detect eDirectory-specific entries."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersNovell.Constants.DETECTION_DN_MARKERS
            ):
                return True

            # attributes is already dict[str, list[str]], just need to normalize keys
            normalized_attrs = {
                name.lower(): values for name, values in attributes.items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifServersNovell.Constants.DETECTION_ATTRIBUTE_MARKERS
            ):
                return True

            # objectClasses is already list[str] in
            object_classes_raw = u.mapper().get(
                attributes,
                c.Ldif.DictKeys.OBJECTCLASS,
                default=[],
            )
            # Ensure object_classes is a list
            if isinstance(object_classes_raw, (list, tuple)):
                object_classes: list[str] = [str(item) for item in object_classes_raw]
            else:
                object_classes = []
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersNovell.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: m.Ldif.Entry,
        ) -> r[m.Ldif.Entry]:
            """Normalise eDirectory entries and expose metadata."""
            if not entry.attributes:
                return r[m.Ldif.Entry].ok(entry)

            attributes = entry.attributes.attributes.copy()
            try:
                # Get objectClasses (already list[str] in Attributes)
                object_classes_raw = u.mapper().get(
                    attributes,
                    c.Ldif.DictKeys.OBJECTCLASS,
                    default=[],
                )
                object_classes: list[str] = (
                    object_classes_raw if isinstance(object_classes_raw, list) else []
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Process binary values if any (convert bytes to base64 strings)
                processed_attributes: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    processed_values: list[str] = []
                    # Type annotation to help type checker understand bytes | str union
                    value: bytes | str
                    for value in attr_values:
                        # Explicitly handle both bytes and str types
                        str_value: str
                        if isinstance(value, bytes):
                            str_value = base64.b64encode(value).decode("ascii")
                        else:
                            str_value = str(value)
                        processed_values.append(str_value)
                    processed_attributes[attr_name] = processed_values

                # Add metadata attributes
                processed_attributes[c.Ldif.Domain.QuirkMetadataKeys.SERVER_TYPE] = [
                    self._get_server_type(),
                ]
                processed_attributes[c.Ldif.DictKeys.OBJECTCLASS] = object_classes

                # Create new Attributes directly
                new_attrs = m.Ldif.Attributes(
                    attributes=processed_attributes,
                )
                new_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )
                return r[m.Ldif.Entry].ok(new_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Entry].fail(
                    f"Novell eDirectory entry processing failed: {exc}",
                )
