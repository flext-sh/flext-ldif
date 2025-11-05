"""Novell eDirectory quirks implementation.

Provides detection and lightweight parsing for Novell/Micro Focus eDirectory
schema definitions, ACL values, and operational entries. eDirectory uses the
Novell OID namespace (2.16.840.1.113719) and exposes a number of attributes
prefixed with ``nspm`` or ``login`` that do not appear in RFC-compliant LDAP
servers.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import ClassVar, Final

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory quirks implementation."""

    # =========================================================================
    # Class-level attributes for server identification
    # =========================================================================
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
    priority: ClassVar[int] = 10

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Novell eDirectory quirk."""

        CANONICAL_NAME: ClassVar[str] = "novell_edirectory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["novell_edirectory", "novell"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["novell_edirectory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["novell_edirectory", "rfc"])

        # Novell eDirectory operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "GUID",
            "createTimestamp",
            "modifyTimestamp",
        ])

    def __init__(self) -> None:
        """Initialize Novell quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Pass server_type and priority to nested class instances
        object.__setattr__(self, "schema", self.Schema(server_type=self.server_type, priority=self.priority))
        object.__setattr__(self, "acl", self.Acl(server_type=self.server_type, priority=self.priority))
        object.__setattr__(self, "entry", self.Entry(server_type=self.server_type, priority=self.priority))

    # Quirk detection patterns and prefixes for Novell (shared with Schema and Entry)
    NOVELL_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b2\.16\.840\.1\.113719\.",
        re.IGNORECASE,
    )
    NOVELL_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "nspm",
        "login",
        "dirxml-",
    ])
    NOVELL_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "ndsperson",
        "nspmpasswordpolicy",
        "ndsserver",
        "ndstree",
        "ndsloginproperties",
    ])

    class Schema(FlextLdifServersRfc.Schema):
        """Novell eDirectory schema quirk."""

        NOVELL_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b2\.16\.840\.1\.113719\.",
            re.IGNORECASE,
        )
        NOVELL_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nspm",
            "login",
            "dirxml-",
        ])
        NOVELL_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ndsperson",
            "nspmpasswordpolicy",
            "ndsserver",
            "ndstree",
            "ndsloginproperties",
        ])
        ATTRIBUTE_NAME_REGEX: ClassVar[re.Pattern[str]] = re.compile(
            r"NAME\s+\(?\s*'([^']+)'",
            re.IGNORECASE,
        )

        def _can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect eDirectory attribute definitions."""
            if isinstance(attr_definition, str):
                attr_lower = attr_definition.lower()
                if self.NOVELL_OID_PATTERN.search(attr_definition):
                    return True

                name_matches = self.ATTRIBUTE_NAME_REGEX.findall(attr_definition)
                if any(
                    name.lower().startswith(tuple(self.NOVELL_ATTRIBUTE_PREFIXES))
                    for name in name_matches
                ):
                    return True

                return any(
                    prefix in attr_lower for prefix in self.NOVELL_ATTRIBUTE_PREFIXES
                )
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                if self.NOVELL_OID_PATTERN.search(attr_definition.oid):
                    return True
                attr_name_lower = attr_definition.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in self.NOVELL_ATTRIBUTE_PREFIXES
                )
            return False

        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
        # These methods are inherited from RFC base class:
        # - _parse_attribute(): Uses RFC parser
        # - _parse_objectclass(): Uses RFC parser
        # - convert_attribute_from_rfc(): RFC conversion
        # - convert_objectclass_from_rfc(): RFC conversion
        # - _write_attribute(): RFC writer
        # - _write_objectclass(): RFC writer
        # - should_filter_out_attribute(): Returns False (no filtering)
        # - should_filter_out_objectclass(): Returns False (no filtering)
        #
        # Only _can_handle_* methods are overridden with Novell-specific logic.
        #

        def _can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect eDirectory objectClass definitions."""
            if isinstance(oc_definition, str):
                if self.NOVELL_OID_PATTERN.search(oc_definition):
                    return True

                name_matches = self.ATTRIBUTE_NAME_REGEX.findall(oc_definition)
                return any(
                    name.lower() in self.NOVELL_OBJECTCLASS_NAMES
                    for name in name_matches
                )
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                if self.NOVELL_OID_PATTERN.search(oc_definition.oid):
                    return True
                oc_name_lower = oc_definition.name.lower()
                return oc_name_lower in self.NOVELL_OBJECTCLASS_NAMES
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Novell metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Novell metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "novell_edirectory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add Novell metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Novell metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "novell_edirectory"
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to Novell format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with Novell metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                "novell_edirectory"
            )
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to Novell format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with Novell metadata

            """
            return FlextLdifServersRfc.SchemaConverter.set_quirk_type(
                rfc_data, self.server_type
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])

        def _can_handle_acl(
            self, acl_line: str | FlextLdifModels.Acl
        ) -> bool:
            """Detect eDirectory ACL values."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return attr_name.strip().lower() in self.ACL_ATTRIBUTE_NAMES
            if isinstance(acl_line, FlextLdifModels.Acl):
                normalized = acl_line.raw_acl.strip() if acl_line.raw_acl else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                return attr_name.strip().lower() in self.ACL_ATTRIBUTE_NAMES
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse eDirectory ACL definition."""
            try:
                _, content = self._splitacl_line(acl_line)
                segments = [segment for segment in content.split("#") if segment]

                # Extract scope (target DN) from first segment
                scope = segments[0] if segments else None

                # Extract trustee (subject) from segment at trustee index
                trustee = (
                    segments[FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_TRUSTEE]
                    if len(segments)
                    > FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_TRUSTEE
                    else None
                )

                # Extract rights (permissions) from segments after rights index
                rights = (
                    segments[FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_RIGHTS :]
                    if len(segments)
                    > FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_RIGHTS
                    else []
                )

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
                            if (
                                attr_name.lower()
                                not in FlextLdifConstants.PermissionNames.ALL_PERMISSIONS
                            ):
                                attributes.append(attr_name)

                # Build Acl model with nested models
                acl = FlextLdifModels.Acl(
                    name="Novell eDirectory ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn=scope or "",  # Novell: scope is target DN
                        attributes=attributes,  # Novell: extracted from rights segments
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="trustee",
                        subject_value=trustee or "unknown",
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read=FlextLdifConstants.PermissionNames.READ in rights
                        if isinstance(rights, list)
                        else False,
                        write=FlextLdifConstants.PermissionNames.WRITE in rights
                        if isinstance(rights, list)
                        else False,
                        add=FlextLdifConstants.PermissionNames.ADD in rights
                        if isinstance(rights, list)
                        else False,
                        delete=(
                            FlextLdifConstants.PermissionNames.DELETE in rights
                            if isinstance(rights, list)
                            else False
                        ),
                        search=(
                            FlextLdifConstants.PermissionNames.SEARCH in rights
                            if isinstance(rights, list)
                            else False
                        ),
                        compare=(
                            FlextLdifConstants.PermissionNames.COMPARE in rights
                            if isinstance(rights, list)
                            else False
                        ),
                    ),
                    server_type="novell_edirectory",
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Novell eDirectory ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Novell eDirectory ACLs use "#" delimited segments:
            scope#trustee#rights#...
            """
            try:
                # Use direct field access on Acl model
                acl_attribute = "acl"  # Novell standard attribute name

                # Check for raw_acl first (original ACL string)
                if acl_data.raw_acl:
                    return FlextResult[str].ok(acl_data.raw_acl)

                # Build from model fields
                parts: list[str] = []

                # Add scope (target DN)
                if acl_data.target and acl_data.target.target_dn:
                    parts.append(acl_data.target.target_dn)

                # Add trustee (subject value)
                if acl_data.subject and acl_data.subject.subject_value:
                    parts.append(acl_data.subject.subject_value)

                # Add rights (permissions) as individual strings
                if acl_data.permissions:
                    perms = acl_data.permissions
                    if perms.read:
                        parts.append(FlextLdifConstants.PermissionNames.READ)
                    if perms.write:
                        parts.append(FlextLdifConstants.PermissionNames.WRITE)
                    if perms.add:
                        parts.append(FlextLdifConstants.PermissionNames.ADD)
                    if perms.delete:
                        parts.append(FlextLdifConstants.PermissionNames.DELETE)
                    if perms.search:
                        parts.append(FlextLdifConstants.PermissionNames.SEARCH)
                    if perms.compare:
                        parts.append(FlextLdifConstants.PermissionNames.COMPARE)

                # Build ACL string
                acl_content = "#".join(parts) if parts else ""
                acl_str = (
                    f"{acl_attribute}: {acl_content}"
                    if acl_content
                    else f"{acl_attribute}:"
                )

                return FlextResult[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    f"Novell eDirectory ACL write failed: {exc}",
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Novell eDirectory entry quirk."""

        EDIR_DIRECTORY_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ou=services",
            "ou=apps",
            "ou=system",
        ])
        EDIR_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "nspmpasswordpolicy",
            "nspmpasswordpolicydn",
            "logindisabled",
            "loginexpirationtime",
        ])

        def model_post_init(self, _context: object, /) -> None:
            """Initialize eDirectory entry quirk."""

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Novell eDirectory-specific logic:
        # - _can_handle_entry(): Detects eDirectory entries by DN/attributes
        # - process_entry(): Normalizes eDirectory entries with metadata
        # - convert_entry_to_rfc(): Converts eDirectory entries to RFC format

        def _can_handle_entry(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Detect eDirectory-specific entries."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.EDIR_DIRECTORY_MARKERS):
                return True

            # attributes is already dict[str, list[str]], just need to normalize keys
            normalized_attrs = {
                name.lower(): values for name, values in attributes.items()
            }
            if any(
                marker in normalized_attrs for marker in self.EDIR_ATTRIBUTE_MARKERS
            ):
                return True

            # objectClasses is already list[str] in LdifAttributes
            object_classes = attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS,
                [],
            )
            return bool(
                any(
                    str(oc).lower() in FlextLdifServersNovell.NOVELL_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise eDirectory entries and expose metadata."""
            attributes = entry.attributes.attributes.copy()
            try:
                # Get objectClasses (already list[str] in LdifAttributes)
                object_classes = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Process binary values if any (convert bytes to base64 strings)
                processed_attributes: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    processed_values: list[str] = []
                    for value in attr_values:
                        if isinstance(value, bytes):
                            processed_values.append(
                                base64.b64encode(value).decode("ascii")
                            )
                        else:
                            processed_values.append(str(value))
                    processed_attributes[attr_name] = processed_values

                # Add metadata attributes
                processed_attributes[FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE] = [
                    FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY
                ]
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(
                    attributes=processed_attributes
                )
                new_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Novell eDirectory entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Remove eDirectory metadata before RFC processing."""
            try:
                # Work directly with LdifAttributes
                normalized_attributes = entry_data.attributes.attributes.copy()
                normalized_attributes.pop(FlextLdifConstants.QuirkMetadataKeys.SERVER_TYPE, None)

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(
                    attributes=normalized_attributes
                )
                new_entry = entry_data.model_copy(
                    update={"attributes": new_attrs},
                )
                return FlextResult[FlextLdifModels.Entry].ok(new_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Novell eDirectory entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersNovell"]
