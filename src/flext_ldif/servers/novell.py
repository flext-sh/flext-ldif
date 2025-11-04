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
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory quirks implementation."""

    server_type = FlextLdifConstants.ServerTypes.NOVELL
    priority = 10

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants:
        """Standardized constants for Novell eDirectory quirk."""

        CANONICAL_NAME: ClassVar[str] = "novell_edirectory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["novell_edirectory", "novell"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["novell_edirectory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(["novell_edirectory", "rfc"])

    def __init__(self) -> None:
        """Initialize Novell quirks."""
        super().__init__()
        self._schema = self.Schema()
        self.schema = self._schema  # Public alias for delegation
        self.acl = self.Acl()
        self.entry = self.Entry()

    def can_handle_attribute(
        self, attribute: str | FlextLdifModels.SchemaAttribute
    ) -> bool:
        """Delegate to schema instance."""
        return self._schema.can_handle_attribute(attribute)

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self._schema.parse_attribute(attr_definition)

    def can_handle_objectclass(
        self, objectclass: str | FlextLdifModels.SchemaObjectClass
    ) -> bool:
        """Delegate to schema instance."""
        return self._schema.can_handle_objectclass(objectclass)

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

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
        priority: ClassVar[int] = 18

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
        priority: ClassVar[int] = 15

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

        def can_handle_attribute(
            self, attribute: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect eDirectory attribute definitions."""
            if isinstance(attribute, str):
                attr_lower = attribute.lower()
                if self.NOVELL_OID_PATTERN.search(attribute):
                    return True

                name_matches = self.ATTRIBUTE_NAME_REGEX.findall(attribute)
                if any(
                    name.lower().startswith(tuple(self.NOVELL_ATTRIBUTE_PREFIXES))
                    for name in name_matches
                ):
                    return True

                return any(
                    prefix in attr_lower for prefix in self.NOVELL_ATTRIBUTE_PREFIXES
                )
            if isinstance(attribute, FlextLdifModels.SchemaAttribute):
                if self.NOVELL_OID_PATTERN.search(attribute.oid):
                    return True
                attr_name_lower = attribute.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in self.NOVELL_ATTRIBUTE_PREFIXES
                )
            return False

        # INHERITED METHODS (from FlextLdifServersRfc.Schema)
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
        # Only can_handle_* methods are overridden with Novell-specific logic.
        #

        def can_handle_objectclass(
            self, objectclass: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect eDirectory objectClass definitions."""
            if isinstance(objectclass, str):
                if self.NOVELL_OID_PATTERN.search(objectclass):
                    return True

                name_matches = self.ATTRIBUTE_NAME_REGEX.findall(objectclass)
                return any(
                    name.lower() in self.NOVELL_OBJECTCLASS_NAMES
                    for name in name_matches
                )
            if isinstance(objectclass, FlextLdifModels.SchemaObjectClass):
                if self.NOVELL_OID_PATTERN.search(objectclass.oid):
                    return True
                oc_name_lower = objectclass.name.lower()
                return oc_name_lower in self.NOVELL_OBJECTCLASS_NAMES
            return False

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Novell metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Novell metadata

            """
            result = super().parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "novell_edirectory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add Novell metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Novell metadata

            """
            result = super().parse_objectclass(oc_definition)
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
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

            def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
                """Delegate to outer Novell Acl's can_handle_acl implementation."""
                outer_acl = FlextLdifServersNovell.Acl()
                return outer_acl.can_handle_acl(acl)

            def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Novell Acl's parse_acl implementation."""
                outer_acl = FlextLdifServersNovell.Acl()
                return outer_acl.parse_acl(acl_line)

            def write_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[str]:
                """Delegate to outer Novell Acl's write_acl_to_rfc implementation."""
                outer_acl = FlextLdifServersNovell.Acl()
                return outer_acl.write_acl_to_rfc(acl_data)

            def convert_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Novell Acl's convert_acl_to_rfc implementation."""
                outer_acl = FlextLdifServersNovell.Acl()
                return outer_acl.convert_acl_to_rfc(acl_data)

            def convert_acl_from_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Novell Acl's convert_acl_from_rfc implementation."""
                outer_acl = FlextLdifServersNovell.Acl()
                return outer_acl.convert_acl_from_rfc(acl_data)

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

            def can_handle_entry(
                self,
                entry: FlextLdifModels.Entry,
            ) -> bool:
                """Delegate to outer Novell Entry's can_handle_entry implementation."""
                outer_entry = FlextLdifServersNovell.Entry()
                return outer_entry.can_handle_entry(entry)

            def process_entry(
                self,
                entry: FlextLdifModels.Entry,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Novell Entry's process_entry implementation."""
                outer_entry = FlextLdifServersNovell.Entry()
                return outer_entry.process_entry(entry)

            def convert_entry_to_rfc(
                self,
                entry_data: FlextLdifModels.Entry,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Novell Entry's convert_entry_to_rfc implementation."""
                outer_entry = FlextLdifServersNovell.Entry()
                result = outer_entry.convert_entry_to_rfc(entry_data)
                if result.is_failure:
                    return FlextResult[FlextLdifModels.Entry].fail(result.error)
                # Result is already Entry
                return result

    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Detect eDirectory ACL values."""
            normalized = acl.raw_acl.strip() if acl.raw_acl else ""
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            return attr_name.strip().lower() in self.ACL_ATTRIBUTE_NAMES

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
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

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Wrap eDirectory ACL into generic RFC representation."""
            try:
                # Convert Novell ACL to RFC format using model_copy
                rfc_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.RFC},
                )
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Novell eDirectory ACL→RFC conversion failed: {exc}",
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Repackage RFC ACL payload for eDirectory."""
            try:
                # Convert RFC ACL to Novell format using model_copy
                ed_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.NOVELL},
                )
                return FlextResult[FlextLdifModels.Acl].ok(ed_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Novell eDirectory ACL conversion failed: {exc}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
        priority: ClassVar[int] = 15

        def model_post_init(self, _context: object, /) -> None:
            """Initialize eDirectory entry quirk."""

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with Novell eDirectory-specific logic:
        # - can_handle_entry(): Detects eDirectory entries by DN/attributes
        # - process_entry(): Normalizes eDirectory entries with metadata
        # - convert_entry_to_rfc(): Converts eDirectory entries to RFC format

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Detect eDirectory-specific entries."""
            entry_dn = entry.dn.value
            attributes = entry.attributes.attributes
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
