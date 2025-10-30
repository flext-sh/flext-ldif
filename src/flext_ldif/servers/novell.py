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
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersNovell(FlextLdifServersRfc):
    """Novell eDirectory quirks implementation."""

    # Top-level configuration for Novell quirks
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
    priority: ClassVar[int] = 15

    def __init__(self) -> None:
        """Initialize Novell quirks."""
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

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Detect eDirectory attribute definitions."""
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
        # Only can_handle_* methods are overridden with Novell-specific logic.
        #

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Detect eDirectory objectClass definitions."""
            if self.NOVELL_OID_PATTERN.search(oc_definition):
                return True

            name_matches = self.ATTRIBUTE_NAME_REGEX.findall(oc_definition)
            return any(
                name.lower() in self.NOVELL_OBJECTCLASS_NAMES for name in name_matches
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

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

    class Acl(FlextLdifServersRfc.Acl):
        """Novell eDirectory ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.NOVELL
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect eDirectory ACL values."""
            normalized = acl_line.strip()
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

                # Build Acl model with nested models
                acl = FlextLdifModels.Acl(
                    name="Novell eDirectory ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn=scope or "",  # Novell: scope is target DN
                        attributes=[],  # Novell stub - not extracted from segments
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="trustee",
                        subject_value=trustee or "unknown",
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read="read" in rights if isinstance(rights, list) else False,
                        write="write" in rights if isinstance(rights, list) else False,
                        add="add" in rights if isinstance(rights, list) else False,
                        delete=(
                            "delete" in rights if isinstance(rights, list) else False
                        ),
                        search=(
                            "search" in rights if isinstance(rights, list) else False
                        ),
                        compare=(
                            "compare" in rights if isinstance(rights, list) else False
                        ),
                    ),
                    server_type=FlextLdifConstants.ServerTypes.NOVELL,
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
                        parts.append("read")
                    if perms.write:
                        parts.append("write")
                    if perms.add:
                        parts.append("add")
                    if perms.delete:
                        parts.append("delete")
                    if perms.search:
                        parts.append("search")
                    if perms.compare:
                        parts.append("compare")

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

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Novell eDirectory-specific logic:
        # - can_handle_entry(): Detects eDirectory entries by DN/attributes
        # - process_entry(): Normalizes eDirectory entries with metadata
        # - convert_entry_to_rfc(): Converts eDirectory entries to RFC format

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Detect eDirectory-specific entries."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.EDIR_DIRECTORY_MARKERS):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                marker in normalized_attrs for marker in self.EDIR_ATTRIBUTE_MARKERS
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
                    str(oc).lower() in FlextLdifServersNovell.NOVELL_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise eDirectory entries and expose metadata."""
            try:
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Novell eDirectory entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Remove eDirectory metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Novell eDirectory entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersNovell"]
