"""IBM Tivoli Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersTivoli(FlextLdifServersRfc):
    """Schema quirks for IBM Tivoli Directory Server."""

    def __init__(self) -> None:
        """Initialize Tivoli quirks."""
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

    # Quirk detection patterns and prefixes for Tivoli (shared with Schema and Entry)
    TIVOLI_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b1\.3\.18\.",
        re.IGNORECASE,
    )
    TIVOLI_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "ibm-",
        "ids-",
    ])
    TIVOLI_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "ibm-slapdaccesscontrolsubentry",
        "ibm-ldapserver",
        "ibm-filterentry",
    ])

    class Schema(FlextLdifServersRfc.Schema):
        """IBM Tivoli Directory Server schema quirks implementation."""

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
        priority: ClassVar[int] = 15

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
        # Only can_handle_* methods are overridden with Tivoli-specific logic.
        #

        TIVOLI_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b1\.3\.18\.",
            re.IGNORECASE,
        )
        TIVOLI_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "ibm-",
            "ids-",
        ])
        TIVOLI_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrolsubentry",
            "ibm-ldapserver",
            "ibm-filterentry",
        ])

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Detect Tivoli-specific attributes."""
            attr_lower = attr_definition.lower()
            if self.TIVOLI_OID_PATTERN.search(attr_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(tuple(self.TIVOLI_ATTRIBUTE_PREFIXES))
                for name in name_matches
            ):
                return True

            return any(
                prefix in attr_lower for prefix in self.TIVOLI_ATTRIBUTE_PREFIXES
            )

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Detect Tivoli objectClass definitions."""
            if self.TIVOLI_OID_PATTERN.search(oc_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower() in self.TIVOLI_OBJECTCLASS_NAMES for name in name_matches
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

    class Acl(FlextLdifServersRfc.Acl):
        """IBM Tivoli DS ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrol",
            "ibm-slapdgroupacl",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect Tivoli DS ACL values."""
            normalized = acl_line.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            return attr_name.strip().lower() in self.ACL_ATTRIBUTE_NAMES

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse Tivoli DS ACL definition."""
            try:
                _, content = self._splitacl_line(acl_line)

                # Extract access type from brace content
                access_match = re.search(r'access\s+"(\w+)"', content, re.IGNORECASE)
                access_type = access_match.group(1) if access_match else "read"

                # Build Acl model with minimal parsing
                acl = FlextLdifModels.Acl(
                    name="Tivoli ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn="",
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="",
                        subject_value="",
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read=(access_type.lower() == "read"),
                        write=(access_type.lower() == "write"),
                    ),
                    server_type=FlextLdifConstants.ServerTypes.IBM_TIVOLI,
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"IBM Tivoli DS ACL parsing failed: {exc}",
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Wrap Tivoli DS ACL into generic RFC representation."""
            try:
                # Convert Novell ACL to RFC format using model_copy
                rfc_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.RFC},
                )
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"IBM Tivoli DS ACL→RFC conversion failed: {exc}",
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Repackage RFC ACL payload for Tivoli DS."""
            try:
                # Convert RFC ACL to Novell format using model_copy
                ed_acl = acl_data.model_copy(
                    update={"server_type": FlextLdifConstants.ServerTypes.IBM_TIVOLI},
                )
                return FlextResult[FlextLdifModels.Acl].ok(ed_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→IBM Tivoli DS ACL conversion failed: {exc}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            IBM Tivoli DS ACLs use "#" delimited segments:
            scope#trustee#rights#...
            """
            try:
                # Use Tivoli-specific attribute name
                acl_attribute = "ibm-slapdaccesscontrol"

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
                return FlextResult[str].fail(f"IBM Tivoli DS ACL write failed: {exc}")

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """IBM Tivoli DS entry quirk."""

        TIVOLI_DIRECTORY_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=ibm",
            "cn=configuration",
            "cn=schema",
        ])
        TIVOLI_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ibm-entryuuid",
            "ibm-slapdaccesscontrol",
            "ibm-replicationchangecount",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
        priority: ClassVar[int] = 15

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with Tivoli DS-specific logic:
        # - can_handle_entry(): Detects Tivoli DS entries by DN/attributes
        # - process_entry(): Normalizes Tivoli DS entries with metadata
        # - convert_entry_to_rfc(): Converts Tivoli DS entries to RFC format

        def normalize_dn(self, entry_dn: str) -> str:
            """Normalize DN for Tivoli DS."""
            return entry_dn.lower()

        def normalize_attribute_name(self, attr_name: str) -> str:
            """Normalize attribute name for Tivoli DS."""
            return attr_name.lower()

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Detect Tivoli DS-specific entries."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.TIVOLI_DIRECTORY_MARKERS):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                marker in normalized_attrs for marker in self.TIVOLI_ATTRIBUTE_MARKERS
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
                    str(oc).lower() in FlextLdifServersTivoli.TIVOLI_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Strip IBM Tivoli DS metadata before RFC processing."""
            try:
                # Remove Tivoli-specific metadata, preserve everything else including DN
                rfc_entry = dict(entry_data)
                rfc_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                rfc_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    rfc_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry→RFC conversion failed: {exc}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert RFC entry to Tivoli DS-specific format."""
            try:
                # Extract DN
                entry_dn = str(entry_data.get(FlextLdifConstants.DictKeys.DN, ""))

                # Normalize DN for Tivoli DS
                normalized_dn = self.normalize_dn(entry_dn)

                # Normalize attribute names
                tivoli_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: normalized_dn,
                }
                for key, value in entry_data.items():
                    if key != FlextLdifConstants.DictKeys.DN:
                        normalized_name = self.normalize_attribute_name(str(key))
                        tivoli_entry[normalized_name] = value

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    tivoli_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"RFC→IBM Tivoli DS entry conversion failed: {exc}",
                )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise IBM Tivoli DS entries and attach metadata."""
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
                        ).decode("utf-8")
                    else:
                        processed_attributes[attr_name] = attr_value

                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.ServerTypes.IBM_TIVOLI,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=ibm" in dn_lower
                    or "cn=configuration" in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}",
                )


__all__ = ["FlextLdifServersTivoli"]
