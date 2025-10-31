"""IBM Tivoli Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersTivoli(FlextLdifServersRfc):
    """Schema quirks for IBM Tivoli Directory Server."""

    server_type = FlextLdifConstants.ServerTypes.IBM_TIVOLI
    priority = 15

    def __init__(self) -> None:
        """Initialize Tivoli quirks."""
        super().__init__()
        self._schema = self.Schema()
        self.schema = self.Schema()
        self.acl = self.Acl()
        self.entry = self.Entry()

    def can_handle_attribute(self, attribute: FlextLdifModels.SchemaAttribute) -> bool:
        """Delegate to schema instance."""
        return self._schema.can_handle_attribute(attribute)

    def parse_attribute(
        self,
        attr_definition: str,
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Delegate to schema instance."""
        return self._schema.parse_attribute(attr_definition)

    def can_handle_objectclass(
        self, objectclass: FlextLdifModels.SchemaObjectClass
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

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect Tivoli-specific attributes."""
            if self.TIVOLI_OID_PATTERN.search(attribute.oid):
                return True
            attr_name_lower = attribute.name.lower()
            return any(
                attr_name_lower.startswith(prefix)
                for prefix in self.TIVOLI_ATTRIBUTE_PREFIXES
            )

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect Tivoli objectClass definitions."""
            if self.TIVOLI_OID_PATTERN.search(objectclass.oid):
                return True
            oc_name_lower = objectclass.name.lower()
            return oc_name_lower in self.TIVOLI_OBJECTCLASS_NAMES

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Tivoli metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Tivoli metadata

            """
            result = super().parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add Tivoli metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Tivoli metadata

            """
            result = super().parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to Tivoli format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with Tivoli metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to Tivoli format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with Tivoli metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk("ibm_tivoli")
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(result_data)

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

            def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
                """Delegate to outer Tivoli Acl's can_handle_acl implementation."""
                outer_acl = FlextLdifServersTivoli.Acl()
                return outer_acl.can_handle_acl(acl)

            def write_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[str]:
                """Delegate to outer Tivoli Acl's write_acl_to_rfc implementation."""
                outer_acl = FlextLdifServersTivoli.Acl()
                return outer_acl.write_acl_to_rfc(acl_data)

            def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Tivoli Acl's parse_acl implementation."""
                outer_acl = FlextLdifServersTivoli.Acl()
                return outer_acl.parse_acl(acl_line)

            def convert_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Tivoli Acl's convert_acl_to_rfc implementation."""
                outer_acl = FlextLdifServersTivoli.Acl()
                return outer_acl.convert_acl_to_rfc(acl_data)

            def convert_acl_from_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Tivoli Acl's convert_acl_from_rfc implementation."""
                outer_acl = FlextLdifServersTivoli.Acl()
                return outer_acl.convert_acl_from_rfc(acl_data)

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

            def can_handle_entry(
                self,
                entry: FlextLdifModels.Entry,
            ) -> bool:
                """Delegate to outer Tivoli Entry's can_handle_entry implementation."""
                outer_entry = FlextLdifServersTivoli.Entry()
                return outer_entry.can_handle_entry(entry)

            def process_entry(
                self,
                entry: FlextLdifModels.Entry,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Tivoli Entry's process_entry implementation."""
                outer_entry = FlextLdifServersTivoli.Entry()
                return outer_entry.process_entry(entry)

            def convert_entry_to_rfc(
                self,
                entry_data: FlextLdifModels.Entry,
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Tivoli Entry's convert_entry_to_rfc implementation."""
                outer_entry = FlextLdifServersTivoli.Entry()
                return outer_entry.convert_entry_to_rfc(entry_data)

    class Acl(FlextLdifServersRfc.Acl):
        """IBM Tivoli DS ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrol",
            "ibm-slapdgroupacl",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.IBM_TIVOLI
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Detect Tivoli DS ACL values."""
            if not acl.raw_acl:
                return False
            normalized = acl.raw_acl.strip()
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
                access_type = (
                    access_match.group(1)
                    if access_match
                    else FlextLdifConstants.PermissionNames.READ
                )

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
                        read=(
                            access_type.lower()
                            == FlextLdifConstants.PermissionNames.READ
                        ),
                        write=(
                            access_type.lower()
                            == FlextLdifConstants.PermissionNames.WRITE
                        ),
                    ),
                    server_type="ibm_tivoli",
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
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Detect Tivoli DS-specific entries."""
            entry_dn = entry.dn.value
            attributes = entry.attributes.attributes
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
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Strip IBM Tivoli DS metadata before RFC processing."""
            try:
                # Work directly with LdifAttributes
                attributes = entry_data.attributes.attributes.copy()
                # Remove Tivoli-specific metadata, preserve everything else
                attributes.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                attributes.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)

                # Create new LdifAttributes directly from the dict
                new_attrs = FlextLdifModels.LdifAttributes(attributes=attributes)

                rfc_entry = entry_data.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(rfc_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"IBM Tivoli DS entry→RFC conversion failed: {exc}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert RFC entry to Tivoli DS-specific format."""
            try:
                # Work directly with Entry model
                entry_dn = entry_data.dn.value
                attributes = entry_data.attributes.attributes.copy()

                # Normalize DN for Tivoli DS
                normalized_dn = self.normalize_dn(entry_dn)

                # Normalize attribute names - work directly with dict[str, list[str]]
                tivoli_attrs: dict[str, list[str]] = {}
                for key, value in attributes.items():
                    normalized_name = self.normalize_attribute_name(key)
                    tivoli_attrs[normalized_name] = value

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(attributes=tivoli_attrs)
                new_dn = FlextLdifModels.DistinguishedName(value=normalized_dn)

                tivoli_entry = entry_data.model_copy(
                    update={"dn": new_dn, "attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(tivoli_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"RFC→IBM Tivoli DS entry conversion failed: {exc}",
                )

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise IBM Tivoli DS entries and attach metadata."""
            try:
                entry_dn = entry.dn.value
                attributes = entry.attributes.attributes.copy()
                dn_lower = entry_dn.lower()

                # Get objectClasses directly from attributes (already list[str])
                object_classes = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Copy all existing attributes first
                processed_attributes = attributes.copy()

                # Process binary values if any (convert bytes to base64 strings)
                for attr_name, attr_values in processed_attributes.items():
                    processed_values: list[str] = []
                    for value in attr_values:
                        if isinstance(value, bytes):
                            processed_values.append(
                                base64.b64encode(value).decode("utf-8")
                            )
                        else:
                            processed_values.append(str(value))
                    processed_attributes[attr_name] = processed_values

                # Add/update metadata attributes
                processed_attributes[FlextLdifConstants.DictKeys.SERVER_TYPE] = [
                    FlextLdifConstants.ServerTypes.IBM_TIVOLI
                ]
                processed_attributes[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] = [
                    str("cn=ibm" in dn_lower or "cn=configuration" in dn_lower)
                ]
                # Update objectClass (already in list format)
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(
                    attributes=processed_attributes
                )

                processed_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}",
                )


__all__ = ["FlextLdifServersTivoli"]
