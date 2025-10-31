"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation.

    Extends RFC base with Apache-specific detection for attributes, objectClasses, and entries.
    All parsing/conversion inherited from RFC - only detection and metadata handling overridden.
    Uses FlextLdifUtilities for shared validation logic across servers.
    """

    server_type = FlextLdifConstants.ServerTypes.APACHE
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
        """Schema quirks for Apache Directory Server (ApacheDS).

        Detects and tags Apache-specific schema attributes and objectClasses.
        Inherits all parsing and conversion from RFC base.
        """

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        priority: ClassVar[int] = 15

        def can_handle_attribute(
            self, attribute: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect ApacheDS attribute definitions using centralized constants."""
            # Handle both string and model inputs
            if isinstance(attribute, str):
                attr_definition = attribute
                attr_lower = attribute.lower()

                # Check OID pattern from constants
                if re.search(
                    FlextLdifConstants.LdapServerDetection.APACHE_OID_PATTERN,
                    attr_definition,
                ):
                    return True

                # Check attribute name prefixes
                name_matches = re.findall(
                    r"NAME\s+\(?\s*'([^']+)'",
                    attr_definition,
                    re.IGNORECASE,
                )
                if any(
                    name.lower().startswith(
                        tuple(
                            FlextLdifConstants.LdapServerDetection.APACHE_ATTRIBUTE_PREFIXES
                        )
                    )
                    for name in name_matches
                ):
                    return True

                return any(
                    prefix in attr_lower
                    for prefix in FlextLdifConstants.LdapServerDetection.APACHE_ATTRIBUTE_PREFIXES
                )
            if isinstance(attribute, FlextLdifModels.SchemaAttribute):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifConstants.LdapServerDetection.APACHE_OID_PATTERN,
                    attribute.oid,
                ):
                    return True

                # Check attribute name prefixes
                attr_name_lower = attribute.name.lower()
                return any(
                    attr_name_lower.startswith(prefix)
                    for prefix in FlextLdifConstants.LdapServerDetection.APACHE_ATTRIBUTE_PREFIXES
                )
            return False

        def can_handle_objectclass(
            self, objectclass: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect ApacheDS objectClass definitions using centralized constants."""
            if isinstance(objectclass, str):
                if re.search(
                    FlextLdifConstants.LdapServerDetection.APACHE_OID_PATTERN,
                    objectclass,
                ):
                    return True

                name_matches = re.findall(
                    r"NAME\s+\(?\s*'([^']+)'",
                    objectclass,
                    re.IGNORECASE,
                )
                return any(
                    name.lower()
                    in FlextLdifConstants.LdapServerDetection.APACHE_OBJECTCLASS_NAMES
                    for name in name_matches
                )
            if isinstance(objectclass, FlextLdifModels.SchemaObjectClass):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifConstants.LdapServerDetection.APACHE_OID_PATTERN,
                    objectclass.oid,
                ):
                    return True

                # Check objectClass name
                oc_name_lower = objectclass.name.lower()
                return (
                    oc_name_lower
                    in FlextLdifConstants.LdapServerDetection.APACHE_OBJECTCLASS_NAMES
                )
            return False

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add Apache metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with Apache metadata

            """
            result = super().parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "apache_directory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add Apache metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with Apache metadata

            """
            result = super().parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Use FlextLdifUtilities for common objectClass validation
                FlextLdifUtilities.ObjectClassValidator.fix_missing_sup(
                    oc_data, server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )
                FlextLdifUtilities.ObjectClassValidator.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "apache_directory"
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        def convert_attribute_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaAttribute,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Convert RFC attribute to Apache format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaAttribute

            Returns:
                FlextResult with SchemaAttribute marked with Apache metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                "apache_directory"
            )
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(result_data)

        def convert_objectclass_from_rfc(
            self,
            rfc_data: FlextLdifModels.SchemaObjectClass,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Convert RFC objectClass to Apache format with metadata.

            Args:
                rfc_data: RFC-compliant SchemaObjectClass

            Returns:
                FlextResult with SchemaObjectClass marked with Apache metadata

            """
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                "apache_directory"
            )
            result_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(result_data)

        # Nested Acl and Entry classes for test API compatibility
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema - delegates to outer Apache.Acl."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()
                self._outer = FlextLdifServersApache.Acl()

            def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
                """Delegate to outer Apache Acl."""
                return self._outer.can_handle_acl(acl)

            def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Apache Acl."""
                return self._outer.parse_acl(acl_line)

            def convert_acl_to_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Apache Acl."""
                return self._outer.convert_acl_to_rfc(acl_data)

            def convert_acl_from_rfc(
                self,
                acl_data: FlextLdifModels.Acl,
            ) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Apache Acl."""
                return self._outer.convert_acl_from_rfc(acl_data)

            def write_acl_to_rfc(
                self, acl_data: FlextLdifModels.Acl
            ) -> FlextResult[str]:
                """Delegate to outer Apache Acl."""
                return self._outer.write_acl_to_rfc(acl_data)

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema - delegates to outer Apache.Entry."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()
                self._outer = FlextLdifServersApache.Entry()

            def can_handle_entry(self, entry: FlextLdifModels.Entry) -> bool:
                """Delegate to outer Apache Entry."""
                return self._outer.can_handle_entry(entry)

            def process_entry(
                self, entry: FlextLdifModels.Entry
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Apache Entry."""
                return self._outer.process_entry(entry)

            def convert_entry_to_rfc(
                self, entry_data: FlextLdifModels.Entry
            ) -> FlextResult[FlextLdifModels.Entry]:
                """Delegate to outer Apache Entry."""
                return self._outer.convert_entry_to_rfc(entry_data)

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk.

        Handles ApacheDS ACI (Access Control Instruction) format.
        """

        ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            FlextLdifConstants.AclAttributes.ACI,
        ])
        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Detect ApacheDS ACI lines."""
            if not isinstance(acl, FlextLdifModels.Acl):
                return False
            if not acl.raw_acl:
                return False
            normalized = acl.raw_acl.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if attr_name.strip().lower() in self.ACI_ATTRIBUTE_NAMES:
                return True

            return normalized.lower().startswith("(version")

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ApacheDS ACI definition."""
            try:
                attr_name, _content = self._splitacl_line(acl_line)

                # Create proper Acl model
                acl_model = FlextLdifModels.Acl(
                    name=f"apache-{attr_name}",
                    target=FlextLdifModels.AclTarget(
                        target_dn="*",
                        attributes=[attr_name] if attr_name else [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type=FlextLdifConstants.AclSubjectTypes.ANONYMOUS,
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Apache Directory Server ACL parsing failed: {exc}",
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Wrap ApacheDS ACL into a generic RFC representation."""
            try:
                # Convert to RFC-compliant ACL model (ApacheDS ACI is already RFC-compliant)
                rfc_acl = FlextLdifModels.Acl(
                    name=acl_data.name,
                    target=acl_data.target,
                    subject=acl_data.subject,
                    permissions=acl_data.permissions,
                    server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    raw_acl=acl_data.raw_acl,
                )
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Apache Directory Server ACL→RFC conversion failed: {exc}",
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Repackage RFC ACL payload for ApacheDS."""
            try:
                # Convert to ApacheDS-specific ACL model
                apache_acl = FlextLdifModels.Acl(
                    name=acl_data.name,
                    target=acl_data.target,
                    subject=acl_data.subject,
                    permissions=acl_data.permissions,
                    server_type=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    raw_acl=acl_data.raw_acl,
                )
                return FlextResult[FlextLdifModels.Acl].ok(apache_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Apache Directory Server ACL conversion failed: {exc}",
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Apache Directory Server ACLs use ACI format.
            """
            try:
                acl_attribute = getattr(
                    acl_data,
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE,
                    FlextLdifConstants.DictKeys.ACI,
                )
                data_raw = getattr(acl_data, FlextLdifConstants.DictKeys.DATA, {})
                data: dict[str, object] = data_raw if isinstance(data_raw, dict) else {}
                content = data.get("content", "")
                clauses_raw = data.get("clauses", [])
                clauses: list[str] = (
                    clauses_raw if isinstance(clauses_raw, list) else []
                )

                if content:
                    acl_str = f"{acl_attribute}: {content}"
                elif clauses:
                    acl_str = f"{acl_attribute}: {' '.join(clauses)}"
                else:
                    acl_str = f"{acl_attribute}:"

                return FlextResult[str].ok(acl_str)
            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    f"Apache Directory Server ACL write failed: {exc}",
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class Entry(FlextLdifServersRfc.Entry):
        """Entry quirks for Apache Directory Server.

        Handles ApacheDS-specific entry detection and processing.
        """

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
        priority: ClassVar[int] = 15

        def can_handle_entry(self, entry: FlextLdifModels.Entry) -> bool:
            """Detect ApacheDS-specific entries using centralized constants."""
            if not isinstance(entry, FlextLdifModels.Entry):
                return False

            attributes = entry.attributes.attributes
            entry_dn = entry.dn.value

            if not entry_dn:
                return False

            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifConstants.LdapServerDetection.APACHE_DN_MARKERS
            ):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(
                    tuple(
                        FlextLdifConstants.LdapServerDetection.APACHE_ATTRIBUTE_PREFIXES
                    )
                )
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
                    str(oc).lower()
                    in FlextLdifConstants.LdapServerDetection.APACHE_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self, entry: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise ApacheDS entries and attach metadata."""
            try:
                attributes = entry.attributes.attributes.copy()
                entry_dn = entry.dn.value
                dn_lower = entry_dn.lower()

                # Store metadata in extensions
                metadata = entry.metadata or FlextLdifModels.QuirkMetadata()
                metadata.extensions[FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY] = (
                    "ou=config" in dn_lower
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
                    f"Apache Directory Server entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self, entry_data: FlextLdifModels.Entry
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Strip ApacheDS metadata before RFC processing."""
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
                    f"Apache Directory Server entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
