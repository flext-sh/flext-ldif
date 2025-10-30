"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersApache(FlextLdifServersRfc):
    """Apache Directory Server quirks implementation."""

    # Top-level configuration for Apache quirks
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
    priority: ClassVar[int] = 15

    def __init__(self) -> None:
        """Initialize Apache quirks."""
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

    class Schema(FlextLdifServersRfc.Schema):
        """Schema quirks for Apache Directory Server (ApacheDS)."""

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
        priority: ClassVar[int] = 15

        APACHE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b1\.3\.6\.1\.4\.1\.18060\.",
            re.IGNORECASE,
        )
        APACHE_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])
        APACHE_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-directoryservice",
            "ads-base",
            "ads-server",
            "ads-partition",
            "ads-interceptor",
        ])

        def can_handle_attribute(self, attr_definition: str) -> bool:
            """Detect ApacheDS attribute definitions."""
            attr_lower = attr_definition.lower()
            if self.APACHE_OID_PATTERN.search(attr_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                attr_definition,
                re.IGNORECASE,
            )
            if any(
                name.lower().startswith(tuple(self.APACHE_ATTRIBUTE_PREFIXES))
                for name in name_matches
            ):
                return True

            return any(
                prefix in attr_lower for prefix in self.APACHE_ATTRIBUTE_PREFIXES
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
        # Only can_handle_* methods are overridden with ApacheDS-specific logic.
        #

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Detect ApacheDS objectClass definitions."""
            if self.APACHE_OID_PATTERN.search(oc_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                oc_definition,
                re.IGNORECASE,
            )
            return any(
                name.lower() in self.APACHE_OBJECTCLASS_NAMES for name in name_matches
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        # These are references to the outer class definitions for proper architecture
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

    class Acl(FlextLdifServersRfc.Acl):
        """Apache Directory Server ACI quirk."""

        ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            FlextLdifConstants.DictKeys.ACI,
        ])
        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect ApacheDS ACI lines."""
            normalized = acl_line.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if attr_name.strip().lower() in self.ACI_ATTRIBUTE_NAMES:
                return True

            return normalized.lower().startswith("(version")

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse ApacheDS ACI definition."""
            try:
                attr_name, content = self._splitacl_line(acl_line)
                _clauses = [
                    clause.strip() for clause in self.CLAUSE_PATTERN.findall(content)
                ]

                # Create proper Acl model
                acl_model = FlextLdifModels.Acl(
                    name=f"apache-{attr_name}",
                    target=FlextLdifModels.AclTarget(
                        target_dn="*",
                        attributes=[attr_name] if attr_name else [],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="anonymous",
                        subject_value="*",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type=FlextLdifConstants.ServerTypes.APACHE,
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
                    server_type=FlextLdifConstants.ServerTypes.APACHE,
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
                    server_type=FlextLdifConstants.ServerTypes.APACHE,
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
        """Entry quirks for Apache Directory Server."""

        APACHE_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "ou=config",
            "ou=services",
            "ou=system",
            "ou=partitions",
        ])
        APACHE_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "ads-",
            "apacheds",
        ])

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.APACHE
        priority: ClassVar[int] = 15

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with ApacheDS-specific logic:
        # - can_handle_entry(): Detects ApacheDS entries by DN/attributes
        # - process_entry(): Normalizes ApacheDS entries with metadata
        # - convert_entry_to_rfc(): Converts ApacheDS entries to RFC format

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Detect ApacheDS-specific entries."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.APACHE_DN_MARKERS):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(tuple(self.APACHE_ATTRIBUTE_PREFIXES))
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
                    str(oc).lower() in FlextLdifServersApache.APACHE_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise ApacheDS entries and attach metadata."""
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.ServerTypes.APACHE,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "ou=config"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Apache Directory Server entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Strip ApacheDS metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Apache Directory Server entry→RFC conversion failed: {exc}",
                )


__all__ = ["FlextLdifServersApache"]
