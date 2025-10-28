"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif import FlextLdifModels
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import BaseAclQuirk, BaseEntryQuirk, BaseSchemaQuirk
from flext_ldif.quirks.rfc_parsers import RfcAttributeParser, RfcObjectClassParser
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersApache(BaseSchemaQuirk):
    """Schema quirks for Apache Directory Server (ApacheDS)."""

    APACHE_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b1\.3\.6\.1\.4\.1\.18060\.", re.IGNORECASE
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

    # Apache Directory Server configuration defaults
    server_type: ClassVar[str] = FlextLdifConstants.LdapServers.APACHE_DIRECTORY
    priority: ClassVar[int] = 15

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Detect ApacheDS attribute definitions."""
        attr_lower = attr_definition.lower()
        if self.APACHE_OID_PATTERN.search(attr_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", attr_definition, re.IGNORECASE
        )
        if any(
            name.lower().startswith(tuple(self.APACHE_ATTRIBUTE_PREFIXES))
            for name in name_matches
        ):
            return True

        return any(prefix in attr_lower for prefix in self.APACHE_ATTRIBUTE_PREFIXES)

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse ApacheDS attribute definition."""
        # Use RFC parser as foundation
        rfc_result = RfcAttributeParser.parse_common(
            attr_definition, case_insensitive=True
        )
        if not rfc_result.is_success:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"Apache Directory Server attribute parsing failed: {rfc_result.error}"
            )

        # Enhance with Apache-specific metadata
        attribute = rfc_result.unwrap()
        attribute.metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
            quirk_type="apache_directory",
            original_format=attr_definition.strip(),
        )

        return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Detect ApacheDS objectClass definitions."""
        if self.APACHE_OID_PATTERN.search(oc_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", oc_definition, re.IGNORECASE
        )
        return any(
            name.lower() in self.APACHE_OBJECTCLASS_NAMES for name in name_matches
        )

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse ApacheDS objectClass definition."""
        # Use RFC parser as foundation
        rfc_result = RfcObjectClassParser.parse_common(
            oc_definition, case_insensitive=True
        )
        if not rfc_result.is_success:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"Apache Directory Server objectClass parsing failed: {rfc_result.error}"
            )

        # Enhance with Apache-specific metadata
        oc_data = rfc_result.unwrap()
        oc_data.metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
            quirk_type="apache_directory",
            original_format=oc_definition.strip(),
        )

        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert ApacheDS attribute metadata to an RFC-friendly payload."""
        try:
            # Create a new SchemaAttribute model with RFC-compliant data (remove server-specific metadata)
            rfc_data = FlextLdifModels.SchemaAttribute(
                oid=attr_data.oid,
                name=attr_data.name or attr_data.oid,
                desc=attr_data.desc,
                syntax=attr_data.syntax,
                length=attr_data.length,
                equality=attr_data.equality,
                ordering=attr_data.ordering,
                substr=attr_data.substr,
                single_value=attr_data.single_value,
                usage=attr_data.usage,
                sup=attr_data.sup,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"Apache Directory Server→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert ApacheDS objectClass metadata to an RFC-friendly payload."""
        try:
            # Create a new SchemaObjectClass model with RFC-compliant data (remove server-specific metadata)
            rfc_data = FlextLdifModels.SchemaObjectClass(
                oid=oc_data.oid,
                name=oc_data.name or oc_data.oid,
                desc=oc_data.desc,
                sup=oc_data.sup,
                kind=oc_data.kind or FlextLdifConstants.Schema.STRUCTURAL,
                must=oc_data.must or [],
                may=oc_data.may or [],
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"Apache Directory Server→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to ApacheDS-specific format."""
        try:
            # Update metadata to indicate Apache Directory Server format
            updated_metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="apache_directory",
                original_format=None,
            )
            converted = rfc_data.model_copy(
                update={"metadata": updated_metadata}, deep=True
            )
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(converted)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→Apache Directory Server attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to ApacheDS-specific format."""
        try:
            # Update metadata to indicate Apache Directory Server format
            updated_metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="apache_directory",
                original_format=None,
            )
            converted = rfc_data.model_copy(
                update={"metadata": updated_metadata}, deep=True
            )
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(converted)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→Apache Directory Server objectClass conversion failed: {exc}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format."""
        try:
            oid = getattr(attr_data, FlextLdifConstants.DictKeys.OID, "")
            name = getattr(attr_data, FlextLdifConstants.DictKeys.NAME, "")
            desc = getattr(attr_data, FlextLdifConstants.DictKeys.DESC, None)
            syntax = getattr(attr_data, FlextLdifConstants.DictKeys.SYNTAX, None)
            equality = getattr(attr_data, FlextLdifConstants.DictKeys.EQUALITY, None)
            single_value = getattr(
                attr_data, FlextLdifConstants.DictKeys.SINGLE_VALUE, False
            )

            attr_str = f"( {oid}"
            if name:
                attr_str += f" NAME '{name}'"
            if desc:
                attr_str += f" DESC '{desc}'"
            if syntax:
                attr_str += f" SYNTAX {syntax}"
            if equality:
                attr_str += f" EQUALITY {equality}"
            if single_value:
                attr_str += " SINGLE-VALUE"
            attr_str += " )"

            return FlextResult[str].ok(attr_str)
        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[str].fail(
                f"Apache Directory Server attribute write failed: {exc}"
            )

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format."""
        try:
            oid = getattr(oc_data, FlextLdifConstants.DictKeys.OID, "")
            name = getattr(oc_data, FlextLdifConstants.DictKeys.NAME, "")
            desc = getattr(oc_data, FlextLdifConstants.DictKeys.DESC, None)
            sup = getattr(oc_data, FlextLdifConstants.DictKeys.SUP, None)
            kind = getattr(
                oc_data,
                FlextLdifConstants.DictKeys.KIND,
                FlextLdifConstants.Schema.STRUCTURAL,
            )
            must = getattr(oc_data, FlextLdifConstants.DictKeys.MUST, [])
            may = getattr(oc_data, FlextLdifConstants.DictKeys.MAY, [])

            oc_str = f"( {oid}"
            if name:
                oc_str += f" NAME '{name}'"
            if desc:
                oc_str += f" DESC '{desc}'"
            if sup:
                oc_str += f" SUP {sup}"
            oc_str += f" {kind}"
            if must and isinstance(must, list):
                must_attrs = " $ ".join(must)
                oc_str += f" MUST ( {must_attrs} )"
            if may and isinstance(may, list):
                may_attrs = " $ ".join(may)
                oc_str += f" MAY ( {may_attrs} )"
            oc_str += " )"

            return FlextResult[str].ok(oc_str)
        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[str].fail(
                f"Apache Directory Server objectClass write failed: {exc}"
            )

    class AclQuirk(BaseAclQuirk):
        """Apache Directory Server ACI quirk."""

        ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            FlextLdifConstants.DictKeys.ACI,
        ])
        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 200

        def __init__(
            self,
            server_type: str = FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            priority: int = 15,
        ) -> None:
            """Initialize Apache Directory Server ACL quirk."""
            super().__init__(server_type=server_type, priority=priority)

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
                        target_dn="*", attributes=[attr_name] if attr_name else []
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="anonymous", subject_value="*"
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type="apache_directory",
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Apache Directory Server ACL parsing failed: {exc}"
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
                    f"Apache Directory Server ACL→RFC conversion failed: {exc}"
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
                    server_type="apache_directory",
                    raw_acl=acl_data.raw_acl,
                )
                return FlextResult[FlextLdifModels.Acl].ok(apache_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Apache Directory Server ACL conversion failed: {exc}"
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
                    f"Apache Directory Server ACL write failed: {exc}"
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class EntryQuirk(BaseEntryQuirk):
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

        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 200

        def __init__(
            self,
            server_type: str = FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            priority: int = 15,
        ) -> None:
            """Initialize Apache Directory Server entry quirk."""
            super().__init__(server_type=server_type, priority=priority)

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
                FlextLdifConstants.DictKeys.OBJECTCLASS, []
            )
            object_classes = (
                object_classes_raw
                if isinstance(object_classes_raw, list)
                else [object_classes_raw]
            )
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifQuirksServersApache.APACHE_OBJECTCLASS_NAMES
                    for oc in object_classes
                )
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
                    FlextLdifConstants.DictKeys.OBJECTCLASS, []
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
                            attr_value
                        ).decode("ascii")
                    else:
                        processed_attributes[attr_name] = attr_value

                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "ou=config"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Apache Directory Server entry processing failed: {exc}"
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
                    normalized_entry
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Apache Directory Server entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersApache"]
