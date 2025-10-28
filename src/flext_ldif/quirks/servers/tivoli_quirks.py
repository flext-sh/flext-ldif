"""IBM Tivoli Directory Server quirks implementation."""

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


class FlextLdifQuirksServersTivoli(BaseSchemaQuirk):
    """Schema quirks for IBM Tivoli Directory Server."""

    TIVOLI_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b1\.3\.18\.", re.IGNORECASE
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

    # IBM Tivoli Directory Server configuration defaults
    server_type: ClassVar[str] = FlextLdifConstants.LdapServers.IBM_TIVOLI
    priority: ClassVar[int] = 15

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Detect Tivoli-specific attributes."""
        attr_lower = attr_definition.lower()
        if self.TIVOLI_OID_PATTERN.search(attr_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", attr_definition, re.IGNORECASE
        )
        if any(
            name.lower().startswith(tuple(self.TIVOLI_ATTRIBUTE_PREFIXES))
            for name in name_matches
        ):
            return True

        return any(prefix in attr_lower for prefix in self.TIVOLI_ATTRIBUTE_PREFIXES)

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse IBM Tivoli DS attribute definition."""
        # Use RFC parser as foundation
        rfc_result = RfcAttributeParser.parse_common(
            attr_definition, case_insensitive=True
        )
        if not rfc_result.is_success:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"IBM Tivoli DS attribute parsing failed: {rfc_result.error}"
            )

        # Enhance with IBM Tivoli-specific metadata
        attribute = rfc_result.unwrap()
        attribute.metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
            quirk_type="ibm_tivoli",
            original_format=attr_definition.strip(),
        )

        return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Detect Tivoli objectClass definitions."""
        if self.TIVOLI_OID_PATTERN.search(oc_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", oc_definition, re.IGNORECASE
        )
        return any(
            name.lower() in self.TIVOLI_OBJECTCLASS_NAMES for name in name_matches
        )

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse IBM Tivoli DS objectClass definition."""
        # Use RFC parser as foundation
        rfc_result = RfcObjectClassParser.parse_common(
            oc_definition, case_insensitive=True
        )
        if not rfc_result.is_success:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"IBM Tivoli DS objectClass parsing failed: {rfc_result.error}"
            )

        # Enhance with IBM Tivoli-specific metadata
        oc_data = rfc_result.unwrap()
        oc_data.metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
            quirk_type="ibm_tivoli",
            original_format=oc_definition.strip(),
        )

        return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert Tivoli attribute metadata to an RFC-friendly payload."""
        try:
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
                metadata=None,  # No quirk metadata in RFC format
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_data)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"IBM Tivoli DS→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert Tivoli objectClass metadata to an RFC-friendly payload."""
        try:
            # Build RFC-compliant SchemaObjectClass model using direct field access
            rfc_data = FlextLdifModels.SchemaObjectClass(
                oid=oc_data.oid,
                name=oc_data.name or oc_data.oid,
                desc=oc_data.desc,
                sup=oc_data.sup,
                kind=oc_data.kind,
                must=oc_data.must,
                may=oc_data.may,
                metadata=None,  # No quirk metadata in RFC format
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_data)

        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"IBM Tivoli DS→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to IBM Tivoli DS-specific format."""
        try:
            # Use model_copy to add IBM Tivoli-specific metadata
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="ibm_tivoli"
            )
            tivoli_data = rfc_data.model_copy(update={"metadata": metadata}, deep=True)
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(tivoli_data)
        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→IBM Tivoli DS attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to IBM Tivoli DS-specific format."""
        try:
            # Use model_copy to add IBM Tivoli-specific metadata
            metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                quirk_type="ibm_tivoli"
            )
            tivoli_data = rfc_data.model_copy(update={"metadata": metadata}, deep=True)
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(tivoli_data)
        except (ValueError, TypeError, AttributeError) as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→IBM Tivoli DS objectClass conversion failed: {exc}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format."""
        try:
            # Use direct field access instead of .get()
            oid = attr_data.oid or ""
            name = attr_data.name or ""
            desc = attr_data.desc
            syntax = attr_data.syntax
            equality = attr_data.equality
            single_value = attr_data.single_value or False

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
            return FlextResult[str].fail(f"IBM Tivoli DS attribute write failed: {exc}")

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format."""
        try:
            # Use direct field access instead of .get()
            oid = oc_data.oid or ""
            name = oc_data.name or ""
            desc = oc_data.desc
            sup = oc_data.sup
            kind = oc_data.kind or "STRUCTURAL"
            must = oc_data.must or []
            may = oc_data.may or []

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
                f"IBM Tivoli DS objectClass write failed: {exc}"
            )

    class AclQuirk(BaseAclQuirk):
        """IBM Tivoli DS ACL quirk."""

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ibm-slapdaccesscontrol",
            "ibm-slapdgroupacl",
        ])

        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 200

        def __init__(self) -> None:
            """Initialize Tivoli DS ACL quirk."""
            super().__init__(
                server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
                priority=15,
            )

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
                    server_type=FlextLdifConstants.LdapServers.IBM_TIVOLI,
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"IBM Tivoli DS ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Wrap Tivoli DS ACL into generic RFC representation."""
            try:
                # Convert Novell ACL to RFC format using model_copy
                rfc_acl = acl_data.model_copy(update={"server_type": "rfc"})
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"IBM Tivoli DS ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Repackage RFC ACL payload for Tivoli DS."""
            try:
                # Convert RFC ACL to Novell format using model_copy
                ed_acl = acl_data.model_copy(update={"server_type": "tivoli"})
                return FlextResult[FlextLdifModels.Acl].ok(ed_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→IBM Tivoli DS ACL conversion failed: {exc}"
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

    class EntryQuirk(BaseEntryQuirk):
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

        server_type: ClassVar[str] = "generic"
        priority: ClassVar[int] = 200

        def __init__(
            self,
            server_type: str = FlextLdifConstants.LdapServers.IBM_TIVOLI,
            priority: int = 15,
        ) -> None:
            """Initialize IBM Tivoli DS entry quirk."""
            super().__init__(server_type=server_type, priority=priority)

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
                    in FlextLdifQuirksServersTivoli.TIVOLI_OBJECTCLASS_NAMES
                    for oc in object_classes
                )
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
                    rfc_entry
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry→RFC conversion failed: {exc}"
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
                    FlextLdifConstants.DictKeys.DN: normalized_dn
                }
                for key, value in entry_data.items():
                    if key != FlextLdifConstants.DictKeys.DN:
                        normalized_name = self.normalize_attribute_name(str(key))
                        tivoli_entry[normalized_name] = value

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    tivoli_entry
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"RFC→IBM Tivoli DS entry conversion failed: {exc}"
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
                        ).decode("utf-8")
                    else:
                        processed_attributes[attr_name] = attr_value

                processed_entry: dict[str, object] = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.IBM_TIVOLI,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=ibm" in dn_lower
                    or "cn=configuration" in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersTivoli"]
