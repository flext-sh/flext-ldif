"""IBM Tivoli Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult
from pydantic import Field

# Pydantic removed
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    BaseAclQuirk,
    BaseEntryQuirk,
    BaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


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

    def __init__(
        self,
        server_type: str = FlextLdifConstants.LdapServers.IBM_TIVOLI,
        priority: int = 15,
    ) -> None:
        """Initialize Tivoli schema quirk.

        Args:
            server_type: IBM Tivoli Directory Server type
            priority: Standard priority for Tivoli parsing

        """
        super().__init__(server_type=server_type, priority=priority)

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
        """Parse Tivoli DS attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    "IBM Tivoli DS attribute definition is missing an OID"
                )

            name_tokens = re.findall(
                r"NAME\s+\(?\s*'([^']+)'", attr_definition, re.IGNORECASE
            )
            primary_name = name_tokens[0] if name_tokens else oid_match.group(1)

            desc_match = re.search(r"DESC\s+'([^']+)'", attr_definition, re.IGNORECASE)
            sup_match = re.search(r"SUP\s+([\w-]+)", attr_definition, re.IGNORECASE)
            equality_match = re.search(
                r"EQUALITY\s+([\w-]+)", attr_definition, re.IGNORECASE
            )
            ordering_match = re.search(
                r"ORDERING\s+([\w-]+)", attr_definition, re.IGNORECASE
            )
            substr_match = re.search(
                r"SUBSTR\s+([\w-]+)", attr_definition, re.IGNORECASE
            )
            syntax_match = re.search(
                r"SYNTAX\s+([\d.]+)(?:\{(\d+)\})?", attr_definition, re.IGNORECASE
            )
            single_value = bool(
                re.search(r"\bSINGLE-VALUE\b", attr_definition, re.IGNORECASE)
            )

            # Extract syntax length if present
            length_val: int | None = None
            if syntax_match and syntax_match.group(2):
                length_val = int(syntax_match.group(2))

            # Build metadata for server-specific data
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="tivoli",
                custom_data={},
                extensions={
                    "aliases": name_tokens or None,
                },
            )

            # Build SchemaAttribute model
            schema_attr = FlextLdifModels.SchemaAttribute(
                oid=oid_match.group(1),
                name=primary_name,
                desc=desc_match.group(1) if desc_match else None,
                syntax=syntax_match.group(1) if syntax_match else None,
                length=length_val,
                equality=equality_match.group(1) if equality_match else None,
                ordering=ordering_match.group(1) if ordering_match else None,
                substr=substr_match.group(1) if substr_match else None,
                single_value=single_value,
                usage=None,  # Tivoli stub - usage not extracted
                sup=sup_match.group(1) if sup_match else None,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"IBM Tivoli DS attribute parsing failed: {exc}"
            )

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
        """Parse Tivoli DS objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "IBM Tivoli DS objectClass definition is missing an OID"
                )

            name_tokens = re.findall(
                r"NAME\s+\(?\s*'([^']+)'", oc_definition, re.IGNORECASE
            )
            primary_name = name_tokens[0] if name_tokens else oid_match.group(1)

            desc_match = re.search(r"DESC\s+'([^']+)'", oc_definition, re.IGNORECASE)
            sup_match = re.search(r"SUP\s+([\w-]+)", oc_definition, re.IGNORECASE)

            must_match = re.search(r"MUST\s+\(([^)]+)\)", oc_definition, re.IGNORECASE)
            may_match = re.search(r"MAY\s+\(([^)]+)\)", oc_definition, re.IGNORECASE)
            must_attrs = (
                [attr.strip() for attr in must_match.group(1).split("$")]
                if must_match
                else []
            )
            may_attrs = (
                [attr.strip() for attr in may_match.group(1).split("$")]
                if may_match
                else []
            )

            if re.search(r"\bSTRUCTURAL\b", oc_definition, re.IGNORECASE):
                kind = FlextLdifConstants.Schema.STRUCTURAL
            elif re.search(r"\bAUXILIARY\b", oc_definition, re.IGNORECASE):
                kind = FlextLdifConstants.Schema.AUXILIARY
            elif re.search(r"\bABSTRACT\b", oc_definition, re.IGNORECASE):
                kind = FlextLdifConstants.Schema.ABSTRACT
            else:
                kind = FlextLdifConstants.Schema.STRUCTURAL

            # Build metadata for server-specific data
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="tivoli",
                custom_data={},
                extensions={
                    "aliases": name_tokens or None,
                },
            )

            # Build SchemaObjectClass model
            schema_oc = FlextLdifModels.SchemaObjectClass(
                oid=oid_match.group(1),
                name=primary_name,
                desc=desc_match.group(1) if desc_match else None,
                sup=sup_match.group(1) if sup_match else None,
                kind=kind,
                must=[attr for attr in must_attrs if attr],
                may=[attr for attr in may_attrs if attr],
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(schema_oc)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"IBM Tivoli DS objectClass parsing failed: {exc}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert Tivoli attribute metadata to an RFC-friendly payload."""
        try:
            # Build RFC-compliant SchemaAttribute model using direct field access
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

        except Exception as exc:
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

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"IBM Tivoli DS→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to IBM Tivoli DS-specific format."""
        try:
            # Use model_copy to add Novell-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="tivoli",
                custom_data={},
                extensions={},
            )
            tivoli_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(tivoli_data)
        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→IBM Tivoli DS attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to IBM Tivoli DS-specific format."""
        try:
            # Use model_copy to add Novell-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="tivoli",
                custom_data={},
                extensions={},
            )
            tivoli_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(tivoli_data)
        except Exception as exc:
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
        except Exception as exc:
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
        except Exception as exc:
            return FlextResult[str].fail(
                f"IBM Tivoli DS objectClass write failed: {exc}"
            )

    class AclQuirk(BaseAclQuirk):
        """IBM Tivoli DS ACL quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.IBM_TIVOLI,
            description="IBM Tivoli DS server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for Tivoli DS ACL"
        )

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])

        def model_post_init(self, _context: object, /) -> None:
            """Initialize Tivoli DS ACL quirk."""

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
                    name="IBM Tivoli DS ACL",
                    target=FlextLdifModels.AclTarget(
                        target_dn=scope,  # Novell: scope is target DN
                        attributes=None,  # Novell stub - not extracted from segments
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="trustee",
                        subject_value=trustee or "unknown",
                    ),
                    permissions=FlextLdifModels.AclPermissions(
                        read="read" in rights if isinstance(rights, list) else False,
                        write="write" in rights if isinstance(rights, list) else False,
                        add="add" in rights if isinstance(rights, list) else False,
                        delete="delete" in rights
                        if isinstance(rights, list)
                        else False,
                        search="search" in rights
                        if isinstance(rights, list)
                        else False,
                        compare="compare" in rights
                        if isinstance(rights, list)
                        else False,
                    ),
                    server_type="tivoli",
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as exc:
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

            except Exception as exc:
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

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→IBM Tivoli DS ACL conversion failed: {exc}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            IBM Tivoli DS ACLs use "#" delimited segments:
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
            except Exception as exc:
                return FlextResult[str].fail(f"IBM Tivoli DS ACL write failed: {exc}")

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class EntryQuirk(BaseEntryQuirk):
        """IBM Tivoli DS entry quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.IBM_TIVOLI,
            description="IBM Tivoli DS server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for Tivoli DS entry"
        )

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
            """Initialize Tivoli DS entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> bool:
            """Detect Tivoli DS-specific entries."""
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

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise Tivoli DS entries and expose metadata."""
            try:
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.IBM_TIVOLI,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Remove Tivoli DS metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"IBM Tivoli DS entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersTivoli"]
