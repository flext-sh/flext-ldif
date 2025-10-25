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


class FlextLdifQuirksServersNovell(BaseSchemaQuirk):
    """Novell eDirectory schema quirk."""

    NOVELL_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b2\.16\.840\.1\.113719\.", re.IGNORECASE
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
        r"NAME\s+\(?\s*'([^']+)'", re.IGNORECASE
    )

    def __init__(
        self,
        server_type: str = FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
        priority: int = 15,
    ) -> None:
        """Initialize eDirectory schema quirk.

        Args:
            server_type: Novell eDirectory server type
            priority: Standard priority for eDirectory parsing

        """
        super().__init__(server_type=server_type, priority=priority)

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

        return any(prefix in attr_lower for prefix in self.NOVELL_ATTRIBUTE_PREFIXES)

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse eDirectory attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                    "Novell eDirectory attribute definition is missing an OID"
                )

            name_tokens = self.ATTRIBUTE_NAME_REGEX.findall(attr_definition)
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
                quirk_type="novell",
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
                usage=None,  # Novell stub - usage not extracted
                sup=sup_match.group(1) if sup_match else None,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(schema_attr)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"Novell eDirectory attribute parsing failed: {exc}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Detect eDirectory objectClass definitions."""
        if self.NOVELL_OID_PATTERN.search(oc_definition):
            return True

        name_matches = self.ATTRIBUTE_NAME_REGEX.findall(oc_definition)
        return any(
            name.lower() in self.NOVELL_OBJECTCLASS_NAMES for name in name_matches
        )

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse eDirectory objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                    "Novell eDirectory objectClass definition is missing an OID"
                )

            name_tokens = self.ATTRIBUTE_NAME_REGEX.findall(oc_definition)
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
                quirk_type="novell",
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
                f"Novell eDirectory objectClass parsing failed: {exc}"
            )

    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert eDirectory attribute metadata to RFC representation."""
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
                f"Novell eDirectory→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert eDirectory objectClass metadata to RFC representation."""
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
                f"Novell eDirectory→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to Novell eDirectory-specific format."""
        try:
            # Use model_copy to add Novell-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="novell",
                custom_data={},
                extensions={},
            )
            novell_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaAttribute].ok(novell_data)
        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→Novell eDirectory attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to Novell eDirectory-specific format."""
        try:
            # Use model_copy to add Novell-specific metadata
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="novell",
                custom_data={},
                extensions={},
            )
            novell_data = rfc_data.model_copy(update={"metadata": metadata})
            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(novell_data)
        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→Novell eDirectory objectClass conversion failed: {exc}"
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
            return FlextResult[str].fail(
                f"Novell eDirectory attribute write failed: {exc}"
            )

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
                f"Novell eDirectory objectClass write failed: {exc}"
            )

    class AclQuirk(BaseAclQuirk):
        """Novell eDirectory ACL quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            description="Novell eDirectory server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for eDirectory ACL"
        )

        ACL_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "acl",
            "inheritedacl",
        ])

        def model_post_init(self, _context: object, /) -> None:
            """Initialize eDirectory ACL quirk."""

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
                    server_type="novell",
                    raw_acl=acl_line,
                )
                return FlextResult[FlextLdifModels.Acl].ok(acl)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Novell eDirectory ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Wrap eDirectory ACL into generic RFC representation."""
            try:
                # Convert Novell ACL to RFC format using model_copy
                rfc_acl = acl_data.model_copy(update={"server_type": "rfc"})
                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Novell eDirectory ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Repackage RFC ACL payload for eDirectory."""
            try:
                # Convert RFC ACL to Novell format using model_copy
                ed_acl = acl_data.model_copy(update={"server_type": "novell"})
                return FlextResult[FlextLdifModels.Acl].ok(ed_acl)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Novell eDirectory ACL conversion failed: {exc}"
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
            except Exception as exc:
                return FlextResult[str].fail(
                    f"Novell eDirectory ACL write failed: {exc}"
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class EntryQuirk(BaseEntryQuirk):
        """Novell eDirectory entry quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
            description="Novell eDirectory server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for eDirectory entry"
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
            """Initialize eDirectory entry quirk."""

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
                    in FlextLdifQuirksServersNovell.NOVELL_OBJECTCLASS_NAMES
                    for oc in object_classes
                )
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise eDirectory entries and expose metadata."""
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_entry
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Novell eDirectory entry processing failed: {exc}"
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
                    normalized_entry
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Novell eDirectory entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersNovell"]
