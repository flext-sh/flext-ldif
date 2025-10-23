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

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersNovell(FlextLdifQuirksBaseSchemaQuirk):
    """Novell eDirectory schema quirk."""

    server_type: str = Field(
        default=FlextLdifConstants.LdapServers.NOVELL_EDIRECTORY,
        description="Novell eDirectory server type",
    )
    priority: int = Field(
        default=15, description="Standard priority for eDirectory parsing"
    )

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

    def model_post_init(self, _context: object, /) -> None:
        """Initialize eDirectory schema quirk."""

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

    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
        """Parse eDirectory attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[dict[str, object]].fail(
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

            attr_data: dict[str, object] = {
                FlextLdifConstants.DictKeys.OID: oid_match.group(1),
                FlextLdifConstants.DictKeys.NAME: primary_name,
                FlextLdifConstants.DictKeys.DESC: desc_match.group(1)
                if desc_match
                else None,
                FlextLdifConstants.DictKeys.SUP: sup_match.group(1)
                if sup_match
                else None,
                FlextLdifConstants.DictKeys.EQUALITY: equality_match.group(1)
                if equality_match
                else None,
                FlextLdifConstants.DictKeys.ORDERING: ordering_match.group(1)
                if ordering_match
                else None,
                FlextLdifConstants.DictKeys.SUBSTR: substr_match.group(1)
                if substr_match
                else None,
                FlextLdifConstants.DictKeys.SYNTAX: syntax_match.group(1)
                if syntax_match
                else None,
                FlextLdifConstants.DictKeys.SINGLE_VALUE: single_value,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }

            if syntax_match and syntax_match.group(2):
                attr_data["syntax_length"] = int(syntax_match.group(2))

            if name_tokens:
                attr_data["aliases"] = name_tokens

            return FlextResult[dict[str, object]].ok(attr_data)

        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
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

    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
        """Parse eDirectory objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[dict[str, object]].fail(
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
                kind = "STRUCTURAL"
            elif re.search(r"\bAUXILIARY\b", oc_definition, re.IGNORECASE):
                kind = "AUXILIARY"
            elif re.search(r"\bABSTRACT\b", oc_definition, re.IGNORECASE):
                kind = "ABSTRACT"
            else:
                kind = "STRUCTURAL"

            oc_data: dict[str, object] = {
                FlextLdifConstants.DictKeys.OID: oid_match.group(1),
                FlextLdifConstants.DictKeys.NAME: primary_name,
                FlextLdifConstants.DictKeys.DESC: desc_match.group(1)
                if desc_match
                else None,
                FlextLdifConstants.DictKeys.SUP: sup_match.group(1)
                if sup_match
                else None,
                FlextLdifConstants.DictKeys.MUST: [attr for attr in must_attrs if attr],
                FlextLdifConstants.DictKeys.MAY: [attr for attr in may_attrs if attr],
                FlextLdifConstants.DictKeys.KIND: kind,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }

            if name_tokens:
                oc_data["aliases"] = name_tokens

            return FlextResult[dict[str, object]].ok(oc_data)

        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"Novell eDirectory objectClass parsing failed: {exc}"
            )

    def convert_attribute_to_rfc(
        self,
        attr_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Convert eDirectory attribute metadata to RFC representation."""
        try:
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: attr_data.get(
                    FlextLdifConstants.DictKeys.OID
                ),
                FlextLdifConstants.DictKeys.NAME: attr_data.get(
                    FlextLdifConstants.DictKeys.NAME
                )
                or attr_data.get(FlextLdifConstants.DictKeys.OID),
                FlextLdifConstants.DictKeys.DESC: attr_data.get(
                    FlextLdifConstants.DictKeys.DESC
                ),
                FlextLdifConstants.DictKeys.SYNTAX: attr_data.get(
                    FlextLdifConstants.DictKeys.SYNTAX
                ),
                FlextLdifConstants.DictKeys.EQUALITY: attr_data.get(
                    FlextLdifConstants.DictKeys.EQUALITY
                ),
                FlextLdifConstants.DictKeys.ORDERING: attr_data.get(
                    FlextLdifConstants.DictKeys.ORDERING
                ),
                FlextLdifConstants.DictKeys.SUBSTR: attr_data.get(
                    FlextLdifConstants.DictKeys.SUBSTR
                ),
                FlextLdifConstants.DictKeys.SINGLE_VALUE: attr_data.get(
                    FlextLdifConstants.DictKeys.SINGLE_VALUE
                ),
                FlextLdifConstants.DictKeys.SUP: attr_data.get(
                    FlextLdifConstants.DictKeys.SUP
                ),
            }

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"Novell eDirectory→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self,
        oc_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Convert eDirectory objectClass metadata to RFC representation."""
        try:
            rfc_data = {
                FlextLdifConstants.DictKeys.OID: oc_data.get(
                    FlextLdifConstants.DictKeys.OID
                ),
                FlextLdifConstants.DictKeys.NAME: oc_data.get(
                    FlextLdifConstants.DictKeys.NAME
                )
                or oc_data.get(FlextLdifConstants.DictKeys.OID),
                FlextLdifConstants.DictKeys.DESC: oc_data.get(
                    FlextLdifConstants.DictKeys.DESC
                ),
                FlextLdifConstants.DictKeys.SUP: oc_data.get(
                    FlextLdifConstants.DictKeys.SUP
                ),
                FlextLdifConstants.DictKeys.KIND: oc_data.get(
                    FlextLdifConstants.DictKeys.KIND
                ),
                FlextLdifConstants.DictKeys.MUST: oc_data.get(
                    FlextLdifConstants.DictKeys.MUST
                ),
                FlextLdifConstants.DictKeys.MAY: oc_data.get(
                    FlextLdifConstants.DictKeys.MAY
                ),
            }

            return FlextResult[dict[str, object]].ok(rfc_data)

        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"Novell eDirectory→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant attribute to Novell eDirectory-specific format."""
        try:
            novell_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[dict[str, object]].ok(novell_data)
        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"RFC→Novell eDirectory attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant objectClass to Novell eDirectory-specific format."""
        try:
            novell_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[dict[str, object]].ok(novell_data)
        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"RFC→Novell eDirectory objectClass conversion failed: {exc}"
            )

    def write_attribute_to_rfc(self, attr_data: dict[str, object]) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format."""
        try:
            oid = attr_data.get(FlextLdifConstants.DictKeys.OID, "")
            name = attr_data.get(FlextLdifConstants.DictKeys.NAME, "")
            desc = attr_data.get(FlextLdifConstants.DictKeys.DESC)
            syntax = attr_data.get(FlextLdifConstants.DictKeys.SYNTAX)
            equality = attr_data.get(FlextLdifConstants.DictKeys.EQUALITY)
            single_value = attr_data.get(
                FlextLdifConstants.DictKeys.SINGLE_VALUE, False
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
        except Exception as exc:
            return FlextResult[str].fail(
                f"Novell eDirectory attribute write failed: {exc}"
            )

    def write_objectclass_to_rfc(self, oc_data: dict[str, object]) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format."""
        try:
            oid = oc_data.get(FlextLdifConstants.DictKeys.OID, "")
            name = oc_data.get(FlextLdifConstants.DictKeys.NAME, "")
            desc = oc_data.get(FlextLdifConstants.DictKeys.DESC)
            sup = oc_data.get(FlextLdifConstants.DictKeys.SUP)
            kind = oc_data.get(FlextLdifConstants.DictKeys.KIND, "STRUCTURAL")
            must = oc_data.get(FlextLdifConstants.DictKeys.MUST, [])
            may = oc_data.get(FlextLdifConstants.DictKeys.MAY, [])

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

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
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

        def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
            """Parse eDirectory ACL definition."""
            try:
                attr_name, content = self._splitacl_line(acl_line)
                segments = [segment for segment in content.split("#") if segment]

                acl_payload: dict[str, object] = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: attr_name,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.DATA: {
                        "segments": segments,
                        "scope": segments[0] if segments else None,
                        "trustee": segments[
                            FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_TRUSTEE
                        ]
                        if len(segments)
                        > FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_TRUSTEE
                        else None,
                        "rights": segments[
                            FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_RIGHTS :
                        ]
                        if len(segments)
                        > FlextLdifConstants.Acl.NOVELL_SEGMENT_INDEX_RIGHTS
                        else [],
                        "content": content.strip(),
                    },
                }
                return FlextResult[dict[str, object]].ok(acl_payload)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"Novell eDirectory ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Wrap eDirectory ACL into generic RFC representation."""
            try:
                # Type narrowing: rfc_acl is already dict[str, object] (FlextLdifTypes.Models.CustomDataDict)
                rfc_acl: dict[str, object] = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[dict[str, object]].ok(rfc_acl)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"Novell eDirectory ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Repackage RFC ACL payload for eDirectory."""
            try:
                # Type narrowing: ed_acl is already dict[str, object] (FlextLdifTypes.Models.CustomDataDict)
                ed_acl: dict[str, object] = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: "acl",
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[dict[str, object]].ok(ed_acl)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"RFC→Novell eDirectory ACL conversion failed: {exc}"
                )

        def write_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Novell eDirectory ACLs use "#" delimited segments:
            scope#trustee#rights#...
            """
            try:
                acl_attribute = acl_data.get(
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE,
                    "acl",
                )
                data_raw = acl_data.get(FlextLdifConstants.DictKeys.DATA, {})
                data: dict[str, object] = data_raw if isinstance(data_raw, dict) else {}

                # Check for existing content first
                content = data.get("content", "")
                if content:
                    # Use existing content if available
                    acl_str = f"{acl_attribute}: {content}"
                else:
                    # Build from structured segments
                    segments_raw = data.get("segments", [])
                    segments: list[str] = (
                        segments_raw if isinstance(segments_raw, list) else []
                    )

                    if segments:
                        # Use segments if available
                        acl_content = "#".join(segments)
                        acl_str = f"{acl_attribute}: {acl_content}"
                    else:
                        # Build from individual fields
                        scope = data.get("scope", "")
                        trustee = data.get("trustee", "")
                        rights_raw = data.get("rights", [])
                        rights: list[str] = (
                            rights_raw if isinstance(rights_raw, list) else []
                        )

                        parts = [scope, trustee]
                        parts.extend(rights)
                        # Filter empty parts and ensure they're strings
                        string_parts: list[str] = [str(p) for p in parts if p]

                        acl_content = "#".join(string_parts) if string_parts else ""
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

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
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
            attributes: FlextLdifTypes.Models.CustomDataDict,
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
            attributes: FlextLdifTypes.Models.CustomDataDict,
        ) -> FlextResult[dict[str, object]]:
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

                return FlextResult[dict[str, object]].ok(processed_entry)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"Novell eDirectory entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Remove eDirectory metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                return FlextResult[dict[str, object]].ok(normalized_entry)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"Novell eDirectory entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersNovell"]
