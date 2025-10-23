"""389 Directory Server quirks implementation."""

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


class FlextLdifQuirksServersDs389(FlextLdifQuirksBaseSchemaQuirk):
    """Schema quirks for Red Hat / 389 Directory Server."""

    server_type: str = Field(
        default=FlextLdifConstants.LdapServers.DS_389,
        description="389 Directory Server type",
    )
    priority: int = Field(
        default=15, description="Standard priority for 389 DS parsing"
    )

    DS389_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b2\.16\.840\.1\.113730\.", re.IGNORECASE
    )
    DS389_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
        "nsslapd-",
        "nsds",
        "nsuniqueid",
    ])
    DS389_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "nscontainer",
        "nsperson",
        "nsds5replica",
        "nsds5replicationagreement",
    ])

    def model_post_init(self, _context: object, /) -> None:
        """Initialise 389 DS schema quirk."""

    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Detect 389 DS attribute definitions."""
        attr_lower = attr_definition.lower()
        if self.DS389_OID_PATTERN.search(attr_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", attr_definition, re.IGNORECASE
        )
        if any(
            name.lower().startswith(tuple(self.DS389_ATTRIBUTE_PREFIXES))
            for name in name_matches
        ):
            return True

        return any(prefix in attr_lower for prefix in self.DS389_ATTRIBUTE_PREFIXES)

    def parse_attribute(self, attr_definition: str) -> FlextResult[dict[str, object]]:
        """Parse 389 DS attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[dict[str, object]].fail(
                    "389 Directory Server attribute definition is missing an OID"
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
                f"389 Directory Server attribute parsing failed: {exc}"
            )

    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Detect 389 DS objectClass definitions."""
        if self.DS389_OID_PATTERN.search(oc_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", oc_definition, re.IGNORECASE
        )
        return any(
            name.lower() in self.DS389_OBJECTCLASS_NAMES for name in name_matches
        )

    def parse_objectclass(self, oc_definition: str) -> FlextResult[dict[str, object]]:
        """Parse 389 DS objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[dict[str, object]].fail(
                    "389 Directory Server objectClass definition is missing an OID"
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
                f"389 Directory Server objectClass parsing failed: {exc}"
            )

    def convert_attribute_to_rfc(
        self,
        attr_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Convert 389 DS attribute metadata to an RFC-friendly payload."""
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
                f"389 Directory Server→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self,
        oc_data: dict[str, object],
    ) -> FlextResult[dict[str, object]]:
        """Convert 389 DS objectClass metadata to an RFC-friendly payload."""
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
                f"389 Directory Server→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant attribute to 389 DS-specific format."""
        try:
            ds389_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[dict[str, object]].ok(ds389_data)
        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"RFC→389 Directory Server attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Convert RFC-compliant objectClass to 389 DS-specific format."""
        try:
            ds389_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[dict[str, object]].ok(ds389_data)
        except Exception as exc:
            return FlextResult[dict[str, object]].fail(
                f"RFC→389 Directory Server objectClass conversion failed: {exc}"
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
                f"389 Directory Server attribute write failed: {exc}"
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
                f"389 Directory Server objectClass write failed: {exc}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """389 Directory Server ACI quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.DS_389,
            description="389 Directory Server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for 389 DS ACL"
        )

        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        def model_post_init(self, _context: object, /) -> None:
            """Initialise 389 DS ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect 389 DS ACI lines."""
            normalized = acl_line.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if attr_name.strip().lower() == FlextLdifConstants.DictKeys.ACI:
                return True

            return normalized.lower().startswith("(version")

        def parse_acl(self, acl_line: str) -> FlextResult[dict[str, object]]:
            """Parse 389 DS ACI definition."""
            try:
                attr_name, content = self._splitacl_line(acl_line)
                clauses = [
                    clause.strip() for clause in self.CLAUSE_PATTERN.findall(content)
                ]

                version_match = re.search(
                    r"version\s+([0-9.]+)", content, re.IGNORECASE
                )
                acl_name_match = re.search(
                    r"acl\s+\"([^\"]+)\"", content, re.IGNORECASE
                )
                permissions_match = re.search(
                    r"allow\s*\(([^)]+)\)", content, re.IGNORECASE
                )
                permissions = (
                    [perm.strip() for perm in permissions_match.group(1).split(",")]
                    if permissions_match
                    else []
                )
                target_attr_match = re.search(
                    r"targetattr\s*=\s*\"([^\"]+)\"", content, re.IGNORECASE
                )
                userdn_matches = re.findall(
                    r"userdn\s*=\s*\"([^\"]+)\"", content, re.IGNORECASE
                )

                acl_payload: dict[str, object] = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: attr_name,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.DATA: {
                        "clauses": clauses,
                        "version": version_match.group(1) if version_match else None,
                        "acl_name": acl_name_match.group(1) if acl_name_match else None,
                        "permissions": permissions,
                        "targetattr": target_attr_match.group(1)
                        if target_attr_match
                        else None,
                        "userdns": userdn_matches,
                        "content": content.strip(),
                    },
                }
                return FlextResult[dict[str, object]].ok(acl_payload)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"389 Directory Server ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Wrap 389 DS ACL into a generic RFC representation."""
            try:
                # Type narrowing: rfc_acl is already dict[str, object] (FlextLdifTypes.Models.CustomDataDict)
                rfc_acl: dict[str, object] = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[dict[str, object]].ok(rfc_acl)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"389 Directory Server ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Repackage RFC ACL payload for 389 DS."""
            try:
                # Type narrowing: ds_acl is already dict[str, object] (FlextLdifTypes.Models.CustomDataDict)
                ds_acl: dict[str, object] = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.DS389_ACL,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.ACI,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[dict[str, object]].ok(ds_acl)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"RFC→389 Directory Server ACL conversion failed: {exc}"
                )

        def write_acl_to_rfc(self, acl_data: dict[str, object]) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            389 Directory Server ACLs use ACI format with structured clauses.
            """
            try:
                acl_attribute = acl_data.get(
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE,
                    FlextLdifConstants.DictKeys.ACI,
                )
                data_raw = acl_data.get(FlextLdifConstants.DictKeys.DATA, {})
                data: dict[str, object] = data_raw if isinstance(data_raw, dict) else {}

                # Extract structured fields
                version = data.get("version")
                acl_name = data.get("acl_name")
                permissions_raw = data.get("permissions", [])
                permissions: list[str] = (
                    permissions_raw if isinstance(permissions_raw, list) else []
                )
                targetattr = data.get("targetattr")
                userdns_raw = data.get("userdns", [])
                userdns: list[str] = (
                    userdns_raw if isinstance(userdns_raw, list) else []
                )
                content = data.get("content", "")

                # Build ACI string from structured data if available
                if content:
                    # Use existing content if available
                    acl_str = f"{acl_attribute}: {content}"
                else:
                    # Build from structured fields
                    parts = []
                    if version:
                        parts.append(f"(version {version})")
                    if acl_name:
                        parts.append(f'acl "{acl_name}"')
                    if permissions:
                        perms = ", ".join(permissions)
                        parts.append(f"allow ({perms})")
                    if targetattr:
                        parts.append(f'targetattr = "{targetattr}"')
                    parts.extend(f'userdn = "{userdn}"' for userdn in userdns)

                    acl_content = "; ".join(parts) if parts else ""
                    acl_str = (
                        f"{acl_attribute}: {acl_content}"
                        if acl_content
                        else f"{acl_attribute}:"
                    )

                return FlextResult[str].ok(acl_str)
            except Exception as exc:
                return FlextResult[str].fail(
                    f"389 Directory Server ACL write failed: {exc}"
                )

        @staticmethod
        def _splitacl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Entry quirks for 389 Directory Server."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.DS_389,
            description="389 Directory Server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for 389 DS entry handling"
        )

        DS389_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=config",
            "cn=monitor",
            "cn=changelog",
        ])
        DS389_ATTRIBUTE_PREFIXES: ClassVar[frozenset[str]] = frozenset([
            "nsslapd-",
            "nsds",
            "nsuniqueid",
        ])

        def model_post_init(self, _context: object, /) -> None:
            """Initialise 389 DS entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.CustomDataDict,
        ) -> bool:
            """Detect 389 DS-specific entries."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.DS389_DN_MARKERS):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                attr.startswith(tuple(self.DS389_ATTRIBUTE_PREFIXES))
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
                    in FlextLdifQuirksServersDs389.DS389_OBJECTCLASS_NAMES
                    for oc in object_classes
                )
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextLdifTypes.Models.CustomDataDict,
        ) -> FlextResult[dict[str, object]]:
            """Normalise 389 DS entries and attach metadata."""
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.DS_389,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=config"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[dict[str, object]].ok(processed_entry)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"389 Directory Server entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: dict[str, object],
        ) -> FlextResult[dict[str, object]]:
            """Strip 389 DS metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                return FlextResult[dict[str, object]].ok(normalized_entry)

            except Exception as exc:
                return FlextResult[dict[str, object]].fail(
                    f"389 Directory Server entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersDs389"]
