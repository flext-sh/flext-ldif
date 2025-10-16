"""Apache Directory Server quirks implementation."""

from __future__ import annotations

import base64
import re
from typing import ClassVar

from flext_core import FlextResult, FlextTypes
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersApache(FlextLdifQuirksBaseSchemaQuirk):
    """Schema quirks for Apache Directory Server (ApacheDS)."""

    server_type: str = Field(
        default=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
        description="Apache Directory Server type",
    )
    priority: int = Field(
        default=15, description="Standard priority for ApacheDS parsing"
    )

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

    def model_post_init(self, _context: object, /) -> None:
        """Initialise ApacheDS schema quirk."""

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

    def parse_attribute(self, attr_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse ApacheDS attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    "ApacheDS attribute definition is missing an OID"
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

            attr_data: FlextLdifTypes.Dict = {
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

            return FlextResult[FlextLdifTypes.Dict].ok(attr_data)

        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Apache Directory Server attribute parsing failed: {exc}"
            )

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

    def parse_objectclass(self, oc_definition: str) -> FlextResult[FlextLdifTypes.Dict]:
        """Parse ApacheDS objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[FlextLdifTypes.Dict].fail(
                    "ApacheDS objectClass definition is missing an OID"
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

            oc_data: FlextLdifTypes.Dict = {
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

            return FlextResult[FlextLdifTypes.Dict].ok(oc_data)

        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Apache Directory Server objectClass parsing failed: {exc}"
            )

    def convert_attribute_to_rfc(
        self,
        attr_data: FlextLdifTypes.Dict,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert ApacheDS attribute metadata to an RFC-friendly payload."""
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

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Apache Directory Server→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self,
        oc_data: FlextLdifTypes.Dict,
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert ApacheDS objectClass metadata to an RFC-friendly payload."""
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

            return FlextResult[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"Apache Directory Server→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant attribute to ApacheDS-specific format."""
        try:
            apache_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[FlextLdifTypes.Dict].ok(apache_data)
        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→Apache Directory Server attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifTypes.Dict
    ) -> FlextResult[FlextLdifTypes.Dict]:
        """Convert RFC-compliant objectClass to ApacheDS-specific format."""
        try:
            apache_data = {
                **rfc_data,
                FlextLdifConstants.DictKeys.SERVER_TYPE: self.server_type,
            }
            return FlextResult[FlextLdifTypes.Dict].ok(apache_data)
        except Exception as exc:  # pragma: no cover
            return FlextResult[FlextLdifTypes.Dict].fail(
                f"RFC→Apache Directory Server objectClass conversion failed: {exc}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
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
        except Exception as exc:  # pragma: no cover
            return FlextResult[str].fail(
                f"Apache Directory Server attribute write failed: {exc}"
            )

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifTypes.Dict
    ) -> FlextResult[str]:
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
        except Exception as exc:  # pragma: no cover
            return FlextResult[str].fail(
                f"Apache Directory Server objectClass write failed: {exc}"
            )

    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Apache Directory Server ACI quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            description="Apache Directory Server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for ApacheDS ACL"
        )

        ACI_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
            "ads-aci",
            FlextLdifConstants.DictKeys.ACI,
        ])
        CLAUSE_PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"\([^()]+\)")

        def model_post_init(self, _context: object, /) -> None:
            """Initialize ApacheDS ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Detect ApacheDS ACI lines."""
            normalized = acl_line.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if attr_name.strip().lower() in self.ACI_ATTRIBUTE_NAMES:
                return True

            return normalized.lower().startswith("(version")

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifTypes.Dict]:
            """Parse ApacheDS ACI definition."""
            try:
                attr_name, content = self._split_acl_line(acl_line)
                clauses = [
                    clause.strip() for clause in self.CLAUSE_PATTERN.findall(content)
                ]
                acl_payload: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: attr_name,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.DATA: {
                        "clauses": clauses,
                        "content": content.strip(),
                        "attribute": attr_name,
                    },
                }
                return FlextResult[FlextLdifTypes.Dict].ok(acl_payload)

            except Exception as exc:  # pragma: no cover
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"Apache Directory Server ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifTypes.Dict,
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Wrap ApacheDS ACL into a generic RFC representation."""
            try:
                # Type narrowing: rfc_acl is already FlextLdifTypes.Dict (FlextTypes.Dict)
                rfc_acl: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[FlextLdifTypes.Dict].ok(rfc_acl)

            except Exception as exc:  # pragma: no cover
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"Apache Directory Server ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifTypes.Dict,
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Repackage RFC ACL payload for ApacheDS."""
            try:
                # Type narrowing: apache_acl is already FlextLdifTypes.Dict (FlextTypes.Dict)
                apache_acl: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.ACI,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.ACI,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }
                return FlextResult[FlextLdifTypes.Dict].ok(apache_acl)

            except Exception as exc:  # pragma: no cover
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"RFC→Apache Directory Server ACL conversion failed: {exc}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifTypes.Dict) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Apache Directory Server ACLs use ACI format.
            """
            try:
                acl_attribute = acl_data.get(
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE,
                    FlextLdifConstants.DictKeys.ACI,
                )
                data_raw = acl_data.get(FlextLdifConstants.DictKeys.DATA, {})
                data: FlextLdifTypes.Dict = (
                    data_raw if isinstance(data_raw, dict) else {}
                )
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
            except Exception as exc:
                return FlextResult[str].fail(
                    f"Apache Directory Server ACL write failed: {exc}"
                )

        @staticmethod
        def _split_acl_line(acl_line: str) -> tuple[str, str]:
            """Split an ACL line into attribute name and payload."""
            attr_name, _, remainder = acl_line.partition(":")
            return attr_name.strip(), remainder.strip()

    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Entry quirks for Apache Directory Server."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
            description="Apache Directory Server type",
        )
        priority: int = Field(
            default=15, description="Standard priority for ApacheDS entry handling"
        )

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

        def model_post_init(self, _context: object, /) -> None:
            """Initialise ApacheDS entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextTypes.Dict,
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
            attributes: FlextTypes.Dict,
        ) -> FlextResult[FlextLdifTypes.Dict]:
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

                processed_attributes: FlextLdifTypes.Dict = {}
                for attr_name, attr_value in attributes.items():
                    if isinstance(attr_value, bytes):
                        processed_attributes[attr_name] = base64.b64encode(
                            attr_value
                        ).decode("ascii")
                    else:
                        processed_attributes[attr_name] = attr_value

                processed_entry: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.DN: entry_dn,
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.APACHE_DIRECTORY,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "ou=config"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextResult[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as exc:  # pragma: no cover
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"Apache Directory Server entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Dict,
        ) -> FlextResult[FlextLdifTypes.Dict]:
            """Strip ApacheDS metadata before RFC processing."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                return FlextResult[FlextLdifTypes.Dict].ok(normalized_entry)

            except Exception as exc:  # pragma: no cover
                return FlextResult[FlextLdifTypes.Dict].fail(
                    f"Apache Directory Server entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersApache"]
