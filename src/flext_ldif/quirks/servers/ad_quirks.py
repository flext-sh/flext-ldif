"""Active Directory Quirks Implementation.

Provides Active Directory-specific schema, ACL, and entry handling so that
FLEXT LDIF can recognise Microsoft schema extensions, parse nTSecurityDescriptor
values, and normalise AD entries before handing them to the generic RFC logic.

The implementation focuses on pragmatic heuristics that reliably detect
Active Directory definitions without attempting to replicate the entire
Windows schema parser. The goal is to surface meaningful structured data
while keeping the interface aligned with the generic quirk contracts.

Copyright (c) 2025 FLEXT Team.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import ClassVar

from flext_core import FlextCore
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.quirks.base import (
    FlextLdifQuirksBaseAclQuirk,
    FlextLdifQuirksBaseEntryQuirk,
    FlextLdifQuirksBaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes


class FlextLdifQuirksServersAd(FlextLdifQuirksBaseSchemaQuirk):
    """Active Directory schema quirk."""

    server_type: str = Field(
        default=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
        description="Active Directory server type",
    )
    priority: int = Field(default=15, description="Standard priority for AD parsing")

    # Microsoft-owned schema namespace. All AD schema elements live under it.
    AD_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"\b1\.2\.840\.113556\.", re.IGNORECASE
    )

    # Frequently encountered attribute/objectClass markers (stored lower-case).
    AD_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
        "samaccountname",
        "objectguid",
        "objectsid",
        "userprincipalname",
        "unicodepwd",
        "useraccountcontrol",
        "primarygroupid",
        "logonhours",
        "lockouttime",
        "pwdlastset",
        "memberof",
        "msds-supportedencryptiontypes",
        "serviceprincipalname",
        "distinguishedname",
    ])
    AD_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
        "user",
        "computer",
        "group",
        "organizationalunit",
        "organizationalperson",
        "person",
        "domain",
        "domainpolicy",
        "foreignsecurityprincipal",
        "msds-groupmanagedserviceaccount",
        "msds-managedserviceaccount",
    ])

    def model_post_init(self, _context: object, /) -> None:
        """Initialize Active Directory schema quirk."""

    # --------------------------------------------------------------------- #
    # Schema attribute handling
    # --------------------------------------------------------------------- #
    def can_handle_attribute(self, attr_definition: str) -> bool:
        """Check if the attribute definition contains AD-specific markers."""
        attr_lower = attr_definition.lower()

        if self.AD_OID_PATTERN.search(attr_definition):
            return True

        if "microsoft active directory" in attr_lower:
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", attr_definition, re.IGNORECASE
        )
        if any(name.lower() in self.AD_ATTRIBUTE_NAMES for name in name_matches):
            return True

        return any(marker in attr_lower for marker in self.AD_ATTRIBUTE_NAMES)

    def parse_attribute(
        self, attr_definition: str
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Parse an Active Directory attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    "Active Directory attribute is missing an OID"
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
                r"SYNTAX\s+([\d.]+)", attr_definition, re.IGNORECASE
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

            return FlextCore.Result[FlextLdifTypes.Dict].ok(attr_data)

        except Exception as exc:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"Active Directory attribute parsing failed: {exc}"
            )

    # --------------------------------------------------------------------- #
    # Schema objectClass handling
    # --------------------------------------------------------------------- #
    def can_handle_objectclass(self, oc_definition: str) -> bool:
        """Detect Active Directory objectClass definitions."""
        if self.AD_OID_PATTERN.search(oc_definition):
            return True

        name_matches = re.findall(
            r"NAME\s+\(?\s*'([^']+)'", oc_definition, re.IGNORECASE
        )
        if any(name.lower() in self.AD_OBJECTCLASS_NAMES for name in name_matches):
            return True

        return any(
            marker in oc_definition.lower() for marker in self.AD_OBJECTCLASS_NAMES
        )

    def parse_objectclass(
        self, oc_definition: str
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Parse an Active Directory objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    "Active Directory objectClass is missing an OID"
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

            return FlextCore.Result[FlextLdifTypes.Dict].ok(oc_data)

        except Exception as exc:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"Active Directory objectClass parsing failed: {exc}"
            )

    # --------------------------------------------------------------------- #
    # Schema conversion helpers
    # --------------------------------------------------------------------- #
    def convert_attribute_to_rfc(
        self,
        attr_data: FlextLdifTypes.Dict,
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Convert an AD attribute payload into a pure RFC representation."""
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

            return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as exc:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"Active Directory→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self,
        oc_data: FlextLdifTypes.Dict,
    ) -> FlextCore.Result[FlextLdifTypes.Dict]:
        """Convert an AD objectClass payload into RFC representation."""
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

            return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_data)

        except Exception as exc:
            return FlextCore.Result[FlextLdifTypes.Dict].fail(
                f"Active Directory→RFC objectClass conversion failed: {exc}"
            )

    # ===================================================================== #
    # Nested ACL quirk
    # ===================================================================== #
    class AclQuirk(FlextLdifQuirksBaseAclQuirk):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            description="Active Directory server type",
        )
        priority: int = Field(default=15, description="Standard priority for AD ACL")

        # SDDL strings start with O:, G:, D:, or S:
        SDDL_PREFIX_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^(O:|G:|D:|S:)", re.IGNORECASE
        )

        def model_post_init(self, _context: object, /) -> None:
            """Initialize Active Directory ACL quirk."""

        def can_handle_acl(self, acl_line: str) -> bool:
            """Check whether the ACL line belongs to an AD security descriptor."""
            normalized = acl_line.strip()
            if not normalized:
                return False

            attr_name, _, _ = normalized.partition(":")
            if (
                attr_name.strip().lower()
                == FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR.lower()
            ):
                return True

            return bool(self.SDDL_PREFIX_PATTERN.match(normalized))

        def parse_acl(self, acl_line: str) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Parse nTSecurityDescriptor values and expose best-effort SDDL."""
            try:
                line = acl_line.strip()
                if not line:
                    return FlextCore.Result[FlextLdifTypes.Dict].fail(
                        "Empty ACL line cannot be parsed"
                    )

                attr_name, _, remainder = line.partition(":")
                attr_name = (
                    attr_name.strip()
                    or FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR
                )
                remainder = remainder.lstrip()
                is_base64 = False

                if remainder.startswith(":"):
                    remainder = remainder[1:].strip()
                    is_base64 = True

                raw_value = remainder
                decoded_sddl: str | None = None

                if is_base64 and raw_value:
                    try:
                        decoded_bytes = base64.b64decode(raw_value, validate=True)
                        decoded_sddl = (
                            decoded_bytes.decode("utf-16-le", errors="ignore").strip()
                            or decoded_bytes.decode("utf-8", errors="ignore").strip()
                        )
                    except (binascii.Error, UnicodeDecodeError):
                        decoded_sddl = None

                if (
                    not decoded_sddl
                    and raw_value
                    and self.SDDL_PREFIX_PATTERN.match(raw_value)
                ):
                    decoded_sddl = raw_value

                acl_payload: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.AclFormats.AD_ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.AD_NTSECURITY,
                    FlextLdifConstants.DictKeys.ACL_ATTRIBUTE: attr_name,
                    FlextLdifConstants.DictKeys.RAW: acl_line,
                    FlextLdifConstants.DictKeys.PARSED: decoded_sddl or raw_value or "",
                }

                if is_base64:
                    acl_payload[FlextLdifConstants.DictKeys.DATA] = raw_value

                return FlextCore.Result[FlextLdifTypes.Dict].ok(acl_payload)

            except Exception as exc:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"Active Directory ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifTypes.Dict,
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Convert an AD ACL payload into the generic RFC representation."""
            try:
                rfc_acl: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.TYPE: FlextLdifConstants.DictKeys.ACL,
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.RFC_GENERIC,
                    FlextLdifConstants.DictKeys.SOURCE_FORMAT: FlextLdifConstants.AclFormats.AD_ACL,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextCore.Result[FlextLdifTypes.Dict].ok(rfc_acl)

            except Exception as exc:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"Active Directory ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifTypes.Dict,
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Translate a generic ACL payload back into AD notation metadata."""
            try:
                ad_acl: FlextLdifTypes.Dict = {
                    FlextLdifConstants.DictKeys.FORMAT: FlextLdifConstants.AclFormats.AD_NTSECURITY,
                    FlextLdifConstants.DictKeys.TARGET_FORMAT: FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR,
                    FlextLdifConstants.DictKeys.DATA: acl_data,
                }

                return FlextCore.Result[FlextLdifTypes.Dict].ok(ad_acl)

            except Exception as exc:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"RFC→Active Directory ACL conversion failed: {exc}"
                )

    # ===================================================================== #
    # Nested entry quirk
    # ===================================================================== #
    class EntryQuirk(FlextLdifQuirksBaseEntryQuirk):
        """Active Directory entry processing quirk."""

        server_type: str = Field(
            default=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
            description="Active Directory server type",
        )
        priority: int = Field(default=15, description="Standard priority for AD entry")

        AD_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=users",
            "cn=computers",
            "cn=configuration",
            "cn=system",
            "ou=domain controllers",
        ])
        AD_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "objectguid",
            "objectsid",
            "samaccountname",
            "userprincipalname",
            "ntsecuritydescriptor",
            "useraccountcontrol",
            "serviceprincipalname",
            "lastlogontimestamp",
            "pwdlastset",
        ])

        def model_post_init(self, _context: object, /) -> None:
            """Initialize Active Directory entry quirk."""

        def can_handle_entry(
            self,
            entry_dn: str,
            attributes: FlextCore.Types.Dict,
        ) -> bool:
            """Detect Active Directory entries based on DN, attributes, or classes."""
            dn_lower = entry_dn.lower()
            if any(marker in dn_lower for marker in self.AD_DN_MARKERS):
                return True

            if "dc=" in dn_lower and "cn=configuration" in dn_lower:
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(marker in normalized_attrs for marker in self.AD_ATTRIBUTE_MARKERS):
                return True

            raw_object_classes = attributes.get(
                FlextLdifConstants.DictKeys.OBJECTCLASS, []
            )
            object_classes = (
                raw_object_classes
                if isinstance(raw_object_classes, list)
                else [raw_object_classes]
            )
            return bool(
                any(
                    str(oc).lower() in FlextLdifQuirksServersAd.AD_OBJECTCLASS_NAMES
                    for oc in object_classes
                )
            )

        def process_entry(
            self,
            entry_dn: str,
            attributes: FlextCore.Types.Dict,
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Normalise Active Directory entries and surface metadata."""
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
                    FlextLdifConstants.DictKeys.SERVER_TYPE: FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
                    FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY: "cn=configuration"
                    in dn_lower,
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT: "ou=" in dn_lower,
                    FlextLdifConstants.DictKeys.OBJECTCLASS: object_classes,
                }
                processed_entry.update(processed_attributes)

                return FlextCore.Result[FlextLdifTypes.Dict].ok(processed_entry)

            except Exception as exc:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"Active Directory entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Dict,
        ) -> FlextCore.Result[FlextLdifTypes.Dict]:
            """Strip AD-only metadata before handing control to RFC logic."""
            try:
                normalized_entry = dict[str, object](entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                normalized_entry.pop(
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT, None
                )
                return FlextCore.Result[FlextLdifTypes.Dict].ok(normalized_entry)

            except Exception as exc:
                return FlextCore.Result[FlextLdifTypes.Dict].fail(
                    f"Active Directory entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersAd"]
