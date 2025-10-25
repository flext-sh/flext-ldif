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

from flext_core import FlextResult
from pydantic import Field

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.quirks.base import (
    BaseAclQuirk,
    BaseEntryQuirk,
    BaseSchemaQuirk,
)
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifQuirksServersAd(BaseSchemaQuirk):
    """Active Directory schema quirk."""

    def __init__(
        self,
        server_type: str = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY,
        priority: int = 15,
    ) -> None:
        """Initialize with Active Directory defaults.

        Args:
            server_type: Active Directory server type
            priority: Standard priority for AD parsing

        """
        super().__init__(server_type=server_type, priority=priority)

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
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Parse an Active Directory attribute definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", attr_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaAttribute].fail(
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

            # Create SchemaAttribute model with AD-specific metadata
            attribute = FlextLdifModels.SchemaAttribute(
                oid=oid_match.group(1),
                name=primary_name,
                desc=desc_match.group(1) if desc_match else None,
                sup=sup_match.group(1) if sup_match else None,
                equality=equality_match.group(1) if equality_match else None,
                ordering=ordering_match.group(1) if ordering_match else None,
                substr=substr_match.group(1) if substr_match else None,
                syntax=syntax_match.group(1) if syntax_match else None,
                single_value=single_value,
                length=None,
                usage=None,
                metadata=FlextLdifModels.QuirkMetadata(
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    quirk_data={},
                ),
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(attribute)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
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
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Parse an Active Directory objectClass definition."""
        try:
            oid_match = re.search(r"\(\s*([\d.]+)", oc_definition)
            if not oid_match:
                return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
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
                kind = FlextLdifConstants.Schema.STRUCTURAL
            elif re.search(r"\bAUXILIARY\b", oc_definition, re.IGNORECASE):
                kind = FlextLdifConstants.Schema.AUXILIARY
            elif re.search(r"\bABSTRACT\b", oc_definition, re.IGNORECASE):
                kind = FlextLdifConstants.Schema.ABSTRACT
            else:
                kind = FlextLdifConstants.Schema.STRUCTURAL

            # Build metadata for server type
            metadata = FlextLdifModels.QuirkMetadata(
                server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                    self.server_type
                ),
                quirk_type="ad",
            )

            # Build SchemaObjectClass model
            oc_data = FlextLdifModels.SchemaObjectClass(
                oid=oid_match.group(1),
                name=primary_name,
                desc=desc_match.group(1) if desc_match else None,
                sup=sup_match.group(1) if sup_match else None,
                must=[attr for attr in must_attrs if attr],
                may=[attr for attr in may_attrs if attr],
                kind=kind,
                metadata=metadata,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(oc_data)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"Active Directory objectClass parsing failed: {exc}"
            )

    # --------------------------------------------------------------------- #
    # Schema conversion helpers
    # --------------------------------------------------------------------- #
    def convert_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert an AD attribute payload into a pure RFC representation."""
        try:
            rfc_model = FlextLdifModels.SchemaAttribute(
                oid=attr_data.oid,
                name=attr_data.name or attr_data.oid,
                desc=attr_data.desc,
                syntax=attr_data.syntax,
                equality=attr_data.equality,
                ordering=attr_data.ordering,
                substr=attr_data.substr,
                single_value=attr_data.single_value,
                sup=attr_data.sup,
                length=attr_data.length,
                usage=attr_data.usage,
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(rfc_model)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"Active Directory→RFC attribute conversion failed: {exc}"
            )

    def convert_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert an AD objectClass payload into RFC representation."""
        try:
            rfc_model = FlextLdifModels.SchemaObjectClass(
                oid=oc_data.oid,
                name=oc_data.name or oc_data.oid,
                desc=oc_data.desc,
                sup=oc_data.sup,
                kind=oc_data.kind,
                must=oc_data.must,
                may=oc_data.may,
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(rfc_model)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"Active Directory→RFC objectClass conversion failed: {exc}"
            )

    def convert_attribute_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
        """Convert RFC-compliant attribute to Active Directory-specific format.

        Args:
        rfc_data: RFC-compliant attribute data

        Returns:
        FlextResult with Active Directory attribute data

        """
        try:
            # Convert RFC format to AD format by creating new model with AD metadata
            ad_model = FlextLdifModels.SchemaAttribute(
                oid=rfc_data.oid,
                name=rfc_data.name,
                desc=rfc_data.desc,
                sup=rfc_data.sup,
                equality=rfc_data.equality,
                ordering=rfc_data.ordering,
                substr=rfc_data.substr,
                syntax=rfc_data.syntax,
                single_value=rfc_data.single_value,
                length=rfc_data.length,
                usage=rfc_data.usage,
                metadata=FlextLdifModels.QuirkMetadata(
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    quirk_data={},
                ),
            )

            return FlextResult[FlextLdifModels.SchemaAttribute].ok(ad_model)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaAttribute].fail(
                f"RFC→Active Directory attribute conversion failed: {exc}"
            )

    def convert_objectclass_from_rfc(
        self, rfc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
        """Convert RFC-compliant objectClass to Active Directory-specific format.

        Args:
        rfc_data: RFC-compliant objectClass data

        Returns:
        FlextResult with Active Directory objectClass data

        """
        try:
            # Convert RFC format to AD format by creating new model with AD metadata
            ad_model = FlextLdifModels.SchemaObjectClass(
                oid=rfc_data.oid,
                name=rfc_data.name,
                desc=rfc_data.desc,
                sup=rfc_data.sup,
                kind=rfc_data.kind,
                must=rfc_data.must,
                may=rfc_data.may,
                metadata=FlextLdifModels.QuirkMetadata(
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    quirk_data={},
                ),
            )

            return FlextResult[FlextLdifModels.SchemaObjectClass].ok(ad_model)

        except Exception as exc:
            return FlextResult[FlextLdifModels.SchemaObjectClass].fail(
                f"RFC→Active Directory objectClass conversion failed: {exc}"
            )

    def write_attribute_to_rfc(
        self, attr_data: FlextLdifModels.SchemaAttribute
    ) -> FlextResult[str]:
        """Write attribute data to RFC-compliant string format.

        Args:
        attr_data: Attribute data dictionary

        Returns:
        FlextResult with RFC-compliant attribute string

        """
        try:
            # Build RFC 4512 compliant attribute definition
            oid = attr_data.oid or ""
            name = attr_data.name or ""
            desc = attr_data.desc
            syntax = attr_data.syntax
            equality = attr_data.equality
            single_value = attr_data.single_value

            # Build attribute string
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
                f"Active Directory attribute write failed: {exc}"
            )

    def write_objectclass_to_rfc(
        self, oc_data: FlextLdifModels.SchemaObjectClass
    ) -> FlextResult[str]:
        """Write objectClass data to RFC-compliant string format.

        Args:
        oc_data: ObjectClass data dictionary

        Returns:
        FlextResult with RFC-compliant objectClass string

        """
        try:
            # Build RFC 4512 compliant objectClass definition
            oid = oc_data.oid or ""
            name = oc_data.name or ""
            desc = oc_data.desc
            sup = oc_data.sup
            kind = oc_data.kind
            must = oc_data.must or []
            may = oc_data.may or []

            # Build objectClass string
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
                f"Active Directory objectClass write failed: {exc}"
            )

    # ===================================================================== #
    # Nested ACL quirk
    # ===================================================================== #
    class AclQuirk(BaseAclQuirk):
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

        def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse nTSecurityDescriptor values and expose best-effort SDDL."""
            try:
                line = acl_line.strip()
                if not line:
                    return FlextResult[FlextLdifModels.Acl].fail(
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

                # Create Acl model with minimal fields for AD SDDL format
                acl_model = FlextLdifModels.Acl(
                    name=attr_name,
                    target=FlextLdifModels.AclTarget(
                        target_dn="*",
                        attributes=[],
                    ),
                    subject=FlextLdifModels.AclSubject(
                        subject_type="sddl",
                        subject_value=decoded_sddl or raw_value or "",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Active Directory ACL parsing failed: {exc}"
                )

        def convert_acl_to_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Convert an AD ACL payload into the generic RFC representation."""
            try:
                # Convert to RFC format by creating new Acl with generic server_type
                rfc_acl = FlextLdifModels.Acl(
                    name=acl_data.name,
                    target=acl_data.target,
                    subject=acl_data.subject,
                    permissions=acl_data.permissions,
                    server_type="generic",
                    raw_acl=acl_data.raw_acl,
                )

                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Active Directory ACL→RFC conversion failed: {exc}"
                )

        def convert_acl_from_rfc(
            self,
            acl_data: FlextLdifModels.Acl,
        ) -> FlextResult[FlextLdifModels.Acl]:
            """Translate a generic ACL payload back into AD notation metadata."""
            try:
                # Convert from RFC format by creating new Acl with AD server_type
                ad_acl = FlextLdifModels.Acl(
                    name=acl_data.name,
                    target=acl_data.target,
                    subject=acl_data.subject,
                    permissions=acl_data.permissions,
                    server_type=FlextLdifUtilities.normalize_server_type_for_literal(
                        self.server_type
                    ),
                    raw_acl=acl_data.raw_acl,
                )

                return FlextResult[FlextLdifModels.Acl].ok(ad_acl)

            except Exception as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Active Directory ACL conversion failed: {exc}"
                )

        def write_acl_to_rfc(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
            """Write ACL data to RFC-compliant string format.

            Active Directory ACLs use nTSecurityDescriptor format.

            Args:
            acl_data: ACL data dictionary

            Returns:
            FlextResult with ACL string in AD nTSecurityDescriptor format

            """
            try:
                # Get the raw ACL value
                raw_value = acl_data.raw_acl or ""
                acl_attribute = FlextLdifConstants.DictKeys.NTSECURITYDESCRIPTOR

                # Use the raw ACL value
                sddl_value = raw_value

                # Format as LDIF attribute line
                # AD typically uses base64 encoding for nTSecurityDescriptor
                if sddl_value:
                    acl_str = f"{acl_attribute}: {sddl_value}"
                else:
                    acl_str = f"{acl_attribute}:"

                return FlextResult[str].ok(acl_str)

            except Exception as exc:
                return FlextResult[str].fail(
                    f"Active Directory ACL write failed: {exc}"
                )

    # ===================================================================== #
    # Nested entry quirk
    # ===================================================================== #
    class EntryQuirk(BaseEntryQuirk):
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
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
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
            attributes: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Normalise Active Directory entries and surface metadata."""
            try:
                # Suppress unused parameter warning - required by interface
                _ = entry_dn
                object_classes_raw = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS, []
                )
                object_classes = (
                    object_classes_raw
                    if isinstance(object_classes_raw, list)
                    else [object_classes_raw]
                )

                # Process attributes (e.g., encode binary values)
                processed_attributes: FlextLdifTypes.Models.EntryAttributesDict = {}
                for attr_name, attr_value in attributes.items():
                    if isinstance(attr_value, bytes):
                        processed_attributes[attr_name] = base64.b64encode(
                            attr_value
                        ).decode("ascii")
                    else:
                        processed_attributes[attr_name] = attr_value

                # Ensure objectClass is included
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_attributes
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Active Directory entry processing failed: {exc}"
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Strip AD-only metadata before handing control to RFC logic."""
            try:
                normalized_entry = dict(entry_data)
                normalized_entry.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                normalized_entry.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                normalized_entry.pop(
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT, None
                )
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry
                )

            except Exception as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Active Directory entry→RFC conversion failed: {exc}"
                )


__all__ = ["FlextLdifQuirksServersAd"]
