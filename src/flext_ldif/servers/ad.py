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
from typing import ClassVar, cast

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server quirks implementation.

    Extends RFC base quirks with Active Directory-specific handling for:
    - Schema: Microsoft schema extensions and OID namespace
    - ACL: nTSecurityDescriptor parsing and SDDL support
    - Entry: AD-specific entry transformations and normalization
    """

    # Top-level configuration for AD quirks
    server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
    priority: ClassVar[int] = 15

    def __init__(self) -> None:
        """Initialize AD quirks."""
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
        """Active Directory schema quirk."""

        # Active Directory configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
        priority: ClassVar[int] = 15

        # Microsoft-owned schema namespace. All AD schema elements live under it.
        AD_OID_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"\b1\.2\.840\.113556\.",
            re.IGNORECASE,
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

        # --------------------------------------------------------------------- #
        # Utility methods
        # --------------------------------------------------------------------- #
        @staticmethod
        def _normalize_server_type_for_literal(
            server_type: str,
        ) -> FlextLdifConstants.LiteralTypes.ServerType:
            """Normalize server type to literal-compatible form.

            Converts short-form identifiers (oid, oud) to long-form (oracle_oid, oracle_oud).
            Other types are returned as-is.

            Args:
                server_type: Server type identifier

            Returns:
                Normalized server type for LiteralTypes.ServerType

            """
            server_type_map: dict[str, FlextLdifConstants.LiteralTypes.ServerType] = {
                "oid": "oracle_oid",
                "oud": "oracle_oud",
            }
            return cast(
                "FlextLdifConstants.LiteralTypes.ServerType",
                server_type_map.get(server_type, server_type),
            )

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
                r"NAME\s+\(?\s*'([^']+)'",
                attr_definition,
                re.IGNORECASE,
            )
            if any(name.lower() in self.AD_ATTRIBUTE_NAMES for name in name_matches):
                return True

            return any(marker in attr_lower for marker in self.AD_ATTRIBUTE_NAMES)

        def can_handle_objectclass(self, oc_definition: str) -> bool:
            """Detect Active Directory objectClass definitions."""
            if self.AD_OID_PATTERN.search(oc_definition):
                return True

            name_matches = re.findall(
                r"NAME\s+\(?\s*'([^']+)'",
                oc_definition,
                re.IGNORECASE,
            )
            if any(name.lower() in self.AD_OBJECTCLASS_NAMES for name in name_matches):
                return True

            return any(
                marker in oc_definition.lower() for marker in self.AD_OBJECTCLASS_NAMES
            )

        # Nested class references for Schema - allows Schema().Entry() pattern
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Acl class."""
                super().__init__()

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
            priority: ClassVar[int] = 15

            def __init__(self) -> None:
                """Initialize by delegating to outer Entry class."""
                super().__init__()

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
        # Only can_handle_* methods are overridden with AD-specific logic.
        #
        # ===================================================================== #
        # Nested ACL quirk
        # ===================================================================== #

    class Acl(FlextLdifServersRfc.Acl):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        # SDDL strings start with O:, G:, D:, or S:
        SDDL_PREFIX_PATTERN: ClassVar[re.Pattern[str]] = re.compile(
            r"^(O:|G:|D:|S:)",
            re.IGNORECASE,
        )

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
        priority: ClassVar[int] = 15

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
                        "Empty ACL line cannot be parsed",
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
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        self.server_type,
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Active Directory ACL parsing failed: {exc}",
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
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        FlextLdifConstants.ServerTypes.GENERIC,
                    ),
                    raw_acl=acl_data.raw_acl,
                )

                return FlextResult[FlextLdifModels.Acl].ok(rfc_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Active Directory ACL→RFC conversion failed: {exc}",
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
                    server_type=cast(
                        "FlextLdifConstants.LiteralTypes.ServerType",
                        self.server_type,
                    ),
                    raw_acl=acl_data.raw_acl,
                )

                return FlextResult[FlextLdifModels.Acl].ok(ad_acl)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"RFC→Active Directory ACL conversion failed: {exc}",
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

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[str].fail(
                    f"Active Directory ACL write failed: {exc}",
                )

    # ===================================================================== #
    # Nested entry quirk
    # ===================================================================== #
    class Entry(FlextLdifServersRfc.Entry):
        """Active Directory entry processing quirk."""

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

        server_type: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
        priority: ClassVar[int] = 15

        def __init__(self) -> None:
            """Initialize Active Directory entry quirk."""
            super().__init__(server_type=FlextLdifConstants.ServerTypes.AD)

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with AD-specific logic:
        # - can_handle_entry(): Detects AD entries by DN/attributes
        # - process_entry(): Normalizes AD entries with metadata
        # - convert_entry_to_rfc(): Converts AD entries to RFC format

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
                FlextLdifConstants.DictKeys.OBJECTCLASS,
                [],
            )
            object_classes = (
                raw_object_classes
                if isinstance(raw_object_classes, list)
                else [raw_object_classes]
            )
            return bool(
                any(
                    str(oc).lower() in FlextLdifServersAd.Schema.AD_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
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
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
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
                            attr_value,
                        ).decode("ascii")
                    else:
                        processed_attributes[attr_name] = attr_value

                # Ensure objectClass is included
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    processed_attributes,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Active Directory entry processing failed: {exc}",
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
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT,
                    None,
                )
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                    normalized_entry,
                )

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].fail(
                    f"Active Directory entry→RFC conversion failed: {exc}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifTypes.Models.EntryAttributesDict,
        ) -> FlextResult[FlextLdifTypes.Models.EntryAttributesDict]:
            """Convert entry from RFC format - pass-through for Active Directory.

            Args:
            entry_data: RFC-compliant entry attributes

            Returns:
            FlextResult with data (unchanged, since AD entries are RFC-compliant)

            """
            return FlextResult[FlextLdifTypes.Models.EntryAttributesDict].ok(
                entry_data,
            )


__all__ = ["FlextLdifServersAd"]
