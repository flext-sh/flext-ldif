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
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server quirks implementation.

    Extends RFC base quirks with Active Directory-specific handling for:
    - Schema: Microsoft schema extensions and OID namespace
    - ACL: nTSecurityDescriptor parsing and SDDL support
    - Entry: AD-specific entry transformations and normalization
    """

    # Top-level configuration for AD quirks
    server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
    priority: ClassVar[int] = 15

    def __getattr__(self, name: str) -> object:
        """Delegate method calls to nested Schema, Acl, or Entry instances.

        This enables calling schema/acl/entry methods directly on the main server instance.

        Args:
            name: Method or attribute name to look up

        Returns:
            Method or attribute from nested instance

        Raises:
            AttributeError: If attribute not found in any nested instance

        """
        # Try schema methods first (most common)
        if hasattr(self.schema, name):
            return getattr(self.schema, name)
        # Try acl methods
        if hasattr(self.acl, name):
            return getattr(self.acl, name)
        # Try entry methods
        if hasattr(self.entry, name):
            return getattr(self.entry, name)
        # Not found in any nested instance
        msg = f"'{type(self).__name__}' object has no attribute '{name}'"
        raise AttributeError(msg)

    class Schema(FlextLdifServersRfc.Schema):
        """Active Directory schema quirk."""

        # Active Directory configuration defaults
        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        priority: ClassVar[int] = 15

        def can_handle_attribute(
            self, attribute: FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect AD attribute definitions using centralized constants."""
            # Check OID pattern from constants
            if re.search(
                FlextLdifConstants.LdapServerDetection.AD_OID_PATTERN, attribute.oid
            ):
                return True

            attr_name_lower = attribute.name.lower()
            if "microsoft active directory" in attr_name_lower:
                return True

            if (
                attr_name_lower
                in FlextLdifConstants.LdapServerDetection.AD_ATTRIBUTE_NAMES
            ):
                return True

            return any(
                marker in attr_name_lower
                for marker in FlextLdifConstants.LdapServerDetection.AD_ATTRIBUTE_NAMES
            )

        def can_handle_objectclass(
            self, objectclass: FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect AD objectClass definitions using centralized constants."""
            if re.search(
                FlextLdifConstants.LdapServerDetection.AD_OID_PATTERN, objectclass.oid
            ):
                return True

            oc_name_lower = objectclass.name.lower()
            if (
                oc_name_lower
                in FlextLdifConstants.LdapServerDetection.AD_OBJECTCLASS_NAMES
            ):
                return True

            return any(
                marker in oc_name_lower
                for marker in FlextLdifConstants.LdapServerDetection.AD_OBJECTCLASS_NAMES
            )

        def parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add AD metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with AD metadata

            """
            result = super().parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "active_directory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add AD metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with AD metadata

            """
            result = super().parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Use FlextLdifUtilities for common objectClass validation
                FlextLdifUtilities.ObjectClassValidator.fix_missing_sup(
                    oc_data, server_type=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
                )
                FlextLdifUtilities.ObjectClassValidator.fix_kind_mismatch(
                    oc_data, server_type=FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
                )
                metadata = FlextLdifModels.QuirkMetadata.create_for_quirk(
                    "active_directory"
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        # Nested class references for Schema - allows Schema().Entry() pattern
        class Acl(FlextLdifServersRfc.Acl):
            """Nested Acl reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
            priority: ClassVar[int] = 15

            def parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
                """Delegate to outer Active Directory Acl's parse_acl implementation."""
                # Create an instance of the outer FlextLdifServersAd.Acl and use its parse_acl
                outer_acl = FlextLdifServersAd.Acl()
                return outer_acl.parse_acl(acl_line)

        class Entry(FlextLdifServersRfc.Entry):
            """Nested Entry reference within Schema."""

            server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
            priority: ClassVar[int] = 15

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

        # OVERRIDE: Active Directory uses "nTSecurityDescriptor" for ACL attributes
        acl_attribute_name = "nTSecurityDescriptor"

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        priority: ClassVar[int] = 15

        def can_handle_acl(self, acl: FlextLdifModels.Acl) -> bool:
            """Check whether the ACL line belongs to an AD security descriptor."""
            if not acl.raw_acl:
                return False
            normalized = acl.raw_acl.strip()
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

        def get_acl_attribute_name(self) -> str:
            """Get Active Directory-specific ACL attribute name.

            Active Directory uses 'nTSecurityDescriptor' for storing
            security descriptors containing ACL information.

            Returns:
                'nTSecurityDescriptor' - AD-specific ACL attribute name

            """
            return self.acl_attribute_name

    # ===================================================================== #
    # Nested entry quirk
    # ===================================================================== #
    class Entry(FlextLdifServersRfc.Entry):
        """Active Directory entry processing quirk."""

        server_type: ClassVar[str] = FlextLdifConstants.LdapServers.ACTIVE_DIRECTORY
        priority: ClassVar[int] = 15

        # --------------------------------------------------------------------- #
        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # --------------------------------------------------------------------- #
        # These methods override the base class with AD-specific logic:
        # - can_handle_entry(): Detects AD entries by DN/attributes
        # - process_entry(): Normalizes AD entries with metadata
        # - convert_entry_to_rfc(): Converts AD entries to RFC format

        def can_handle_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> bool:
            """Detect Active Directory entries based on DN, attributes, or classes."""
            entry_dn = entry.dn.value
            attributes = entry.attributes.attributes
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifConstants.LdapServerDetection.AD_DN_MARKERS
            ):
                return True

            if (
                FlextLdifConstants.DnPatterns.DC_PREFIX in dn_lower
                and "cn=configuration" in dn_lower
            ):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifConstants.LdapServerDetection.AD_ATTRIBUTE_MARKERS
            ):
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
                    str(oc).lower()
                    in FlextLdifConstants.LdapServerDetection.AD_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )

        def process_entry(
            self,
            entry: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Normalise Active Directory entries and surface metadata."""
            try:
                attributes = entry.attributes.attributes.copy()

                # Get objectClasses (already list[str] in LdifAttributes)
                object_classes = attributes.get(
                    FlextLdifConstants.DictKeys.OBJECTCLASS,
                    [],
                )

                # Process attributes - work directly with dict[str, list[str]]
                # Process binary values if any (convert bytes to base64 strings)
                processed_attributes: dict[str, list[str]] = {}
                for attr_name, attr_values in attributes.items():
                    processed_values: list[str] = []
                    for value in attr_values:
                        if isinstance(value, bytes):
                            processed_values.append(
                                base64.b64encode(value).decode("ascii")
                            )
                        else:
                            processed_values.append(str(value))
                    processed_attributes[attr_name] = processed_values

                # Ensure objectClass is included (already in list format)
                processed_attributes[FlextLdifConstants.DictKeys.OBJECTCLASS] = (
                    object_classes
                )

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(
                    attributes=processed_attributes
                )

                processed_entry = entry.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(processed_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Active Directory entry processing failed: {exc}",
                )

        def convert_entry_to_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Strip AD-only metadata before handing control to RFC logic."""
            try:
                # Work directly with LdifAttributes
                attributes = entry_data.attributes.attributes.copy()
                attributes.pop(FlextLdifConstants.DictKeys.SERVER_TYPE, None)
                attributes.pop(FlextLdifConstants.DictKeys.IS_CONFIG_ENTRY, None)
                attributes.pop(
                    FlextLdifConstants.DictKeys.IS_TRADITIONAL_DIT,
                    None,
                )

                # Create new LdifAttributes directly
                new_attrs = FlextLdifModels.LdifAttributes(attributes=attributes)

                rfc_entry = entry_data.model_copy(
                    update={"attributes": new_attrs},
                )

                return FlextResult[FlextLdifModels.Entry].ok(rfc_entry)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Entry].fail(
                    f"Active Directory entry→RFC conversion failed: {exc}",
                )

        def convert_entry_from_rfc(
            self,
            entry_data: FlextLdifModels.Entry,
        ) -> FlextResult[FlextLdifModels.Entry]:
            """Convert entry from RFC format - pass-through for Active Directory.

            Args:
            entry_data: RFC-compliant entry model

            Returns:
            FlextResult with data (unchanged, since AD entries are RFC-compliant)

            """
            return FlextResult[FlextLdifModels.Entry].ok(entry_data)


__all__ = ["FlextLdifServersAd"]
