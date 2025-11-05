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
from collections.abc import Mapping
from typing import ClassVar, Final

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

    # === STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY ===
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Active Directory quirk."""

        # === STANDARDIZED CONSTANTS (from FlextLdifServersRfc.Constants) ===
        SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
        CANONICAL_NAME: ClassVar[str] = "active_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["active_directory", "ad"])
        PRIORITY: ClassVar[int] = 30
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["active_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            "active_directory",
            "rfc",
        ])

        # Active Directory ACL format constants
        ACL_FORMAT: ClassVar[str] = "nTSecurityDescriptor"  # AD ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "nTSecurityDescriptor"  # ACL attribute name

        # Active Directory DN patterns
        AD_DN_PATTERNS: Final[frozenset[str]] = frozenset([
            "CN=",
            "OU=",
            "DC=",
            "O=",
            "L=",
            "ST=",
            "C=",
        ])

        # ACL-specific regex patterns (migrated from nested Acl class)
        ACL_SDDL_PREFIX_PATTERN: Final[str] = r"^(O:|G:|D:|S:)"

        # Encoding constants (migrated from _parse_acl method)
        ENCODING_UTF16LE: Final[str] = "utf-16-le"
        ENCODING_UTF8: Final[str] = "utf-8"
        ENCODING_ERROR_IGNORE: Final[str] = "ignore"
        ACL_SUBJECT_TYPE_SDDL: Final[str] = "sddl"

        # Active Directory required object classes
        AD_REQUIRED_CLASSES: Final[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "user",
        ])

        # Active Directory operational attributes (server-specific)
        OPERATIONAL_ATTRIBUTES: Final[frozenset[str]] = frozenset([
            "objectGUID",
            "objectSid",
            "whenCreated",
            "whenChanged",
            "uSNCreated",
            "uSNChanged",
            "dSCorePropagationData",
        ])

        # === AD-SPECIFIC DETECTION PATTERNS ===
        # (migrated from FlextLdifConstants.LdapServerDetection)
        DETECTION_OID_PATTERN = r"1\.2\.840\.113556\."
        DETECTION_ATTRIBUTE_NAMES: Final[frozenset[str]] = frozenset([
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
        DETECTION_OBJECTCLASS_NAMES = frozenset([
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
        DETECTION_DN_MARKERS = frozenset([
            "cn=users",
            "cn=computers",
            "cn=configuration",
            "cn=system",
            "ou=domain controllers",
        ])
        # DN marker constants for can_handle
        DN_MARKER_DC: Final[str] = "dc="
        DN_MARKER_CN_CONFIGURATION: Final[str] = "cn=configuration"
        DETECTION_ATTRIBUTE_MARKERS: Final[frozenset[str]] = frozenset([
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

    # =========================================================================
    # Class-level attributes for server identification (from Constants)
    # =========================================================================
    server_type: ClassVar[str] = Constants.SERVER_TYPE
    priority: ClassVar[int] = Constants.PRIORITY

    def __init__(self) -> None:
        """Initialize Active Directory quirks."""
        super().__init__()
        # Use object.__setattr__ to bypass Pydantic validation for dynamic attributes
        # Nested classes no longer require server_type and priority parameters
        object.__setattr__(self, "schema", self.Schema())
        object.__setattr__(self, "acl", self.Acl())
        object.__setattr__(self, "entry", self.Entry())

    def __getattr__(self, name: str) -> object:
        """Delegate method calls to nested Schema, Acl, or Entry.

        Enables calling schema/acl/entry methods on the main server instance.

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

        def can_handle_attribute(
            self, attr_definition: str | FlextLdifModels.SchemaAttribute
        ) -> bool:
            """Detect AD attribute definitions using centralized constants."""
            if isinstance(attr_definition, str):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN, attr_definition
                ):
                    return True
                attr_lower = attr_definition.lower()
                if "microsoft active directory" in attr_lower:
                    return True
                if attr_lower in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_NAMES:
                    return True

                return any(
                    marker in attr_lower
                    for marker in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_NAMES
                )
            if isinstance(attr_definition, FlextLdifModels.SchemaAttribute):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                    attr_definition.oid,
                ):
                    return True

                attr_name_lower = attr_definition.name.lower()
                if "microsoft active directory" in attr_name_lower:
                    return True

                if (
                    attr_name_lower
                    in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_NAMES
                ):
                    return True

                return any(
                    marker in attr_name_lower
                    for marker in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_NAMES
                )
            return False

        def can_handle_objectclass(
            self, oc_definition: str | FlextLdifModels.SchemaObjectClass
        ) -> bool:
            """Detect AD objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN, oc_definition
                ):
                    return True
                oc_lower = oc_definition.lower()
                if oc_lower in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES:
                    return True
                return any(
                    marker in oc_lower
                    for marker in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            if isinstance(oc_definition, FlextLdifModels.SchemaObjectClass):
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                    oc_definition.oid,
                ):
                    return True

                oc_name_lower = oc_definition.name.lower()
                if (
                    oc_name_lower
                    in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                ):
                    return True

                return any(
                    marker in oc_name_lower
                    for marker in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                )
            return False

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaAttribute]:
            """Parse attribute definition and add AD metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                FlextResult with SchemaAttribute marked with AD metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.unwrap()
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    "active_directory"
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata})
                )
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> FlextResult[FlextLdifModels.SchemaObjectClass]:
            """Parse objectClass definition and add AD metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                FlextResult with SchemaObjectClass marked with AD metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.unwrap()
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilities.ObjectClass.fix_missing_sup(oc_data)
                FlextLdifUtilities.ObjectClass.fix_kind_mismatch(oc_data)
                metadata = FlextLdifModels.QuirkMetadata.create_for(
                    "active_directory"
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata})
                )
            return result

        # Nested class references for Schema - allows Schema().Entry() pattern

    class Acl(FlextLdifServersRfc.Acl):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        # SDDL pattern moved to Constants.ACL_SDDL_PREFIX_PATTERN

        # OVERRIDE: Active Directory uses "nTSecurityDescriptor" for ACL attributes
        # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
        # No instance variable needed - use Constants directly

        def can_handle(self, acl: str | FlextLdifModels.Acl) -> bool:
            """Check if this is an Active Directory ACL (public method).

            Args:
                acl: ACL line string or Acl model to check.

            Returns:
                True if this is Active Directory ACL format

            """
            return self.can_handle(acl)

        def can_handle_acl(self, acl_line: str | FlextLdifModels.Acl) -> bool:
            """Check whether the ACL line belongs to an AD security descriptor."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip() if acl_line else ""
                if not normalized:
                    return False
                attr_name, _, _ = normalized.partition(":")
                if (
                    attr_name.strip().lower()
                    == FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME.lower()
                ):
                    return True
                return bool(
                    re.match(
                        FlextLdifServersAd.Constants.ACL_SDDL_PREFIX_PATTERN,
                        normalized,
                        re.IGNORECASE,
                    )
                )
            if isinstance(acl_line, FlextLdifModels.Acl):
                if not acl_line.raw_acl:
                    return False
                normalized = acl_line.raw_acl.strip()
                if not normalized:
                    return False

                attr_name, _, _ = normalized.partition(":")
                if (
                    attr_name.strip().lower()
                    == FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME.lower()
                ):
                    return True

                return bool(
                    re.match(
                        FlextLdifServersAd.Constants.ACL_SDDL_PREFIX_PATTERN,
                        normalized,
                        re.IGNORECASE,
                    )
                )
            return False

        def _parse_acl(self, acl_line: str) -> FlextResult[FlextLdifModels.Acl]:
            """Parse nTSecurityDescriptor values and expose best-effort SDDL."""
            try:
                line = acl_line.strip()
                if not line:
                    return FlextResult[FlextLdifModels.Acl].fail(
                        "Empty ACL line cannot be parsed",
                    )

                attr_name, _, remainder = line.partition(":")
                attr_name = (
                    attr_name.strip() or FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME
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
                            decoded_bytes.decode(
                                FlextLdifServersAd.Constants.ENCODING_UTF16LE,
                                errors=FlextLdifServersAd.Constants.ENCODING_ERROR_IGNORE,
                            ).strip()
                            or decoded_bytes.decode(
                                FlextLdifServersAd.Constants.ENCODING_UTF8,
                                errors=FlextLdifServersAd.Constants.ENCODING_ERROR_IGNORE,
                            ).strip()
                        )
                    except (binascii.Error, UnicodeDecodeError):
                        decoded_sddl = None

                if (
                    not decoded_sddl
                    and raw_value
                    and re.match(
                        FlextLdifServersAd.Constants.ACL_SDDL_PREFIX_PATTERN,
                        raw_value,
                        re.IGNORECASE,
                    )
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
                        subject_type=FlextLdifServersAd.Constants.ACL_SUBJECT_TYPE_SDDL,
                        subject_value=decoded_sddl or raw_value or "",
                    ),
                    permissions=FlextLdifModels.AclPermissions(),
                    metadata=FlextLdifModels.QuirkMetadata.create_for(
                        FlextLdifServersAd.Constants.SERVER_TYPE,
                        original_format=acl_line,
                    ),
                    raw_acl=acl_line,
                )

                return FlextResult[FlextLdifModels.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return FlextResult[FlextLdifModels.Acl].fail(
                    f"Active Directory ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModels.Acl) -> FlextResult[str]:
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
                acl_attribute = FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME

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

    # Nested entry quirk
    class Entry(FlextLdifServersRfc.Entry):
        """Active Directory entry processing quirk."""

        # OVERRIDDEN METHODS (from FlextLdifServersBase.Entry)
        # These methods override the base class with AD-specific logic:
        # - can_handle(): Detects AD entries by DN/attributes

        def can_handle(
            self,
            entry_dn: str,
            attributes: Mapping[str, object],
        ) -> bool:
            """Detect Active Directory entries based on DN, attributes, or classes."""
            if not entry_dn:
                return False
            dn_lower = entry_dn.lower()
            if any(
                marker in dn_lower
                for marker in FlextLdifServersAd.Constants.DETECTION_DN_MARKERS
            ):
                return True

            # Check for DC= prefix and cn=configuration marker from Constants
            if (
                FlextLdifServersAd.Constants.DN_MARKER_DC in dn_lower
                and FlextLdifServersAd.Constants.DN_MARKER_CN_CONFIGURATION in dn_lower
            ):
                return True

            normalized_attrs = {
                name.lower(): value for name, value in attributes.items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_MARKERS
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
                    in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )


__all__ = ["FlextLdifServersAd"]
