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
from enum import StrEnum
from typing import ClassVar

from flext_core import FlextResult

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import FlextLdifTypes
from flext_ldif.utilities import FlextLdifUtilities


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server quirks implementation.

    Extends RFC base quirks with Active Directory-specific handling for:
    - Schema: Microsoft schema extensions and OID namespace
    - ACL: nTSecurityDescriptor parsing and SDDL support
    - Entry: AD-specific entry transformations and normalization
    """

    # =========================================================================
    # STANDARDIZED CONSTANTS FOR AUTO-DISCOVERY
    # =========================================================================
    # Top-level server identity attributes (moved from Constants)
    SERVER_TYPE: ClassVar[str] = FlextLdifConstants.ServerTypes.AD
    PRIORITY: ClassVar[int] = 10

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Active Directory quirk."""

        # === STANDARDIZED CONSTANTS (from FlextLdifServersRfc.Constants) ===
        CANONICAL_NAME: ClassVar[str] = "active_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["active_directory", "ad"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["active_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            "active_directory",
            "rfc",
        ])

        # Active Directory ACL format constants
        ACL_FORMAT: ClassVar[str] = "nTSecurityDescriptor"  # AD ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "nTSecurityDescriptor"  # ACL attribute name

        # Active Directory DN patterns
        AD_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset([
            "CN=",
            "OU=",
            "DC=",
            "O=",
            "L=",
            "ST=",
            "C=",
        ])

        # Server detection patterns and weights
        # Migrated from FlextLdifConstants.ServerDetection
        DETECTION_PATTERN: ClassVar[str] = r"1\.2\.840\.113556\."
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "objectGUID",
            "samAccountName",
            "sIDHistory",
            "nTSecurityDescriptor",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 8

        # ACL-specific regex patterns (migrated from nested Acl class)
        ACL_SDDL_PREFIX_PATTERN: ClassVar[str] = r"^(O:|G:|D:|S:)"

        # Encoding constants (migrated from _parse_acl method)
        ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
        ACL_SUBJECT_TYPE_SDDL: ClassVar[str] = "sddl"

        # Active Directory required object classes
        AD_REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "user",
        ])

        # Active Directory operational attributes (server-specific)
        # Migrated from FlextLdifConstants.OperationalAttributeMappings
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "objectGUID",
            "objectSid",
            "whenCreated",
            "whenChanged",
            "uSNCreated",
            "uSNChanged",
            "distinguishedName",
            "canonicalName",
            "lastLogon",
            "logonCount",
            "badPwdCount",
            "pwdLastSet",
            "dSCorePropagationData",
        ])

        # Operational attributes to preserve during migration
        PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset([
            "whenCreated",
            "whenChanged",
        ])

        # AD extends RFC permissions with "control_access"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["control_access"])
        )

        # NOTE: AD inherits RFC baseline for:
        # - ATTRIBUTE_ALIASES, ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS

        # === AD-SPECIFIC DETECTION PATTERNS ===
        # (migrated from FlextLdifConstants.LdapServerDetection)
        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.2\.840\.113556\."
        DETECTION_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset([
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
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset([
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
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset([
            "cn=users",
            "cn=computers",
            "cn=configuration",
            "cn=system",
            "ou=domain controllers",
        ])
        # DN marker constants for can_handle
        DN_MARKER_DC: ClassVar[str] = "dc="
        DN_MARKER_CN_CONFIGURATION: ClassVar[str] = "cn=configuration"
        DETECTION_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset([
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

        # AD-specific detection strings
        DETECTION_MICROSOFT_ACTIVE_DIRECTORY: ClassVar[str] = (
            "microsoft active directory"
        )
        ACL_TARGET_WILDCARD: ClassVar[str] = "*"

        # === NESTED STRENUM DEFINITIONS ===
        # StrEnum definitions for type-safe permission, action, and encoding handling

        class AclPermission(StrEnum):
            """Active Directory-specific ACL permissions."""

            READ = "read"
            WRITE = "write"
            DELETE = "delete"
            CREATE = "create"
            CONTROL_ACCESS = "control_access"
            AUTH = "auth"
            ALL = "all"
            NONE = "none"

        class AclAction(StrEnum):
            """Active Directory ACL action types."""

            ALLOW = "allow"
            DENY = "deny"

        class Encoding(StrEnum):
            """Active Directory-supported encodings."""

            UTF_8 = "utf-8"
            UTF_16_LE = "utf-16-le"
            ASCII = "ascii"
            LATIN_1 = "latin-1"
            CP1252 = "cp1252"

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY

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
            self,
            attr_definition: str | FlextLdifModels.SchemaAttribute,
        ) -> bool:
            """Detect AD attribute definitions using centralized constants."""
            if isinstance(attr_definition, str):
                # Check OID pattern from constants
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                    attr_definition,
                ):
                    return True
                attr_lower = attr_definition.lower()
                detection_str = (
                    FlextLdifServersAd.Constants.DETECTION_MICROSOFT_ACTIVE_DIRECTORY
                )
                if detection_str in attr_lower:
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
                detection_str = (
                    FlextLdifServersAd.Constants.DETECTION_MICROSOFT_ACTIVE_DIRECTORY
                )
                if detection_str in attr_name_lower:
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
            self,
            oc_definition: str | FlextLdifModels.SchemaObjectClass,
        ) -> bool:
            """Detect AD objectClass definitions using centralized constants."""
            if isinstance(oc_definition, str):
                if re.search(
                    FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                    oc_definition,
                ):
                    return True
                oc_lower = oc_definition.lower()
                if oc_lower in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES:
                    return True
                oc_names = FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                return any(marker in oc_lower for marker in oc_names)
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

                oc_names = FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                return any(marker in oc_name_lower for marker in oc_names)
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
                    FlextLdifServersAd.Constants.SERVER_TYPE,
                )
                return FlextResult[FlextLdifModels.SchemaAttribute].ok(
                    attr_data.model_copy(update={"metadata": metadata}),
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
                    FlextLdifServersAd.Constants.SERVER_TYPE,
                )
                return FlextResult[FlextLdifModels.SchemaObjectClass].ok(
                    oc_data.model_copy(update={"metadata": metadata}),
                )
            return result

        # Nested class references for Schema - allows Schema().Entry() pattern

    class Acl(FlextLdifServersRfc.Acl):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        # SDDL pattern moved to Constants.ACL_SDDL_PREFIX_PATTERN

        # OVERRIDE: Active Directory uses "nTSecurityDescriptor" for ACL attributes
        # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
        # No instance variable needed - use Constants directly

        def can_handle(self, acl_line: FlextLdifTypes.Models.AclOrString) -> bool:
            """Check if this is an Active Directory ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is Active Directory ACL format

            """
            return self.can_handle_acl(acl_line)

        def can_handle_acl(self, acl_line: FlextLdifTypes.Models.AclOrString) -> bool:
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
                    ),
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
                    ),
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
                        target_dn=FlextLdifServersAd.Constants.ACL_TARGET_WILDCARD,
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
