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
from contextlib import suppress
from typing import ClassVar

from flext_core import r

from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers._rfc import (
    FlextLdifServersRfcAcl,
)
from flext_ldif.servers.rfc import FlextLdifServersRfc
from flext_ldif.typings import t
from flext_ldif.utilities import u


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server quirks implementation.

    Extends RFC base quirks with Active Directory-specific handling for:
    - Schema: Microsoft schema extensions and OID namespace
    - ACL: nTSecurityDescriptor parsing and SDDL support
    - Entry: AD-specific entry transformations and normalization
    """

    # =========================================================================
    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Active Directory quirk."""

        # Server identity and priority (defined at Constants level)
        SERVER_TYPE: ClassVar[str] = "ad"
        PRIORITY: ClassVar[int] = 10

        # LDAP Connection Defaults (RFC 4511 §4.1 - Standard LDAP ports)
        DEFAULT_PORT: ClassVar[int] = 389  # Standard LDAP port
        DEFAULT_SSL_PORT: ClassVar[int] = 636  # Standard LDAPS port (LDAP over SSL/TLS)
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000  # RFC 2696 Simple Paged Results default

        # Active Directory Global Catalog ports (AD-specific)
        GLOBAL_CATALOG_PORT: ClassVar[int] = 3268  # Global Catalog LDAP port
        GLOBAL_CATALOG_SSL_PORT: ClassVar[int] = 3269  # Global Catalog LDAPS port

        # === STANDARDIZED CONSTANTS (from FlextLdifServersRfc.Constants) ===
        CANONICAL_NAME: ClassVar[str] = "active_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["ad", "active_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["active_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "active_directory",
                "rfc",
            ],
        )

        # Active Directory ACL format constants
        ACL_FORMAT: ClassVar[str] = "nTSecurityDescriptor"  # AD ACL format
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "nTSecurityDescriptor"  # ACL attribute name

        # Active Directory DN patterns
        AD_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset(
            [
                "CN=",
                "OU=",
                "DC=",
                "O=",
                "L=",
                "ST=",
                "C=",
            ],
        )

        # Server detection patterns and weights
        # Migrated from c.ServerDetection
        DETECTION_PATTERN: ClassVar[str] = r"1\.2\.840\.113556\."
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
                "objectGUID",
                "samAccountName",
                "sIDHistory",
                "nTSecurityDescriptor",
            ],
        )
        DETECTION_WEIGHT: ClassVar[int] = 8

        # ACL-specific regex patterns (migrated from nested Acl class)
        ACL_SDDL_PREFIX_PATTERN: ClassVar[str] = r"^(O:|G:|D:|S:)"

        # Encoding constants (migrated from _parse_acl method)
        ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
        # ACL_SUBJECT_TYPE_SDDL removed - use c.AclSubjectType.SDDL

        # Active Directory required object classes
        AD_REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "person",
                "organizationalPerson",
                "user",
            ],
        )

        # Active Directory operational attributes (server-specific)
        # Migrated from c.OperationalAttributeMappings
        OPERATIONAL_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset(
            [
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
            ],
        )

        # Operational attributes to preserve during migration
        PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset(
            [
                "whenCreated",
                "whenChanged",
            ],
        )

        # AD extends RFC permissions with "control_access"
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["control_access"])
        )

        # NOTE: AD inherits RFC baseline for:
        # - ATTRIBUTE_ALIASES, ATTRIBUTE_FIELDS, OBJECTCLASS_REQUIREMENTS

        # === AD-SPECIFIC DETECTION PATTERNS ===
        # (migrated from c.LdapServerDetection)
        DETECTION_OID_PATTERN: ClassVar[str] = r"1\.2\.840\.113556\."
        DETECTION_ATTRIBUTE_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
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
            ],
        )
        DETECTION_OBJECTCLASS_NAMES: ClassVar[frozenset[str]] = frozenset(
            [
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
            ],
        )
        DETECTION_DN_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "cn=users",
                "cn=computers",
                "cn=configuration",
                "cn=system",
                "ou=domain controllers",
            ],
        )
        # DN marker constants for can_handle
        DN_MARKER_DC: ClassVar[str] = "dc="
        DN_MARKER_CN_CONFIGURATION: ClassVar[str] = "cn=configuration"
        DETECTION_ATTRIBUTE_MARKERS: ClassVar[frozenset[str]] = frozenset(
            [
                "objectguid",
                "objectsid",
                "samaccountname",
                "userprincipalname",
                "ntsecuritydescriptor",
                "useraccountcontrol",
                "serviceprincipalname",
                "lastlogontimestamp",
                "pwdlastset",
            ],
        )

        # AD-specific detection strings
        DETECTION_MICROSOFT_ACTIVE_DIRECTORY: ClassVar[str] = (
            "microsoft active directory"
        )
        ACL_TARGET_WILDCARD: ClassVar[str] = "*"

        # === ACL AND ENCODING CONSTANTS (Centralized) ===
        # Use centralized StrEnums from FlextLdifConstants directly
        # No duplicate nested StrEnums - use c.Ldif.AclPermission,
        # c.Ldif.AclAction, and c.Ldif.Encoding directly

    # =========================================================================
    # Server identification - accessed via Constants via properties in base.py
    # =========================================================================
    # NOTE: server_type and priority are accessed via properties in base.py
    # which read from Constants.SERVER_TYPE and Constants.PRIORITY
    # NOTE: __getattr__ delegation is inherited from FlextLdifServersBase

    class Schema(FlextLdifServersRfc.Schema):
        """Active Directory schema quirk."""

        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect AD attribute definitions using centralized constants."""
            return FlextLdifUtilitiesServer.matches_server_patterns(
                value=attr_definition,
                oid_pattern=FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                detection_names=FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_NAMES,
                detection_string=FlextLdifServersAd.Constants.DETECTION_MICROSOFT_ACTIVE_DIRECTORY,
            )

        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect AD objectClass definitions using centralized constants."""
            return FlextLdifUtilitiesServer.matches_server_patterns(
                value=oc_definition,
                oid_pattern=FlextLdifServersAd.Constants.DETECTION_OID_PATTERN,
                detection_names=FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES,
            )

        def _parse_attribute(
            self,
            attr_definition: str,
        ) -> r[m.Ldif.SchemaAttribute]:
            """Parse attribute definition and add AD metadata.

            Args:
                attr_definition: Attribute definition string

            Returns:
                r with SchemaAttribute marked with AD metadata

            """
            result = super()._parse_attribute(attr_definition)
            if result.is_success:
                attr_data = result.value
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                attr_updated = attr_data.model_copy(update={"metadata": metadata})
                return r[m.Ldif.SchemaAttribute].ok(attr_updated)
            return result

        def _parse_objectclass(
            self,
            oc_definition: str,
        ) -> r[m.Ldif.SchemaObjectClass]:
            """Parse objectClass definition and add AD metadata.

            Args:
                oc_definition: ObjectClass definition string

            Returns:
                r with SchemaObjectClass marked with AD metadata

            """
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value
                # Fix common ObjectClass issues (RFC 4512 compliance)
                FlextLdifUtilitiesObjectClass.fix_missing_sup(oc_data)
                FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc_data)
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                oc_updated = oc_data.model_copy(update={"metadata": metadata})
                return r[m.Ldif.SchemaObjectClass].ok(oc_updated)
            return result

        # Nested class references for Schema - allows Schema().Entry() pattern

    class Acl(FlextLdifServersRfcAcl):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        # SDDL pattern moved to Constants.ACL_SDDL_PREFIX_PATTERN

        # OVERRIDE: Active Directory uses "nTSecurityDescriptor" for ACL attributes
        # ACL attribute name is obtained from Constants.ACL_ATTRIBUTE_NAME
        # No instance variable needed - use Constants directly

        def can_handle(self, acl_line: t.Ldif.AclOrString) -> bool:
            """Check if this is an Active Directory ACL (public method).

            Args:
                acl_line: ACL line string or Acl model to check.

            Returns:
                True if this is Active Directory ACL format

            """
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            if isinstance(acl_line, m.Ldif.Acl):
                if not acl_line.raw_acl:
                    return False
                return self.can_handle_acl(acl_line.raw_acl)
            return False

        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
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
            if isinstance(acl_line, m.Ldif.Acl):
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

        def _parse_acl(self, acl_line: str) -> r[m.Ldif.Acl]:
            """Parse nTSecurityDescriptor values and expose best-effort SDDL."""
            try:
                line = acl_line.strip()
                if not line:
                    return r[m.Ldif.Acl].fail(
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
                acl_model = m.Ldif.Acl(
                    name=attr_name,
                    target=m.Ldif.AclTarget(
                        target_dn=FlextLdifServersAd.Constants.ACL_TARGET_WILDCARD,
                        attributes=[],
                    ),
                    subject=m.Ldif.AclSubject(
                        subject_type="sddl",
                        subject_value=(decoded_sddl or (raw_value or "")),
                    ),
                    permissions=m.Ldif.AclPermissions(),
                    metadata=m.Ldif.QuirkMetadata.create_for(
                        self._get_server_type(),
                    ),
                    raw_acl=acl_line,
                )
                # Set original_format in extensions after creation
                if acl_model.metadata and acl_model.metadata.extensions is not None:
                    acl_model.metadata.extensions["original_format"] = acl_line

                return r[m.Ldif.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Acl].fail(
                    f"Active Directory ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: m.Ldif.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format.

            Active Directory ACLs use nTSecurityDescriptor format.

            Args:
            acl_data: ACL data dictionary

            Returns:
            r with ACL string in AD nTSecurityDescriptor format

            """
            try:
                # Get the raw ACL value - fail if missing
                if not acl_data.raw_acl:
                    return r[str].fail(
                        "Active Directory ACL write requires raw_acl value",
                    )
                raw_value = acl_data.raw_acl
                acl_attribute = FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME

                # Use the raw ACL value
                sddl_value = raw_value

                # Format as LDIF attribute line
                # AD typically uses base64 encoding for nTSecurityDescriptor
                if sddl_value:
                    acl_str = f"{acl_attribute}: {sddl_value}"
                else:
                    acl_str = f"{acl_attribute}:"

                return r[str].ok(acl_str)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[str].fail(
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
            attributes: dict[str, list[str]],
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
                name.lower(): value
                for name, value in u.Ldif.mapper().to_dict(attributes).items()
            }
            if any(
                marker in normalized_attrs
                for marker in FlextLdifServersAd.Constants.DETECTION_ATTRIBUTE_MARKERS
            ):
                return True

            # u.Ldif.mapper().get() returns value directly (or default if key not found)
            raw_object_classes: list[str] = u.Ldif.mapper().get(
                attributes,
                c.Ldif.DictKeys.OBJECTCLASS,
                default=[],
            )
            object_classes = (
                raw_object_classes
                if isinstance(raw_object_classes, (list, tuple))
                else [raw_object_classes]
            )
            return bool(
                any(
                    str(oc).lower()
                    in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                    for oc in object_classes
                ),
            )


# Forward references resolved automatically by Pydantic
# No suppress needed - circular import issues should be resolved architecturally


__all__ = ["FlextLdifServersAd"]
