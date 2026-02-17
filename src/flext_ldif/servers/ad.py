"""Active Directory Quirks Implementation."""

from __future__ import annotations

import base64
import binascii
import re
from typing import ClassVar

from flext_core import r

from flext_ldif._models.domain import FlextLdifModelsDomains
from flext_ldif._utilities.object_class import FlextLdifUtilitiesObjectClass
from flext_ldif._utilities.server import FlextLdifUtilitiesServer
from flext_ldif.constants import c
from flext_ldif.models import m
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server quirks implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Active Directory quirk."""

        SERVER_TYPE: ClassVar[str] = "ad"
        PRIORITY: ClassVar[int] = 10

        DEFAULT_PORT: ClassVar[int] = 389
        DEFAULT_SSL_PORT: ClassVar[int] = 636
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000

        GLOBAL_CATALOG_PORT: ClassVar[int] = 3268
        GLOBAL_CATALOG_SSL_PORT: ClassVar[int] = 3269

        CANONICAL_NAME: ClassVar[str] = "active_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["ad", "active_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["active_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset(
            [
                "active_directory",
                "rfc",
            ],
        )

        ACL_FORMAT: ClassVar[str] = "nTSecurityDescriptor"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "nTSecurityDescriptor"

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

        ACL_SDDL_PREFIX_PATTERN: ClassVar[str] = r"^(O:|G:|D:|S:)"

        ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
        ENCODING_UTF8: ClassVar[str] = "utf-8"
        ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"

        AD_REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset(
            [
                "top",
                "person",
                "organizationalPerson",
                "user",
            ],
        )

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

        PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset(
            [
                "whenCreated",
                "whenChanged",
            ],
        )

        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["control_access"])
        )

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

        DETECTION_MICROSOFT_ACTIVE_DIRECTORY: ClassVar[str] = (
            "microsoft active directory"
        )
        ACL_TARGET_WILDCARD: ClassVar[str] = "*"

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
            """Parse attribute definition and add AD metadata."""
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
            """Parse objectClass definition and add AD metadata."""
            result = super()._parse_objectclass(oc_definition)
            if result.is_success:
                oc_data = result.value

                FlextLdifUtilitiesObjectClass.fix_missing_sup(oc_data)
                FlextLdifUtilitiesObjectClass.fix_kind_mismatch(oc_data)
                metadata = m.Ldif.QuirkMetadata.create_for(
                    self._get_server_type(),
                )
                oc_updated = oc_data.model_copy(update={"metadata": metadata})
                return r[m.Ldif.SchemaObjectClass].ok(oc_updated)
            return result

    class Acl(FlextLdifServersRfc.Acl):
        """Active Directory ACL quirk handling nTSecurityDescriptor entries."""

        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an Active Directory ACL (public method)."""
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

                if acl_model.metadata and acl_model.metadata.extensions is not None:
                    acl_model.metadata.extensions["original_format"] = acl_line

                return r[m.Ldif.Acl].ok(acl_model)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[m.Ldif.Acl].fail(
                    f"Active Directory ACL parsing failed: {exc}",
                )

        def _write_acl(self, acl_data: FlextLdifModelsDomains.Acl) -> r[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                if not acl_data.raw_acl:
                    return r[str].fail(
                        "Active Directory ACL write requires raw_acl value",
                    )
                raw_value = acl_data.raw_acl
                acl_attribute = FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME

                sddl_value = raw_value

                if sddl_value:
                    acl_str = f"{acl_attribute}: {sddl_value}"
                else:
                    acl_str = f"{acl_attribute}:"

                return r[str].ok(acl_str)

            except (ValueError, TypeError, AttributeError) as exc:
                return r[str].fail(
                    f"Active Directory ACL write failed: {exc}",
                )

    class Entry(FlextLdifServersRfc.Entry):
        """Active Directory entry processing quirk."""

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
                c.Ldif.DictKeys.OBJECTCLASS,
                [],
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


__all__ = ["FlextLdifServersAd"]
