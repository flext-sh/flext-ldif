"""Active Directory Servers Implementation."""

from __future__ import annotations

import base64
import binascii
import re
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersAd(FlextLdifServersRfc):
    """Active Directory server servers implementation."""

    class Constants(FlextLdifServersRfc.Constants):
        """Standardized constants for Active Directory server."""

        SERVER_TYPE: ClassVar[str] = "ad"
        PRIORITY: ClassVar[int] = 10
        DEFAULT_PORT: ClassVar[int] = c.LDAP_PORT
        DEFAULT_SSL_PORT: ClassVar[int] = c.LDAPS_PORT
        DEFAULT_PAGE_SIZE: ClassVar[int] = 1000
        GLOBAL_CATALOG_PORT: ClassVar[int] = 3268
        GLOBAL_CATALOG_SSL_PORT: ClassVar[int] = 3269
        CANONICAL_NAME: ClassVar[str] = "active_directory"
        ALIASES: ClassVar[frozenset[str]] = frozenset(["ad", "active_directory"])
        CAN_NORMALIZE_FROM: ClassVar[frozenset[str]] = frozenset(["active_directory"])
        CAN_DENORMALIZE_TO: ClassVar[frozenset[str]] = frozenset([
            "active_directory",
            "rfc",
        ])
        ACL_FORMAT: ClassVar[str] = "nTSecurityDescriptor"
        ACL_ATTRIBUTE_NAME: ClassVar[str] = "nTSecurityDescriptor"
        AD_DN_PATTERNS: ClassVar[frozenset[str]] = frozenset([
            "CN=",
            "OU=",
            "DC=",
            "O=",
            "L=",
            "ST=",
            "C=",
        ])
        DETECTION_PATTERN: ClassVar[str] = "1\\.2\\.840\\.113556\\."
        DETECTION_ATTRIBUTES: ClassVar[frozenset[str]] = frozenset([
            "objectGUID",
            "samAccountName",
            "sIDHistory",
            "nTSecurityDescriptor",
        ])
        DETECTION_WEIGHT: ClassVar[int] = 8
        ACL_SDDL_PREFIX_PATTERN: ClassVar[str] = "^(O:|G:|D:|S:)"
        ACL_SDDL_PREFIX_PATTERN_RE: ClassVar[t.Ldif.RegexPattern] = re.compile(
            r"^(O:|G:|D:|S:)",
            re.IGNORECASE,
        )
        ENCODING_UTF16LE: ClassVar[str] = "utf-16-le"
        ENCODING_ERROR_IGNORE: ClassVar[str] = "ignore"
        AD_REQUIRED_CLASSES: ClassVar[frozenset[str]] = frozenset([
            "top",
            "person",
            "organizationalPerson",
            "user",
        ])
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
        PRESERVE_ON_MIGRATION: ClassVar[frozenset[str]] = frozenset([
            "whenCreated",
            "whenChanged",
        ])
        SUPPORTED_PERMISSIONS: ClassVar[frozenset[str]] = (
            FlextLdifServersRfc.Constants.SUPPORTED_PERMISSIONS
            | frozenset(["control_access"])
        )
        DETECTION_OID_PATTERN: ClassVar[str] = "1\\.2\\.840\\.113556\\."
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
        DETECTION_MICROSOFT_ACTIVE_DIRECTORY: ClassVar[str] = (
            "microsoft active directory"
        )
        ATTRIBUTE_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_names=DETECTION_ATTRIBUTE_NAMES,
                detection_string=DETECTION_MICROSOFT_ACTIVE_DIRECTORY,
                match_definition_text=True,
            )
        )
        OBJECTCLASS_PATTERN_SETTINGS: ClassVar[m.Ldif.ServerPatternsConfig] = (
            m.Ldif.ServerPatternsConfig(
                oid_pattern=DETECTION_OID_PATTERN,
                attr_names=DETECTION_OBJECTCLASS_NAMES,
                match_definition_text=True,
            )
        )
        ACL_TARGET_WILDCARD: ClassVar[str] = "*"

    class Schema(FlextLdifServersRfc.Schema):
        """Active Directory schema server."""

        @override
        def can_handle_attribute(
            self,
            attr_definition: str | m.Ldif.SchemaAttribute,
        ) -> bool:
            """Detect AD attribute definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=attr_definition,
                settings=FlextLdifServersAd.Constants.ATTRIBUTE_PATTERN_SETTINGS,
            )
            return matches

        @override
        def can_handle_objectclass(
            self,
            oc_definition: str | m.Ldif.SchemaObjectClass,
        ) -> bool:
            """Detect AD objectClass definitions using centralized constants."""
            matches: bool = u.Ldif.matches_server_patterns(
                value=oc_definition,
                settings=FlextLdifServersAd.Constants.OBJECTCLASS_PATTERN_SETTINGS,
            )
            return matches

        @override
        def _hook_post_parse_objectclass(
            self,
            oc: m.Ldif.SchemaObjectClass,
        ) -> p.Result[m.Ldif.SchemaObjectClass]:
            """Normalize Active Directory objectClass data after RFC parsing."""
            u.Ldif.fix_missing_sup(oc)
            u.Ldif.fix_kind_mismatch(oc)
            return super()._hook_post_parse_objectclass(oc)

    class Acl(FlextLdifServersRfc.Acl):
        """Active Directory ACL server handling nTSecurityDescriptor entries."""

        @override
        def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check if this is an Active Directory ACL (public method)."""
            if isinstance(acl_line, str):
                return self.can_handle_acl(acl_line)
            raw_acl = getattr(acl_line, "raw_acl", None)
            if not isinstance(raw_acl, str) or not raw_acl:
                return False
            return self.can_handle_acl(raw_acl)

        @override
        def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
            """Check whether the ACL line belongs to an AD security descriptor."""
            if isinstance(acl_line, str):
                normalized = acl_line.strip()
            else:
                raw_acl = getattr(acl_line, "raw_acl", None)
                if not isinstance(raw_acl, str):
                    return False
                normalized = raw_acl.strip()
            if not normalized:
                return False
            attr_name, _, _ = normalized.partition(":")
            if (
                attr_name.strip().lower()
                == FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME.lower()
            ):
                return True
            return (
                FlextLdifServersAd.Constants.ACL_SDDL_PREFIX_PATTERN_RE.match(
                    normalized,
                )
                is not None
            )

        @override
        def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse nTSecurityDescriptor values and expose best-effort SDDL."""
            try:
                return self._parse_ad_acl(acl_line)
            except c.EXC_BASIC_TYPE as exc:
                return r[m.Ldif.Acl].fail_op("Active Directory ACL parsing", exc)

        @override
        def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write ACL data to RFC-compliant string format."""
            try:
                return self._write_ad_acl(acl_data)
            except c.EXC_BASIC_TYPE as exc:
                return r[str].fail_op("Active Directory ACL write", exc)

        def _parse_ad_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
            """Parse Active Directory ACL content."""
            line = acl_line.strip()
            if not line:
                return r[m.Ldif.Acl].fail("Empty ACL line cannot be parsed")
            attr_name, _, remainder = line.partition(":")
            attr_name = (
                attr_name.strip() or FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME
            )
            remainder = remainder.lstrip()
            is_base64 = remainder.startswith(":")
            if is_base64:
                remainder = remainder[1:].strip()
            raw_value = remainder
            decoded_sddl = self._decode_sddl(raw_value, is_base64=is_base64)
            acl_model = m.Ldif.Acl(
                name=attr_name,
                target=m.Ldif.AclTarget(
                    target_dn=FlextLdifServersAd.Constants.ACL_TARGET_WILDCARD,
                    attributes=[],
                ),
                subject=m.Ldif.AclSubject(
                    subject_type=c.Ldif.AclSubjectType.SDDL,
                    subject_value=decoded_sddl or (raw_value or ""),
                ),
                permissions=m.Ldif.AclPermissions(),
                metadata=m.Ldif.ServerMetadata.create_for(self._get_server_type()),
                raw_acl=acl_line,
            )
            if acl_model.metadata:
                acl_model.metadata.extensions["original_format"] = acl_line
            return r[m.Ldif.Acl].ok(acl_model)

        @staticmethod
        def _decode_sddl(raw_value: str, *, is_base64: bool) -> str | None:
            """Decode SDDL from raw or base64 nTSecurityDescriptor value."""

            def _decode_base64() -> p.Result[str]:
                """Decode base64 SDDL bytes, propagating the decode failure."""
                try:
                    decoded_bytes = base64.b64decode(raw_value, validate=True)
                except binascii.Error as exc:
                    return r[str].fail(str(exc), exception=exc)
                try:
                    decoded = (
                        decoded_bytes.decode(
                            FlextLdifServersAd.Constants.ENCODING_UTF16LE,
                            errors=FlextLdifServersAd.Constants.ENCODING_ERROR_IGNORE,
                        ).strip()
                        or decoded_bytes.decode(
                            FlextLdifServersAd.Constants.ENCODING_UTF8,
                            errors=FlextLdifServersAd.Constants.ENCODING_ERROR_IGNORE,
                        ).strip()
                    )
                except UnicodeDecodeError as exc:
                    return r[str].fail(str(exc), exception=exc)
                return r[str].ok(decoded)

            if is_base64 and raw_value:
                decode_result = _decode_base64()
                if decode_result.success:
                    return decode_result.value
                return None
            if (
                raw_value
                and FlextLdifServersAd.Constants.ACL_SDDL_PREFIX_PATTERN_RE.match(
                    raw_value,
                )
            ):
                return raw_value
            return None

        @staticmethod
        def _write_ad_acl(acl_data: m.Ldif.Acl) -> p.Result[str]:
            """Write Active Directory ACL content."""
            if not acl_data.raw_acl:
                return r[str].fail(
                    "Active Directory ACL write requires raw_acl value",
                )
            acl_attribute = FlextLdifServersAd.Constants.ACL_ATTRIBUTE_NAME
            if acl_data.raw_acl:
                return r[str].ok(f"{acl_attribute}: {acl_data.raw_acl}")
            return r[str].ok(f"{acl_attribute}:")

    class Entry(FlextLdifServersRfc.Entry):
        """Active Directory entry processing server."""

        @override
        def can_handle(
            self,
            entry_dn: str,
            attributes: t.MutableStrSequenceMapping,
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
            raw_object_classes = attributes.get(c.Ldif.DictKeys.OBJECTCLASS, [])
            object_classes = list(raw_object_classes)
            normalized_object_classes: t.MutableSequenceOf[str] = list(object_classes)
            return any(
                oc.lower() in FlextLdifServersAd.Constants.DETECTION_OBJECTCLASS_NAMES
                for oc in normalized_object_classes
            )


__all__: list[str] = ["FlextLdifServersAd"]
