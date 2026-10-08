"""Oracle Internet Directory (OID) ACL server: subject detection and mapping.

OID/RFC subject mapping helpers.


Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidAclSubjectMixin(FlextLdifServersRfc.Acl):
    """OID ACL subject detection and OID/RFC subject mapping."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def _detect_oid_subject(content: str) -> str | None:
        """Detect OID ACL subject type by matching ACL_SUBJECT_PATTERNS.

        Returns:
            The resulting ``str | None``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        if not content:
            return None
        const = FlextLdifServersOidConstants
        for pattern_key, (_, subject_type, _) in const.ACL_SUBJECT_PATTERNS.items():
            if pattern_key.lower() in content.lower():
                detected_subject: str = subject_type
                return detected_subject
        return None

    def _get_source_subject_type(
        self,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str | None:
        """Get source subject type from metadata.

        Returns:
            The resulting ``str | None``.
        """
        if not metadata or not metadata.extensions:
            return None
        source_subject_type_raw = metadata.extensions.get(
            c.Ldif.ACL_SOURCE_SUBJECT_TYPE,
        )
        validated = self._validate_subject_type(source_subject_type_raw)
        if validated.success:
            source_subject_type: str = validated.value
            return source_subject_type
        return None

    @staticmethod
    def _validate_subject_type(value: t.JsonValue | None) -> p.Result[str]:
        """Validate a raw metadata value as a subject-type string.

        Returns:
            The resulting ``p.Result[str]``.
        """
        try:
            source_subject_type: str = t.str_adapter().validate_python(value)
        except c.ValidationError as exc:
            return r[str].fail(str(exc), exception=exc)
        return r[str].ok(source_subject_type)

    @staticmethod
    def _map_bind_rules_to_oid(
        rfc_subject_value: str,
        source_subject_type: str | None,
    ) -> str:
        """Map bind_rules/group to OID subject type.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        sc = FlextLdifServersOidConstants
        if (
            isinstance(source_subject_type, str)
            and source_subject_type
            in {
                sc.OidAclSubjectType.DN_ATTR,
                sc.OidAclSubjectType.GUID_ATTR,
                sc.OidAclSubjectType.GROUP_ATTR,
            }
        ) or (
            isinstance(source_subject_type, str)
            and source_subject_type
            in {sc.OidAclSubjectType.GROUP_DN, sc.OidAclSubjectType.USER_DN}
        ):
            result = source_subject_type
        elif (
            source_subject_type == "group"
            or (
                "group=" in rfc_subject_value.lower()
                or "groupdn" in rfc_subject_value.lower()
            )
            or "cn=groups" in rfc_subject_value.lower()
        ):
            result = sc.OidAclSubjectType.GROUP_DN
        else:
            result = sc.OidAclSubjectType.USER_DN
        return result

    @staticmethod
    def _map_oid_subject_to_rfc(
        oid_subject_type: str,
        oid_subject_value: str,
    ) -> tuple[c.Ldif.AclSubjectType, str]:
        """Map OID subject types to RFC subject types.

        Returns:
            The resulting ``tuple[c.Ldif.AclSubjectType, str]``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        sc = FlextLdifServersOidConstants
        if oid_subject_type == sc.OidAclSubjectType.SELF:
            result = (c.Ldif.AclSubjectType.SELF, "ldap:///self")
        elif oid_subject_type == sc.OidAclSubjectType.GROUP_DN:
            result = (c.Ldif.AclSubjectType.GROUP, oid_subject_value)
        elif oid_subject_type == sc.OidAclSubjectType.USER_DN or oid_subject_type in {
            sc.OidAclSubjectType.DN_ATTR,
            sc.OidAclSubjectType.GUID_ATTR,
            sc.OidAclSubjectType.GROUP_ATTR,
        }:
            result = (c.Ldif.AclSubjectType.DN, oid_subject_value)
        elif sc.OidAclSubjectType.ANONYMOUS in {oid_subject_type, oid_subject_value}:
            result = (c.Ldif.AclSubjectType.ANONYMOUS, sc.OidAclSubjectType.ANONYMOUS)
        else:
            result = (c.Ldif.AclSubjectType.DN, oid_subject_value)
        return result

    def _map_rfc_subject_to_oid(
        self,
        rfc_subject: m.Ldif.AclSubject,
        metadata: m.Ldif.ServerMetadata | None,
    ) -> str:
        """Map RFC subject type to OID subject type for writing.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        rfc_subject_type = str(rfc_subject.subject_type)
        rfc_subject_value = rfc_subject.subject_value
        source_subject_type = self._get_source_subject_type(metadata)
        sc = FlextLdifServersOidConstants
        if isinstance(source_subject_type, str) and source_subject_type in {
            sc.OidAclSubjectType.DN_ATTR,
            sc.OidAclSubjectType.GUID_ATTR,
            sc.OidAclSubjectType.GROUP_ATTR,
        }:
            result = source_subject_type
        else:
            match rfc_subject_type:
                case "self":
                    result = sc.OidAclSubjectType.SELF
                case "anonymous":
                    result = sc.OidAclSubjectType.ANONYMOUS
                case _ if rfc_subject_value == sc.OidAclSubjectType.ANONYMOUS:
                    result = sc.OidAclSubjectType.ANONYMOUS
                case rfc_type if rfc_type in {
                    sc.OidAclSubjectType.DN_ATTR.value,
                    sc.OidAclSubjectType.GUID_ATTR.value,
                    sc.OidAclSubjectType.GROUP_ATTR.value,
                    sc.OidAclSubjectType.GROUP_DN.value,
                    sc.OidAclSubjectType.USER_DN.value,
                }:
                    result = rfc_type
                case "dn":
                    if isinstance(source_subject_type, str) and source_subject_type in {
                        sc.OidAclSubjectType.DN_ATTR,
                        sc.OidAclSubjectType.GUID_ATTR,
                        sc.OidAclSubjectType.GROUP_ATTR,
                    }:
                        result = source_subject_type
                    else:
                        result = sc.OidAclSubjectType.USER_DN
                case _:
                    result = (
                        source_subject_type
                        if isinstance(source_subject_type, str)
                        else sc.OidAclSubjectType.USER_DN
                    )
        return result

    @staticmethod
    def _prepare_subject_value_with_suffix(
        subject_value: str,
        oid_subject_type: str,
    ) -> str:
        """Prepare subject value with OID-specific suffix if needed.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        sc = FlextLdifServersOidConstants
        if (
            oid_subject_type
            in {
                sc.OidAclSubjectType.DN_ATTR,
                sc.OidAclSubjectType.GUID_ATTR,
                sc.OidAclSubjectType.GROUP_ATTR,
            }
            and "#" not in subject_value
        ):
            type_suffix: t.MappingKV[str, str] = {
                sc.OidAclSubjectType.DN_ATTR: sc.OidAclSubjectSuffix.LDAPURL,
                sc.OidAclSubjectType.GUID_ATTR: sc.OidAclSubjectSuffix.USERDN,
                sc.OidAclSubjectType.GROUP_ATTR: sc.OidAclSubjectSuffix.GROUPDN,
            }
            return f"{subject_value}#{type_suffix[oid_subject_type]}"
        return subject_value


__all__: list[str] = ["FlextLdifServersOidAclSubjectMixin"]
