"""Oracle Internet Directory (OID) ACL server — OID ACL clause formatting helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from typing import ClassVar

from flext_ldif import c, m, p, t, u
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOidAclFormatMixin(FlextLdifServersRfc.Acl):
    """OID ACL OID ACL clause formatting helpers."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def _format_oid_permissions(permissions: t.Ldif.MetadataInputMapping) -> str:
        """Format OID ACL permissions clause.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        allowed_perms: t.MutableSequenceOf[str] = []
        for perm, allowed in permissions.items():
            if allowed:
                oid_perm_name = FlextLdifServersOidConstants.ACL_PERMISSION_NAMES.get(
                    perm,
                    perm,
                )
                allowed_perms.append(oid_perm_name)
        if allowed_perms:
            return f"({','.join(allowed_perms)})"
        return "(none)"

    @staticmethod
    def _format_oid_subject(subject_type: str, subject_value: str) -> str:
        """Format OID ACL subject clause in orclaci format.

        Returns:
            The resulting ``str``.
        """
        from flext_ldif.servers._oid.server_constants import (
            FlextLdifServersOidConstants,
        )

        clean_value = FlextLdifServersOidAclFormatMixin.clean_subject_value(
            subject_value,
        )
        sc = FlextLdifServersOidConstants
        match subject_type.lower():
            case sc.OidAclSubjectType.SELF:
                result = sc.OidAclSubjectType.SELF
            case "anonymous" | sc.OidAclSubjectType.ANONYMOUS:
                result = sc.OidAclSubjectType.ANONYMOUS
            case sc.OidAclSubjectType.GROUP_DN | "group":
                result = f'group="{clean_value}"'
            case sc.OidAclSubjectType.USER_DN | "user":
                result = f'"{clean_value}"'
            case sc.OidAclSubjectType.DN_ATTR:
                result = f"dnattr=({clean_value})"
            case sc.OidAclSubjectType.GUID_ATTR:
                result = f"guidattr=({clean_value})"
            case sc.OidAclSubjectType.GROUP_ATTR:
                result = f"groupattr=({clean_value})"
            case _:
                result = (
                    f'"{clean_value}"'
                    if clean_value
                    else sc.OidAclSubjectType.ANONYMOUS
                )
        return result

    @staticmethod
    def _format_oid_target(target_dn: str, attributes: t.MutableSequenceOf[str]) -> str:
        """Format OID ACL target clause.

        Returns:
            The resulting ``str``.
        """
        if not attributes or target_dn == "entry":
            return "entry"
        if len(attributes) == 1 and attributes[0] == "*":
            return "attr=(*)"
        attrs_str = ",".join(attributes)
        return f"attr=({attrs_str})"

    @staticmethod
    def _normalize_permissions_to_dict(
        permissions: m.Ldif.AclPermissions | t.MutableBoolMapping | None,
    ) -> t.MutableBoolMapping:
        """Normalize permissions to dict for formatting.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        if not permissions:
            return {}
        permissions_model = m.Ldif.AclPermissions.model_validate(permissions)
        raw_perms = permissions_model.model_dump()
        return {
            "read": bool(raw_perms.get("read", False)),
            "write": bool(raw_perms.get("write", False)),
            "add": bool(raw_perms.get("add", False)),
            "delete": bool(raw_perms.get("delete", False)),
            "search": bool(raw_perms.get("search", False)),
            "compare": bool(raw_perms.get("compare", False)),
            "self_write": bool(raw_perms.get("self_write", False)),
            "proxy": bool(raw_perms.get("proxy", False)),
            "browse": bool(raw_perms.get("browse", False)),
            "auth": bool(raw_perms.get("auth", False)),
            "all": bool(raw_perms.get("all", False)),
        }

    @staticmethod
    def _normalize_to_dict(
        value: m.Ldif.AclSubject
        | m.Ldif.ServerMetadata
        | t.MutableConfigurationMapping
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ]
        | str
        | None,
    ) -> t.MutableConfigurationMapping:
        """Normalize value to dict for model validation.

        Returns:
            The resulting ``t.MutableConfigurationMapping``.
        """
        if isinstance(value, Mapping):
            return {
                key: raw_value
                for key, raw_value in value.items()
                if isinstance(raw_value, (str, int, bool))
            }
        if value is None:
            return {}
        if isinstance(value, str):
            return {"subject_type": value}
        dumped = value.model_dump()
        return {
            key: raw_value
            for key, raw_value in dumped.items()
            if isinstance(raw_value, (str, int, bool))
        }

    @staticmethod
    def clean_subject_value(subject_value: str) -> str:
        """Clean OID subject value by removing ldap:/// prefix and parser suffixes.

        Returns:
            The resulting ``str``.
        """
        clean_value = subject_value
        if clean_value.startswith("ldap:///"):
            clean_value = clean_value[8:]
            if "?" in clean_value:
                clean_value = clean_value.split("?")[0]
        if "#" in clean_value:
            suffixes_to_strip = {"#GROUPDN", "#LDAPURL", "#USERDN"}
            for suffix in suffixes_to_strip:
                if clean_value.endswith(suffix):
                    clean_value = clean_value[: -len(suffix)]
                    break
        return clean_value

    def _build_metadata_extensions(
        self,
        metadata: m.Ldif.ServerMetadata
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ]
        | None,
    ) -> t.MutableSequenceOf[str]:
        """Build OID ACL extension clauses from metadata.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        if not metadata:
            return []
        meta_extensions = self._extract_extensions_dict(metadata)
        if not meta_extensions:
            return []
        return self._format_extensions(meta_extensions)

    @staticmethod
    def _extract_extensions_dict(
        metadata: m.Ldif.ServerMetadata
        | MutableMapping[
            str,
            t.Ldif.Scalar | t.MutableSequenceOf[str] | t.MutableAttributeMapping | None,
        ],
    ) -> t.Ldif.MutableMetadataMapping:
        """Extract extensions dict from metadata, converting types if needed.

        Returns:
            The resulting ``t.Ldif.MutableMetadataMapping``.
        """
        metadata = m.Ldif.ServerMetadata.model_validate(metadata)
        extensions = getattr(metadata, "extensions", None)
        # mro-wgwh.5 (agent: kimi-coder) — DynamicMetadata removed: copy the plain
        # mapping.
        return dict(extensions) if extensions is not None else {}

    @staticmethod
    def _format_extensions(
        meta_extensions: t.Ldif.MutableMetadataMapping,
    ) -> t.MutableSequenceOf[str]:
        """Format extension values based on metadata key type.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        extensions: t.MutableSequenceOf[str] = []
        acl_filter = meta_extensions.get(c.Ldif.ACL_FILTER)
        if isinstance(acl_filter, str) and acl_filter:
            extensions.append(f"filter={acl_filter}")
        acl_constraint = meta_extensions.get(c.Ldif.ACL_CONSTRAINT)
        if isinstance(acl_constraint, str) and acl_constraint:
            extensions.append(f"added_object_constraint=({acl_constraint})")
        bindmode = meta_extensions.get(c.Ldif.ACL_BINDMODE)
        if isinstance(bindmode, str) and bindmode:
            extensions.append(f"bindmode=({bindmode})")
        bind_ip_filter = meta_extensions.get(c.Ldif.ACL_BIND_IP_FILTER)
        if isinstance(bind_ip_filter, str) and bind_ip_filter:
            extensions.append(f"bindipfilter=({bind_ip_filter})")
        constrain_to_added = meta_extensions.get(c.Ldif.ACL_CONSTRAIN_TO_ADDED_OBJECT)
        if isinstance(constrain_to_added, str) and constrain_to_added:
            extensions.append(f"constraintonaddedobject=({constrain_to_added})")
        deny_group_override = meta_extensions.get(c.Ldif.ACL_DENY_GROUP_OVERRIDE)
        if deny_group_override is True or (
            isinstance(deny_group_override, str) and deny_group_override
        ):
            extensions.append("DenyGroupOverride")
        append_to_all = meta_extensions.get(c.Ldif.ACL_APPEND_TO_ALL)
        if append_to_all is True or (isinstance(append_to_all, str) and append_to_all):
            extensions.append("AppendToAll")
        return extensions


__all__: list[str] = ["FlextLdifServersOidAclFormatMixin"]
