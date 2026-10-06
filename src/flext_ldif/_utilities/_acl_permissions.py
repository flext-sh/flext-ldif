"""LDIF ACL permission mapping utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeIs

from flext_ldif import c, t


class FlextLdifACLPermissions:
    """Normalize, build, and map ACL permission dictionaries."""

    _ACL_SUBJECT_TYPE_VALUES: frozenset[str] = frozenset(
        subject_type.value for subject_type in c.Ldif.AclSubjectType
    )

    @staticmethod
    def _is_acl_subject_type(value: str) -> TypeIs[c.Ldif.AclSubjectType]:
        """Type guard to check if a string is a valid ACL subject enum value.

        Returns:
            The resulting ``TypeIs[c.Ldif.AclSubjectType]``.
        """
        return value in FlextLdifACLPermissions._ACL_SUBJECT_TYPE_VALUES

    @staticmethod
    def _normalize_permission(
        perm: str,
        permission_map: t.MutableStrMapping | None,
    ) -> str:
        """Normalize permission name using map if available.

        Returns:
            The resulting ``str``.
        """
        if not permission_map:
            return perm
        normalized_permission: str = permission_map.get(perm, perm)
        return normalized_permission

    @staticmethod
    def _process_permission_list(
        perm_list: t.MutableSequenceOf[str],
        permission_map: t.MutableStrMapping | None,
        *,
        is_allow: bool,
    ) -> t.MutableBoolMapping:
        """Process permission list into dictionary.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        result: t.MutableBoolMapping = {}
        for perm in perm_list:
            if perm:
                normalized = FlextLdifACLPermissions._normalize_permission(
                    perm,
                    permission_map,
                )
                result[normalized] = is_allow
        return result

    @staticmethod
    def build_permissions_dict(
        allow_permissions: t.MutableSequenceOf[str],
        permission_map: t.MutableStrMapping | None = None,
        deny_permissions: t.MutableSequenceOf[str] | None = None,
    ) -> t.MutableBoolMapping:
        """Build permissions dictionary from allow/deny lists.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        allow_dict: t.MutableBoolMapping = {}
        if allow_permissions:
            allow_dict = FlextLdifACLPermissions._process_permission_list(
                allow_permissions,
                permission_map,
                is_allow=True,
            )
        deny_dict: t.MutableBoolMapping = {}
        if deny_permissions:
            deny_dict = FlextLdifACLPermissions._process_permission_list(
                deny_permissions,
                permission_map,
                is_allow=False,
            )
        return {**allow_dict, **deny_dict}

    @staticmethod
    def normalize_permission_key(key: str) -> str:
        """Normalize permission key for cross-server ACL mapping.

        Returns:
            The resulting ``str``.
        """
        return {"self_write": "selfwrite"}.get(key, key)

    @staticmethod
    def map_oid_to_oud_permissions(
        orig_perms_dict: t.MutableBoolMapping,
    ) -> t.MutableBoolMapping:
        """Map OID permission names to OUD permission names.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        normalized_orig_perms: t.MutableBoolMapping = {
            FlextLdifACLPermissions.normalize_permission_key(key): value
            for key, value in orig_perms_dict.items()
        }
        mapping_values = {
            FlextLdifACLPermissions.normalize_permission_key(key)
            for key in c.Ldif.ACL_PERMISSION_KEYS
        }
        pass_through_perms = {
            key for key in mapping_values if key not in {"browse", "selfwrite"}
        }
        mapped_perms: t.MutableBoolMapping = {}
        for perm_name, perm_value in normalized_orig_perms.items():
            if perm_name == "browse":
                mapped_perms["read"] = mapped_perms.get("read", False) or perm_value
                mapped_perms["search"] = (
                    mapped_perms.get("search", False) or perm_value
                )
                continue
            if perm_name == "selfwrite":
                mapped_perms["write"] = mapped_perms.get("write", False) or perm_value
                continue
            if perm_name in pass_through_perms:
                mapped_perms[perm_name] = (
                    mapped_perms.get(perm_name, False) or perm_value
                )
        return mapped_perms

    @staticmethod
    def map_oud_to_oid_permissions(
        orig_perms_dict: t.MutableBoolMapping,
    ) -> t.MutableBoolMapping:
        """Map OUD permission names to OID permission names.

        Returns:
            The resulting ``t.MutableBoolMapping``.
        """
        normalized_orig_perms: t.MutableBoolMapping = {
            FlextLdifACLPermissions.normalize_permission_key(key): value
            for key, value in orig_perms_dict.items()
        }
        mapping_values = {
            FlextLdifACLPermissions.normalize_permission_key(key)
            for key in c.Ldif.ACL_PERMISSION_KEYS
        }
        pass_through_perms = {
            key for key in mapping_values if key not in {"read", "search", "browse"}
        }
        has_read = normalized_orig_perms.get("read", False)
        has_search = normalized_orig_perms.get("search", False)
        mapped_perms: t.MutableBoolMapping = {}
        if has_read or has_search:
            mapped_perms["browse"] = has_read and has_search
        for perm_name, perm_value in normalized_orig_perms.items():
            if perm_name in pass_through_perms:
                mapped_perms[perm_name] = perm_value
        return mapped_perms

    @staticmethod
    def build_mapped_permissions_dict(
        mapped_perms: t.MutableBoolMapping,
        mapping: t.MutableStrMapping,
    ) -> t.MutableOptionalBoolMapping:
        """Build permissions dict from a source->mapped key table.

        Returns:
            The resulting ``t.MutableOptionalBoolMapping``.
        """
        result: t.MutableOptionalBoolMapping = {}
        for source_key, mapped_key in mapping.items():
            result[source_key] = mapped_perms.get(mapped_key)
        return result

    @staticmethod
    def filter_supported_permissions(
        permissions: t.MutableSequenceOf[str],
        supported: set[str] | frozenset[str],
    ) -> t.MutableSequenceOf[str]:
        """Filter permissions to only include supported ones.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        supported_lower = {s.lower() for s in supported}
        return [perm.lower() for perm in permissions if perm.lower() in supported_lower]


__all__: list[str] = ["FlextLdifACLPermissions"]
