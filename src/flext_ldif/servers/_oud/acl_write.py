"""Oracle Unified Directory (OUD) Servers — ACI write assembly.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oud.acl_subject import FlextLdifServersOudAclSubjectMixin


class FlextLdifServersOudAclWriteMixin(FlextLdifServersOudAclSubjectMixin):
    """OUD ACI write-side helpers (target/permissions clauses + serialization)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def _build_aci_permissions(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Build ACI permissions clause from ACL model.

        Returns:
            The resulting ``p.Result[str]``.
        """
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

        perms = acl_data.permissions or self._permissions_from_extensions(acl_data)
        if not perms:
            return r[str].fail("ACL model has no permissions t.JsonValue")
        filtered_ops = self._supported_oud_permissions(perms, acl_data)
        if not filtered_ops:
            return r[str].fail(
                f"ACL model has no OUD-supported permissions "
                f"(all were unsupported vendor-specific permissions like "
                f"{FlextLdifServersOudConstants.PERMISSION_SELF_WRITE}, "
                f"stored in metadata)",
            )
        ops_str = ",".join(filtered_ops)
        return r[str].ok(f"{FlextLdifServersOudConstants.ACL_ALLOW_PREFIX}{ops_str})")

    def _permissions_from_extensions(
        self,
        acl_data: m.Ldif.Acl,
    ) -> m.Ldif.AclPermissions | None:
        """Rebuild permissions from acl_target_permissions metadata extensions.

        Returns:
            The resulting ``m.Ldif.AclPermissions | None``.
        """
        if acl_data.permissions or not acl_data.metadata:
            return None
        extensions = acl_data.metadata.extensions
        target_perms_dict_raw = (
            extensions.get("acl_target_permissions") if extensions else None
        )
        if not target_perms_dict_raw:
            target_perms_dict_raw = (
                extensions.get("target_permissions") if extensions else None
            )
        permissions_value: t.JsonPayload | None = target_perms_dict_raw
        if not isinstance(permissions_value, Mapping):
            return None
        target_perms_dict = t.json_mapping_adapter().validate_python(permissions_value)
        perms_data = self._permission_dict_from_extensions(target_perms_dict)
        if not perms_data:
            return None
        return m.Ldif.AclPermissions(
            read=bool(perms_data.get("read")),
            write=bool(perms_data.get("write")),
            add=bool(perms_data.get("add")),
            delete=bool(perms_data.get("delete")),
            search=bool(perms_data.get("search")),
            compare=bool(perms_data.get("compare")),
            self_write=bool(
                perms_data.get("self_write") or perms_data.get("selfwrite"),
            ),
            proxy=bool(perms_data.get("proxy")),
        )

    @staticmethod
    def _permission_dict_from_extensions(
        target_perms_dict: t.MappingKV[str, t.JsonPayload],
    ) -> t.Ldif.MutableMetadataInputMapping:
        """Collect scalar/list permission values from an extensions mapping.

        Returns:
            The resulting ``t.Ldif.MutableMetadataInputMapping``.
        """
        perms_data: t.Ldif.MutableMetadataInputMapping = {}
        for key, val in target_perms_dict.items():
            if isinstance(val, Mapping):
                continue
            if isinstance(val, (str, bool, int, float)):
                perms_data[key] = val
            elif isinstance(val, list):
                str_list: t.JsonValueList = [
                    item for item in val if isinstance(item, str)
                ]
                perms_data[key] = u.normalize_to_metadata(str_list)
        return perms_data

    @staticmethod
    def _supported_oud_permissions(
        perms: m.Ldif.AclPermissions,
        acl_data: m.Ldif.Acl,
    ) -> t.MutableSequenceOf[str]:
        """List OUD-supported permission tokens active on the ACL model.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

        sc = FlextLdifServersOudConstants
        ops: t.MutableSequenceOf[str] = [
            field_name
            for field_name in (
                "read",
                "write",
                "add",
                "delete",
                "search",
                "compare",
                "self_write",
                "proxy",
            )
            if getattr(perms, field_name, False)
        ]
        permission_normalization = {"self_write": "selfwrite"}
        normalized_ops = [permission_normalization.get(op, op) for op in ops]
        filtered_ops = u.Ldif.filter_supported_permissions(
            normalized_ops,
            sc.SUPPORTED_PERMISSIONS,
        )
        meta_extensions = acl_data.metadata.extensions if acl_data.metadata else None
        self_write_to_write_enabled = (
            bool(meta_extensions.get("self_write_to_write"))
            if meta_extensions
            else False
        )
        if (
            self_write_to_write_enabled
            and (sc.PERMISSION_SELF_WRITE in ops)
            and ("write" not in filtered_ops)
        ):
            filtered_ops.append("write")
        return filtered_ops

    def _build_aci_target(self, acl_data: m.Ldif.Acl) -> str:
        """Build ACI target clause from ACL model.

        Returns:
            The resulting ``str``.
        """
        target = acl_data.target or self._target_from_extensions(acl_data)
        clause: str = u.Ldif.build_aci_target_clause(
            target_attributes=target.attributes if target else None,
            target_dn=target.target_dn if target else None,
            separator=" || ",
        )
        return clause

    def _target_from_extensions(
        self,
        acl_data: m.Ldif.Acl,
    ) -> m.Ldif.AclTarget | None:
        """Rebuild the ACL target from acl_target_target metadata extensions.

        Returns:
            The resulting ``m.Ldif.AclTarget | None``.
        """
        if acl_data.target or not acl_data.metadata:
            return None
        extensions = acl_data.metadata.extensions
        target_dict = extensions.get("acl_target_target") if extensions else None
        target_value: t.JsonPayload | None = target_dict
        if not isinstance(target_value, Mapping):
            return None
        target_data: t.Ldif.MutableMetadataMapping = {}
        for raw_key, raw_value in target_value.items():
            json_value: t.JsonPayload | None = raw_value
            if isinstance(json_value, Mapping):
                continue
            if self._scalar_or_list_value(json_value):
                target_data[raw_key] = u.normalize_to_metadata(json_value)
        if not target_data:
            return None
        attrs_raw = target_data.get("attributes")
        dn_raw = target_data.get("target_dn")
        attrs: t.MutableSequenceOf[str] = (
            [item for item in attrs_raw if isinstance(item, str)]
            if isinstance(attrs_raw, list)
            else []
        )
        dn: str = dn_raw if isinstance(dn_raw, str) else "*"
        return m.Ldif.AclTarget.model_validate({
            "target_dn": dn,
            "attributes": attrs,
        })

    @staticmethod
    def _should_use_raw_acl(acl_data: m.Ldif.Acl) -> bool:
        """Check if raw_acl should be used as-is.

        Returns:
            The resulting ``bool``.
        """
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

        if not acl_data.raw_acl:
            return False
        raw_acl_str: str = acl_data.raw_acl
        acl_aci_prefix: str = FlextLdifServersOudConstants.ACL_ACI_PREFIX
        return raw_acl_str.startswith(acl_aci_prefix)

    @override
    def _write_acl(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Write RFC-compliant ACL model to OUD ACI string (internal).

        Returns:
            The resulting ``p.Result[str]``.
        """
        try:
            return self._write_oud_aci(acl_data)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOudAclWriteMixin._module_logger.exception(
                "Failed to write ACL to OUD ACI format",
            )
            return r[str].fail(
                f"Failed to write ACL to OUD ACI format: {e}",
                exception=e,
            )

    def _write_oud_aci(self, acl_data: m.Ldif.Acl) -> p.Result[str]:
        """Build an OUD ACI string from the canonical ACL model.

        Returns:
            The resulting ``p.Result[str]``.
        """
        from flext_ldif.servers._oud.server_constants import (
            FlextLdifServersOudConstants,
        )

        sc = FlextLdifServersOudConstants
        extensions: t.Ldif.MutableMetadataMapping | None = (
            acl_data.metadata.extensions
            if acl_data.metadata and acl_data.metadata.extensions
            else None
        )
        aci_output_lines = u.Ldif.format_conversion_comments(
            extensions,
            "converted_from_server",
            "conversion_comments",
        )
        if self._should_use_raw_acl(acl_data):
            aci_output_lines.append(acl_data.raw_acl)
            return r[str].ok("\n".join(aci_output_lines))
        aci_parts = [self._build_aci_target(acl_data)]
        aci_parts.extend(
            u.Ldif.extract_target_extensions(
                extensions,
                sc.ACL_TARGET_EXTENSIONS_CONFIG,
            ),
        )
        acl_name = acl_data.name or sc.ACL_DEFAULT_NAME
        aci_parts.append(f'({sc.ACL_DEFAULT_VERSION}; acl "{acl_name}";')
        perms_result = self._build_aci_permissions(acl_data)
        if perms_result.failure:
            return r[str].from_failure(perms_result)
        subject_str = self._build_aci_subject(acl_data)
        if not subject_str:
            return r[str].fail("ACL subject DN was filtered out")
        bind_rules = u.Ldif.extract_bind_rules_from_extensions(
            extensions,
            sc.ACL_BIND_RULES_CONFIG,
            tuple_length=sc.ACL_BIND_RULE_TUPLE_LENGTH,
        )
        if bind_rules:
            subject_str = subject_str.rstrip(";)")
            subject_str = f"{subject_str} and {' and '.join(bind_rules)};)"
        aci_parts.extend([perms_result.value, subject_str])
        aci_string = f"{sc.ACL_ACI_PREFIX} {' '.join(aci_parts)}"
        aci_output_lines.append(aci_string)
        return r[str].ok("\n".join(aci_output_lines))


__all__: list[str] = ["FlextLdifServersOudAclWriteMixin"]
