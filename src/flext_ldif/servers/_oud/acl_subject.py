"""Oracle Unified Directory (OUD) Servers — ACI subject clause building.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from flext_ldif import m, p, t, u
from flext_ldif.servers._oud.server_constants import FlextLdifServersOudConstants
from flext_ldif.servers.rfc import FlextLdifServersRfc


class FlextLdifServersOudAclSubjectMixin(FlextLdifServersRfc.Acl):
    """OUD ACI subject/bind-rule clause helpers."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    @staticmethod
    def _extension_get_str(
        extensions: t.Ldif.MetadataInputMapping | None,
        key: str,
    ) -> str | None:
        """Read a metadata extension as string.

        Returns:
            The resulting ``str | None``.
        """
        if not extensions:
            return None
        value = extensions.get(key)
        return value if isinstance(value, str) else None

    @staticmethod
    def _scalar_or_list_value(value: t.JsonPayload | None) -> bool:
        """Check if value is scalar metadata value or list.

        Returns:
            The resulting ``bool``.
        """
        return isinstance(value, (str, int, float, bool, list))

    def _build_aci_subject(self, acl_data: m.Ldif.Acl) -> str:
        """Build ACI bind rules (subject) clause from ACL model.

        Returns:
            The resulting ``str``.
        """
        base_dn, subject_type, subject_value = self._extract_and_resolve_acl_subject(
            acl_data,
        )
        if not subject_type or subject_type == "self":
            return f'userdn="{FlextLdifServersOudConstants.ACL_SELF_SUBJECT}";)'
        attr_suffix_map = {
            "dn_attr": "LDAPURL",
            "guid_attr": "USERDN",
            "group_attr": "GROUPDN",
        }
        if subject_type in attr_suffix_map:
            suffix = attr_suffix_map[subject_type]
            return f'userattr="{subject_value}#{suffix}";)'
        filtered_value = (
            subject_value[: -len(base_dn)].rstrip(",")
            if base_dn and subject_value.endswith(base_dn)
            else subject_value
        )
        bind_operator = {"user": "userdn", "group": "groupdn", "role": "roledn"}.get(
            subject_type,
            "userdn",
        )
        formatted: str = u.Ldif.format_aci_subject(
            subject_type,
            filtered_value,
            bind_operator,
        )
        return formatted

    def _extract_and_resolve_acl_subject(
        self,
        acl_data: m.Ldif.Acl,
    ) -> tuple[str | None, str, str]:
        """Extract metadata and resolve subject type and value in one pass.

        Returns:
            The resulting ``tuple[str | None, str, str]``.
        """
        ext = acl_data.metadata.extensions if acl_data.metadata else None
        base_dn = self._extension_get_str(ext, "base_dn")
        source_subject_type = self._extension_get_str(ext, "acl_source_subject_type")
        subject = acl_data.subject
        attr_subject_types = {"dn_attr", "guid_attr", "group_attr"}
        subject_type = (
            source_subject_type
            if source_subject_type in attr_subject_types
            else (subject.subject_type if subject else source_subject_type)
        ) or "self"
        if subject_type == FlextLdifServersOudConstants.ACL_SUBJECT_TYPE_BIND_RULES:
            subject_type = self._resolved_bind_rules_subject_type(
                subject,
                source_subject_type,
            )
        subject_value = (
            subject.subject_value if subject else None
        ) or self._extension_get_str(ext, "acl_original_subject_value")
        if not subject_value:
            subject_value = (
                FlextLdifServersOudConstants.ACL_SELF_SUBJECT
                if subject_type == "self"
                else ""
            )
        return (base_dn, subject_type, subject_value)

    def _resolved_bind_rules_subject_type(
        self,
        subject: m.Ldif.AclSubject | None,
        source_subject_type: str | None,
    ) -> str:
        """Resolve the subject type hidden behind a bind-rules subject value.

        Returns:
            The resulting ``str``.
        """
        subject_value_lower = (subject.subject_value or "").lower() if subject else ""
        source_subject_type_normalized = source_subject_type or ""
        match source_subject_type_normalized:
            case "dn_attr" | "guid_attr" | "group_attr":
                return source_subject_type_normalized
            case "group_dn":
                return "group"
            case _ if (
                "group=" in subject_value_lower
                or FlextLdifServersOudConstants.ACL_BIND_RULE_TYPE_GROUPDN
                in subject_value_lower
            ):
                return "group"
            case _:
                return FlextLdifServersOudConstants.ACL_SUBJECT_TYPE_BIND_RULES


__all__: list[str] = ["FlextLdifServersOudAclSubjectMixin"]
