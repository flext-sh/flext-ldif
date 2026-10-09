"""Oracle Unified Directory (OUD) Servers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import ClassVar, Self, override

from flext_ldif import c, m, p, r, t, u
from flext_ldif.servers._oud import (
    FlextLdifServersOudAclWriteMixin,
    FlextLdifServersOudConstants,
    server_utilities,
)


class FlextLdifServersOudAcl(FlextLdifServersOudAclWriteMixin):
    """Oracle OUD ACL Implementation (RFC 4876 ACI Format)."""

    _module_logger: ClassVar[p.Logger] = u.fetch_logger(__name__)

    def __init__(
        self,
        acl_service: p.Ldif.AclServer | None = None,
        parent_server: Self | None = None,
        **kwargs: t.Ldif.Scalar,
    ) -> None:
        """Initialize OUD ACL server."""
        from flext_ldif.servers._base import FlextLdifServersBaseSchemaAcl

        filtered_kwargs: t.MutableConfigValueMapping = {
            k: v
            for k, v in kwargs.items()
            if k != "_parent_server" and isinstance(v, (str, float, bool))
        }
        acl_service_typed: p.Ldif.AclServer | None = (
            acl_service if acl_service is not None else None
        )
        parent_server_typed: FlextLdifServersBaseSchemaAcl | None = (
            parent_server
            if isinstance(parent_server, FlextLdifServersBaseSchemaAcl)
            else None
        )
        FlextLdifServersBaseSchemaAcl.__init__(
            self,
            acl_service=acl_service_typed,
            _parent_server=parent_server_typed,
            **filtered_kwargs,
        )

    @override
    def can_handle(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL (public method).

        Returns:
            The resulting ``bool``.
        """
        return self.can_handle_acl(acl_line)

    @staticmethod
    def _is_aci_start(line: str) -> bool:
        """Check if line starts an ACI definition.

        Returns:
            The resulting ``bool``.
        """
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_ACI_PREFIX.lower(),
        )

    @staticmethod
    def _is_ds_cfg_acl(line: str) -> bool:
        """Check if line is a ds-cfg ACL format.

        Returns:
            The resulting ``bool``.
        """
        return line.lower().startswith(
            FlextLdifServersOudConstants.ACL_DS_CFG_PREFIX.lower(),
        )

    @override
    def can_handle_acl(self, acl_line: str | m.Ldif.Acl) -> bool:
        """Check if this is an Oracle OUD ACL line (implements abstract method from.

        base.py).

        Returns:
            The resulting ``bool``.
        """
        if not isinstance(acl_line, str):
            acl_model = m.Ldif.Acl.model_validate(acl_line)
            if acl_model.metadata and acl_model.metadata.server_type:
                metadata_server_type = str(acl_model.metadata.server_type)
                current_server_type: str = self._get_server_type()
                return metadata_server_type == current_server_type
            return bool(
                acl_model.name
                and u.Ldif.normalize_attribute_name(acl_model.name)
                == u.Ldif.normalize_attribute_name(
                    FlextLdifServersOudConstants.ACL_ATTRIBUTE_NAME,
                ),
            )
        normalized = acl_line.strip()
        if not normalized:
            return False
        normalized_lower = normalized.lower()
        oud_prefixes = [
            FlextLdifServersOudConstants.ACL_ACI_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETATTR_PREFIX,
            FlextLdifServersOudConstants.ACL_TARGETSCOPE_PREFIX,
            FlextLdifServersOudConstants.ACL_DEFAULT_VERSION,
        ]
        starts_like_oud = (
            any(normalized.startswith(prefix) for prefix in oud_prefixes)
            or "ds-cfg-" in normalized_lower
        )
        is_non_legacy_acl = not any(
            pattern in normalized_lower for pattern in ["access to", "(", ")", "=", ":"]
        )
        return starts_like_oud or is_non_legacy_acl

    @override
    def resolve_acl_attributes(self) -> t.MutableSequenceOf[str]:
        """Get RFC + OUD extensions.

        Returns:
            The resulting ``t.MutableSequenceOf[str]``.
        """
        return [
            *FlextLdifServersOudConstants.RFC_ACL_ATTRIBUTES,
            *FlextLdifServersOudConstants.OUD_ACL_ATTRIBUTES,
        ]

    def _finalize_aci(
        self,
        current_aci: t.MutableSequenceOf[str],
        acls: t.MutableSequenceOf[m.Ldif.Acl],
    ) -> None:
        """Parse and add accumulated ACI to ACL list."""
        if current_aci:
            aci_text = "\n".join(current_aci)
            result = self.parse_server(aci_text)
            if result.success:
                acls.append(result.value)

    @staticmethod
    def _parse_aci_format(acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse RFC 4876 ACI format using utility with OUD-specific settings.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        settings = server_utilities.FlextLdifServersOudUtilities.resolve_parser_config()
        result: p.Result[m.Ldif.Acl] = u.Ldif.parse_aci(acl_line, settings)
        if not result.success:
            return result
        acl = result.value
        aci_content = acl_line.split(":", 1)[1].strip() if ":" in acl_line else ""
        extensions: t.MutableJsonMapping = {}
        if acl.metadata and acl.metadata.extensions:
            extensions.update(acl.metadata.extensions)
        timeofday_match = FlextLdifServersOudConstants.ACL_TIMEOFDAY_RE.search(
            aci_content,
        )
        if timeofday_match:
            extensions[c.Ldif.ACL_BIND_TIMEOFDAY] = (
                f"{timeofday_match.group(1)}{timeofday_match.group(2)}"
            )
        ssf_match = FlextLdifServersOudConstants.ACL_SSF_RE.search(aci_content)
        if ssf_match:
            extensions[c.Ldif.ACL_SSF] = f"{ssf_match.group(1)}{ssf_match.group(2)}"
        server_type_value = settings.server_type if settings else "oud"
        new_metadata = u.Ldif.server_metadata_for(
            server_type_value,
            extensions=extensions,
        )
        update_dict: MutableMapping[str, m.Ldif.ServerMetadata] = {
            "metadata": new_metadata,
        }
        acl_updated = acl.model_copy(update=update_dict)
        acl_result: m.Ldif.Acl = acl_updated
        return r[m.Ldif.Acl].ok(acl_result)

    @override
    def _parse_acl(self, acl_line: str) -> p.Result[m.Ldif.Acl]:
        """Parse Oracle OUD ACL string to RFC-compliant internal model.

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        normalized = acl_line.strip()
        # The ``aci`` LDIF attribute carries the bare ACI body without the
        # ``aci:`` wrapper; the RFC parser owns the wrapped form, so the
        # attribute-value body is wrapped before parsing instead of falling
        # through to the ds-privilege-name fallback.
        if normalized.startswith("(") and (
            FlextLdifServersOudConstants.ACL_ALLOW_PREFIX in normalized
            or FlextLdifServersOudConstants.ACL_DEFAULT_VERSION in normalized
        ):
            return self._parse_aci_format(
                f"{FlextLdifServersOudConstants.ACL_ACI_PREFIX} {normalized}",
            )
        if normalized.startswith(FlextLdifServersOudConstants.ACL_ACI_PREFIX):
            return self._parse_aci_format(acl_line)
        rfc_result = super()._parse_acl(acl_line)
        if rfc_result.success:
            acl_model = rfc_result.value
            if acl_model.name or normalized.startswith("aci:"):
                return rfc_result
        return self._parse_ds_privilege_name(normalized)

    @staticmethod
    def _parse_ds_privilege_name(privilege_name: str) -> p.Result[m.Ldif.Acl]:
        """Parse OUD ds-privilege-name format (simple privilege names).

        Returns:
            The resulting ``p.Result[m.Ldif.Acl]``.
        """
        try:
            server_type_oud: c.Ldif.ServerTypes = c.Ldif.ServerTypes.OUD
            acl_model = m.Ldif.Acl(
                name=privilege_name,
                target=None,
                subject=None,
                permissions=None,
                server_type=server_type_oud,
                raw_line=privilege_name,
                raw_acl=privilege_name,
                validation_violations=[],
                metadata=m.Ldif.ServerMetadata(
                    server_type=c.Ldif.ServerTypes.OUD,
                    extensions={
                        FlextLdifServersOudConstants.DS_PRIVILEGE_NAME_KEY: (
                            privilege_name
                        ),
                        FlextLdifServersOudConstants.FORMAT_TYPE_KEY: (
                            FlextLdifServersOudConstants.FORMAT_TYPE_DS_PRIVILEGE
                        ),
                    },
                ),
            )
            return r[m.Ldif.Acl].ok(acl_model)
        except c.Ldif.EXC_LDIF_PARSE as e:
            FlextLdifServersOudAcl._module_logger.exception(
                "Failed to parse OUD ds-privilege-name",
            )
            return r[m.Ldif.Acl].fail(
                f"Failed to parse OUD ds-privilege-name: {e}",
                exception=e,
            )


__all__: list[str] = ["FlextLdifServersOudAcl"]
