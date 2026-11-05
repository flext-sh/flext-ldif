# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/acl
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif import c, t


class FlextLdifProtocolsSettingsAcl:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class AciLineFormatConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """ACL name."""
            ...

        @property
        def target_clause(self) -> str:
            """Target clause (e.g., '(targetattr="cn")')."""
            ...

        @property
        def permissions_clause(self) -> str:
            """Permissions clause (e.g., 'allow (read,write)')."""
            ...

        @property
        def bind_rule(self) -> str:
            """Bind rule (e.g., 'userdn="ldap:///self"')."""
            ...

        @property
        def aci_prefix(self) -> str:
            """ACI attribute prefix."""
            ...

        @property
        def version(self) -> str:
            """ACI version."""
            ...

    @runtime_checkable
    class AciParserConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def server_type(self) -> c.Ldif.ServerTypes:
            """Server type identifier (oid, oud, rfc, etc.)."""
            ...

        @property
        def aci_prefix(self) -> str:
            """ACI line prefix."""
            ...

        @property
        def version_acl_pattern(self) -> str:
            """Regex pattern to extract version and ACL name."""
            ...

        @property
        def targetattr_pattern(self) -> str:
            """Regex pattern to extract target attributes."""
            ...

        @property
        def default_targetattr(self) -> str:
            """Default targetattr when none found."""
            ...

        @property
        def allow_deny_pattern(self) -> str:
            """Regex pattern to extract allow/deny permissions."""
            ...

        @property
        def ops_separator(self) -> str:
            """Separator for operations list."""
            ...

        @property
        def action_filter(self) -> str | None:
            """Only include permissions for this action."""
            ...

        @property
        def bind_patterns(self) -> t.MutableStrMapping:
            """Mapping of bind type names to regex patterns."""
            ...

        @property
        def permission_map(self) -> t.MutableStrMapping:
            """Permission name normalization map."""
            ...

        @property
        def special_subjects(self) -> t.MutableStrPairMapping:
            """Special subject value mappings."""
            ...

        @property
        def extra_patterns(self) -> t.MutableStrMapping:
            """Additional extraction patterns for extensions."""
            ...

        @property
        def default_name(self) -> str:
            """Default ACL name when none found."""
            ...

    @runtime_checkable
    class AclMetadataConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def line_breaks(self) -> t.JsonValueList | None:
            """Line break positions."""
            ...

        @property
        def dn_spaces(self) -> str | None:
            """DN spacing information."""
            ...

        @property
        def targetscope(self) -> t.JsonValueList | None:
            """Target scope values."""
            ...

        @property
        def version(self) -> str | None:
            """ACI version string."""
            ...

        @property
        def action_type(self) -> str | None:
            """Action type (allow/deny)."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsAcl",
]
