# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/domain_acl
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

from flext_ldif._protocols import FlextLdifProtocolsElements

if TYPE_CHECKING:
    from flext_ldif import t
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols import (
        FlextLdifLdifProtocolsGeneratedModelsServerMetadata,
        FlextLdifProtocolsBase,
    )


class FlextLdifProtocolsDomainAcl:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class AclPermissions(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def read(self) -> bool:
            """Read permission."""
            ...

        @property
        def write(self) -> bool:
            """Write permission."""
            ...

        @property
        def add(self) -> bool:
            """Add permission."""
            ...

        @property
        def delete(self) -> bool:
            """Delete permission."""
            ...

        @property
        def search(self) -> bool:
            """Search permission."""
            ...

        @property
        def compare(self) -> bool:
            """Compare permission."""
            ...

        @property
        def self_write(self) -> bool:
            """Self-write permission (OID, OUD)."""
            ...

        @property
        def proxy(self) -> bool:
            """Proxy permission (OID, OUD, 389DS)."""
            ...

        @property
        def browse(self) -> bool:
            """Browse permission (OID) - maps to read+search."""
            ...

        @property
        def auth(self) -> bool:
            """Auth permission (OID) - authentication access."""
            ...

        @property
        def all(self) -> bool:
            """All permissions (compound permission)."""
            ...

        @property
        def no_write(self) -> bool:
            """Deny write permission (OID)."""
            ...

        @property
        def no_add(self) -> bool:
            """Deny add permission (OID)."""
            ...

        @property
        def no_delete(self) -> bool:
            """Deny delete permission (OID)."""
            ...

        @property
        def no_browse(self) -> bool:
            """Deny browse permission (OID)."""
            ...

        @property
        def no_self_write(self) -> bool:
            """Deny self-write permission (OID)."""
            ...

    @runtime_checkable
    class AclTarget(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def target_dn(self) -> str:
            """Target DN pattern."""
            ...

        @property
        def attributes(self) -> MutableSequence[str]:
            """Target attributes."""
            ...

    @runtime_checkable
    class AclSubject(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def subject_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.AclSubjectType:
            """Subject type (user, group, etc.)."""
            ...

        @property
        def subject_value(self) -> str:
            """Subject value/pattern."""
            ...

    @runtime_checkable
    class Acl(FlextLdifProtocolsElements.AclElement, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """ACL name."""
            ...

        @property
        def target(self) -> FlextLdifProtocolsBase.AclTarget | None:
            """ACL target specification."""
            ...

        @property
        def subject(self) -> FlextLdifProtocolsBase.AclSubject | None:
            """ACL subject specification."""
            ...

        @property
        def permissions(self) -> FlextLdifProtocolsBase.AclPermissions | None:
            """ACL permission flags."""
            ...

        @property
        def raw_line(self) -> str:
            """Original raw ACL line from LDIF."""
            ...

        @property
        def raw_acl(self) -> str:
            """Original ACL string from LDIF."""
            ...

        @property
        def metadata(
            self,
        ) -> FlextLdifLdifProtocolsGeneratedModelsServerMetadata.ServerMetadata | None:
            """Server-specific metadata for ACL processing."""
            ...

        def resolve_acl_type(self) -> str:
            """Get ACL type identifier for this server using canonical enum."""
            ...

    @runtime_checkable
    class AclWriteMetadata(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_format(self) -> str | None:
            """Original ACL string format from source server."""
            ...

        @property
        def source_server(self) -> str | None:
            """Server type that parsed this ACL."""
            ...

        @property
        def name_sanitized(self) -> bool:
            """True if ACL name was sanitized during processing."""
            ...

        @property
        def original_name_raw(self) -> str | None:
            """Original ACL name before sanitization."""
            ...

        def has_original_format(self) -> bool:
            """Check if original ACL format is available for name replacement."""
            ...

    @runtime_checkable
    class PermissionMappingConfig(FlextCliProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_acl(self) -> FlextLdifProtocolsBase.Acl:
            """Original ACL model."""
            ...

        @property
        def converted_acl(self) -> FlextLdifProtocolsBase.Acl:
            """Converted ACL model (modified in-place)."""
            ...

        @property
        def orig_perms_dict(self) -> t.MutableBoolMapping:
            """Original permissions dict."""
            ...

        @property
        def source_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Source server type."""
            ...

        @property
        def target_server_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Target server type."""
            ...

        @property
        def converted_has_permissions(self) -> bool:
            """Whether converted ACL has permissions."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsDomainAcl",
]
