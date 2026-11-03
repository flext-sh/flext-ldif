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
    from flext_ldif._protocols import FlextLdifProtocolsDomainMetadata


class FlextLdifProtocolsDomainAcl:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class AclPermissions(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        read: bool
        write: bool
        add: bool
        delete: bool
        search: bool
        compare: bool
        self_write: bool
        proxy: bool
        browse: bool
        auth: bool
        all: bool
        no_write: bool
        no_add: bool
        no_delete: bool
        no_browse: bool
        no_self_write: bool

    @runtime_checkable
    class AclTarget(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        target_dn: str
        attributes: MutableSequence[str]

    @runtime_checkable
    class AclSubject(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def subject_type(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.AclSubjectType:
            """Subject type (user, group, etc.)."""
            ...

        subject_value: str

    @runtime_checkable
    class Acl(FlextLdifProtocolsElements.AclElement, Protocol):
        """Structural data contract projected from the owning model."""

        name: str

        @property
        def target(self) -> FlextLdifProtocolsDomainAcl.AclTarget | None:
            """ACL target specification."""
            ...

        @property
        def subject(self) -> FlextLdifProtocolsDomainAcl.AclSubject | None:
            """ACL subject specification."""
            ...

        @property
        def permissions(self) -> FlextLdifProtocolsDomainAcl.AclPermissions | None:
            """ACL permission flags."""
            ...

        raw_line: str
        raw_acl: str

        @property
        def metadata(self) -> FlextLdifProtocolsDomainMetadata.ServerMetadata | None:
            """Server-specific metadata for ACL processing."""
            ...

        def resolve_acl_type(self) -> str:
            """Get ACL type identifier for this server using canonical enum."""
            ...

    @runtime_checkable
    class AclWriteMetadata(FlextCliProtocols.BaseModel, Protocol):
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
    class PermissionMappingConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def original_acl(self) -> FlextLdifProtocolsDomainAcl.Acl:
            """Original ACL model."""
            ...

        @property
        def converted_acl(self) -> FlextLdifProtocolsDomainAcl.Acl:
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
