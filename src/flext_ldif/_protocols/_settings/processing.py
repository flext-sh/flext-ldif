# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/processing
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_cli import FlextCliProtocols

if TYPE_CHECKING:
    from flext_ldif._constants import FlextLdifConstantsBaseParts
    from flext_ldif._protocols._settings import FlextLdifProtocolsSettingsNormalization


class FlextLdifProtocolsSettingsProcessing:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ProcessConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        batch_size: int
        timeout_seconds: int
        max_retries: int

        @property
        def source_server(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Source LDAP server type identifier."""
            ...

        @property
        def target_server(
            self,
        ) -> FlextLdifConstantsBaseParts.FlextLdifConstantsEnums.ServerTypes | None:
            """Target LDAP server type identifier."""
            ...

        base_dn: str

        @property
        def dn_config(
            self,
        ) -> FlextLdifProtocolsSettingsNormalization.DnNormalizationConfig | None:
            """DN normalization configuration."""
            ...

        @property
        def attr_config(
            self,
        ) -> FlextLdifProtocolsSettingsNormalization.AttrNormalizationConfig | None:
            """Attribute normalization configuration."""
            ...

    @runtime_checkable
    class TransformConfig(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def fail_fast(self) -> bool:
            """Stop on first transformation error."""
            ...

        @property
        def preserve_order(self) -> bool:
            """Preserve original entry ordering."""
            ...

        @property
        def track_changes(self) -> bool:
            """Track attribute-level changes for audit."""
            ...

        @property
        def normalize_dns(self) -> bool:
            """Normalize DNs during transformation."""
            ...

        @property
        def normalize_attrs(self) -> bool:
            """Normalize attributes during transformation."""
            ...

        @property
        def process_config(
            self,
        ) -> FlextLdifProtocolsSettingsProcessing.ProcessConfig | None:
            """Processing configuration for batch operations."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsProcessing",
]
