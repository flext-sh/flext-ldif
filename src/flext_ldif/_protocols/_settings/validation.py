# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/_settings/validation
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_cli import FlextCliProtocols


class FlextLdifProtocolsSettingsValidation:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class ServerValidationRules(FlextCliProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def requires_binary_option(self) -> bool:
            """Whether server requires ;binary option for non-ASCII values."""
            ...

        @property
        def requires_naming_attr(self) -> bool:
            """Whether server requires naming attribute in entry."""
            ...

        @property
        def requires_objectclass(self) -> bool:
            """Whether server requires objectClass attribute."""
            ...


__all__: list[str] = [
    "FlextLdifProtocolsSettingsValidation",
]
