# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_schemaelement
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_cli import m as flext_cli_m


class FlextLdifLdifProtocolsGeneratedModelsSchemaElement:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class SchemaElement(Protocol):
        """Structural data contract projected from the owning model."""

        validation_metadata: flext_cli_m.ConfigMap | None


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsSchemaElement",
]
