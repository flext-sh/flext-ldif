# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contract.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_validationmetadata
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import (
        MutableMapping as collections_abc_MutableMapping,
        MutableSequence as collections_abc_MutableSequence,
    )

    from flext_ldif import c as flext_ldif_c


class FlextLdifLdifProtocolsGeneratedModelsValidationMetadata:
    """Own the structural model contract declared by this module."""

    @runtime_checkable
    class ValidationMetadata(Protocol):
        """Structural data contract projected from the owning model."""

        rfc_violations: collections_abc_MutableSequence[str]
        errors: collections_abc_MutableSequence[str]
        warnings: collections_abc_MutableSequence[str]
        context: collections_abc_MutableMapping[str, str]
        server_specific_violations: collections_abc_MutableSequence[str]
        validation_server_type: flext_ldif_c.Ldif.ServerTypes | None


__all__: list[str] = [
    "FlextLdifLdifProtocolsGeneratedModelsValidationMetadata",
]
