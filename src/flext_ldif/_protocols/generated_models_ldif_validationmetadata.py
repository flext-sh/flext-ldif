"""Generated models ldif validationmetadata module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_validationmetadata
SPDX-License-Identifier: MIT
"""

# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import MutableMapping as collections_abc_MutableMapping

    from flext_ldif import c as flext_ldif_c, t as flext_ldif_t


class FlextLdifProtocolsModelsLdifGeneratedValidationMetadata:
    @runtime_checkable
    class ValidationMetadata(Protocol):
        rfc_violations: flext_ldif_t.MutableSequence[str]
        errors: flext_ldif_t.MutableSequence[str]
        warnings: flext_ldif_t.MutableSequence[str]
        context: collections_abc_MutableMapping[str, str]
        server_specific_violations: flext_ldif_t.MutableSequence[str]
        validation_server_type: flext_ldif_c.Ldif.ServerTypes | None


__all__ = ["FlextLdifProtocolsModelsLdifGeneratedValidationMetadata"]
