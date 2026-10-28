"""Generated models ldif schemaelement module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_schemaelement
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
    from flext_cli import m as flext_cli_m


class FlextLdifProtocolsModelsLdifGeneratedSchemaElement:
    @runtime_checkable
    class SchemaElement(Protocol):
        validation_metadata: flext_cli_m.ConfigMap | None


__all__ = ["FlextLdifProtocolsModelsLdifGeneratedSchemaElement"]
