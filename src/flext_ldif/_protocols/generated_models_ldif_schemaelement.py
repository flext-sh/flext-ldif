# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_cli import m as flext_cli_m


class FlextLdifLdifProtocolsGeneratedModelsSchemaElement:
    @runtime_checkable
    class SchemaElement(Protocol):
        validation_metadata: flext_cli_m.ConfigMap | None


__all__ = ["FlextLdifLdifProtocolsGeneratedModelsSchemaElement"]
