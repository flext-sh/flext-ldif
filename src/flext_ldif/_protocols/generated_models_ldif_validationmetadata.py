# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import MutableMapping as collections_abc_MutableMapping

    from flext_ldif import c as flext_ldif_c, t as flext_ldif_t


class FlextLdifLdifProtocolsGeneratedModelsValidationMetadata:
    @runtime_checkable
    class ValidationMetadata(Protocol):
        rfc_violations: flext_ldif_t.MutableSequenceOf[str]
        errors: flext_ldif_t.MutableSequenceOf[str]
        warnings: flext_ldif_t.MutableSequenceOf[str]
        context: collections_abc_MutableMapping[str, str]
        server_specific_violations: flext_ldif_t.MutableSequenceOf[str]
        validation_server_type: flext_ldif_c.Ldif.ServerTypes | None


__all__ = ["FlextLdifLdifProtocolsGeneratedModelsValidationMetadata"]
