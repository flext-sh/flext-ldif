# AUTO-GENERATED FILE — Regenerate with: make gen
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_ldif._protocols import FlextLdifProtocolsValues


class FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion:
    @runtime_checkable
    class AclEntryConversion(Protocol):
        rules: tuple[FlextLdifProtocolsValues.AciRule, ...]
        oracle_internal_skip: bool


__all__ = ["FlextLdifLdifProtocolsGeneratedModelsAclEntryConversion"]
