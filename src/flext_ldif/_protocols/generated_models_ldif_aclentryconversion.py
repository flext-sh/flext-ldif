"""Generated models ldif aclentryconversion module.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/generated_models_ldif_aclentryconversion
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
    from flext_ldif._protocols import FlextLdifProtocolsValues


class FlextLdifProtocolsModelsLdifGeneratedAclEntryConversion:
    @runtime_checkable
    class AclEntryConversion(Protocol):
        rules: tuple[FlextLdifProtocolsValues.AciRule, ...]
        oracle_internal_skip: bool


__all__ = ["FlextLdifProtocolsModelsLdifGeneratedAclEntryConversion"]
