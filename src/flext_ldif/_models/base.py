"""Base classes for flext-ldif models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_models/base
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_cli import m

from flext_ldif import p, t
from flext_ldif._models.elements import FlextLdifModelsBasesParts


class FlextLdifModelsBases(FlextLdifModelsBasesParts):
    """Facade namespace for all FLEXT-LDIF base model classes."""

    class RegistryPortOptions(m.ArbitraryTypesModel):
        """Required registry capability shared by the consuming service MRO."""

        registry: t.Port[p.Registry] = m.Field(
            exclude=True, description="Explicit instance-scoped dialect registry"
        )


__all__: list[str] = ["FlextLdifModelsBases"]
