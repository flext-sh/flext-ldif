# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
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

from flext_cli import m as flext_cli_m

from flext_ldif._models import (
    FlextLdifModelsBases,
    FlextLdifModelsCollections,
    FlextLdifModelsComposite,
    FlextLdifModelsConfig,
    FlextLdifModelsDomainEntryChangeOperationValue,
    FlextLdifModelsDomainEntryControl,
    FlextLdifModelsDomainEntryStatistics,
    FlextLdifModelsDomainsEntries,
    FlextLdifModelsEvents,
    FlextLdifModelsProcessing,
    FlextLdifModelsResults,
    FlextLdifModelsSettings,
)


class FlextLdifModels(flext_cli_m):
    """LDIF domain models — flat façade with MRO class inheritance.

    Architecture: Domain layer helper
    All nested classes inherit via MRO from their ``models`` implementations.
    Types live in ``typings.py``, constants in ``constants.py``.
    """

    class Ldif(
        FlextLdifModelsBases,
        FlextLdifModelsCollections,
        FlextLdifModelsComposite,
        FlextLdifModelsConfig,
        FlextLdifModelsDomainsEntries,
        FlextLdifModelsDomainEntryChangeOperationValue,
        FlextLdifModelsDomainEntryControl,
        FlextLdifModelsDomainEntryStatistics,
        FlextLdifModelsEvents,
        FlextLdifModelsProcessing,
        FlextLdifModelsResults,
        FlextLdifModelsSettings,
    ):
        """LDIF namespace for cross-project access."""


m = FlextLdifModels
__all__: list[str] = ["FlextLdifModels", "m"]
