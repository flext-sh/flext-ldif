# AUTO-GENERATED FILE — Regenerate with: make gen
"""LDIF Domain Models - Unified Model Aggregation Layer.

Facade that groups all LDIF model classes for the ``FlextLdifModels``
namespace.  Every nested class uses real MRO inheritance from its
internal ``models`` definition — no ``TypeAlias`` for classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_cli import m as flext_cli_m

from flext_ldif._models.base import FlextLdifModelsBases
from flext_ldif._models.collections import FlextLdifModelsCollections
from flext_ldif._models.composite import FlextLdifModelsComposite
from flext_ldif._models.config import FlextLdifModelsConfig
from flext_ldif._models.domain_entries import FlextLdifModelsDomainsEntries
from flext_ldif._models.domain_entry_change_value import (
    FlextLdifModelsDomainEntryChangeOperationValue,
)
from flext_ldif._models.domain_entry_control import FlextLdifModelsDomainEntryControl
from flext_ldif._models.domain_entry_statistics import (
    FlextLdifModelsDomainEntryStatistics,
)
from flext_ldif._models.events import FlextLdifModelsEvents
from flext_ldif._models.processing import FlextLdifModelsProcessing
from flext_ldif._models.results import FlextLdifModelsResults
from flext_ldif._models.settings import FlextLdifModelsSettings


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
