# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Models. Settings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._models._settings.acl import FlextLdifModelsSettingsAcl
    from flext_ldif._models._settings.criteria import FlextLdifModelsSettingsCriteria
    from flext_ldif._models._settings.migrate import FlextLdifModelsSettingsMigrate
    from flext_ldif._models._settings.misc import FlextLdifModelsSettingsMisc
    from flext_ldif._models._settings.normalization import (
        FlextLdifModelsSettingsNormalization,
    )
    from flext_ldif._models._settings.processing import (
        FlextLdifModelsSettingsProcessing,
    )
    from flext_ldif._models._settings.rules import FlextLdifModelsSettingsRules
    from flext_ldif._models._settings.validation import (
        FlextLdifModelsSettingsValidation,
    )


__all__: tuple[str, ...] = (
    "FlextLdifModelsSettingsAcl",
    "FlextLdifModelsSettingsCriteria",
    "FlextLdifModelsSettingsMigrate",
    "FlextLdifModelsSettingsMisc",
    "FlextLdifModelsSettingsNormalization",
    "FlextLdifModelsSettingsProcessing",
    "FlextLdifModelsSettingsRules",
    "FlextLdifModelsSettingsValidation",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextLdifModelsSettingsAcl": ".acl",
        "FlextLdifModelsSettingsCriteria": ".criteria",
        "FlextLdifModelsSettingsMigrate": ".migrate",
        "FlextLdifModelsSettingsMisc": ".misc",
        "FlextLdifModelsSettingsNormalization": ".normalization",
        "FlextLdifModelsSettingsProcessing": ".processing",
        "FlextLdifModelsSettingsRules": ".rules",
        "FlextLdifModelsSettingsValidation": ".validation",
    }),
    public_exports=__all__,
)
