# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Ldif. Protocols. Settings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_ldif._protocols._settings.acl import FlextLdifProtocolsSettingsAcl
    from flext_ldif._protocols._settings.criteria import (
        FlextLdifProtocolsSettingsCriteria,
    )
    from flext_ldif._protocols._settings.migrate import (
        FlextLdifProtocolsSettingsMigrate,
    )
    from flext_ldif._protocols._settings.misc import FlextLdifProtocolsSettingsMisc
    from flext_ldif._protocols._settings.normalization import (
        FlextLdifProtocolsSettingsNormalization,
    )
    from flext_ldif._protocols._settings.processing import (
        FlextLdifProtocolsSettingsProcessing,
    )
    from flext_ldif._protocols._settings.rules import FlextLdifProtocolsSettingsRules
    from flext_ldif._protocols._settings.validation import (
        FlextLdifProtocolsSettingsValidation,
    )


__all__: tuple[str, ...] = (
    "FlextLdifProtocolsSettingsAcl",
    "FlextLdifProtocolsSettingsCriteria",
    "FlextLdifProtocolsSettingsMigrate",
    "FlextLdifProtocolsSettingsMisc",
    "FlextLdifProtocolsSettingsNormalization",
    "FlextLdifProtocolsSettingsProcessing",
    "FlextLdifProtocolsSettingsRules",
    "FlextLdifProtocolsSettingsValidation",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextLdifProtocolsSettingsAcl": ".acl",
        "FlextLdifProtocolsSettingsCriteria": ".criteria",
        "FlextLdifProtocolsSettingsMigrate": ".migrate",
        "FlextLdifProtocolsSettingsMisc": ".misc",
        "FlextLdifProtocolsSettingsNormalization": ".normalization",
        "FlextLdifProtocolsSettingsProcessing": ".processing",
        "FlextLdifProtocolsSettingsRules": ".rules",
        "FlextLdifProtocolsSettingsValidation": ".validation",
    },
    public_exports=__all__,
)
