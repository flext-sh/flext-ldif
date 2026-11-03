# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_protocols/settings
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._protocols._settings import (
    FlextLdifProtocolsSettingsAcl,
    FlextLdifProtocolsSettingsCriteria,
    FlextLdifProtocolsSettingsMigrate,
    FlextLdifProtocolsSettingsMisc,
    FlextLdifProtocolsSettingsNormalization,
    FlextLdifProtocolsSettingsProcessing,
    FlextLdifProtocolsSettingsRules,
    FlextLdifProtocolsSettingsValidation,
)


class FlextLdifProtocolsSettings(
    FlextLdifProtocolsSettingsAcl,
    FlextLdifProtocolsSettingsCriteria,
    FlextLdifProtocolsSettingsMigrate,
    FlextLdifProtocolsSettingsMisc,
    FlextLdifProtocolsSettingsNormalization,
    FlextLdifProtocolsSettingsProcessing,
    FlextLdifProtocolsSettingsRules,
    FlextLdifProtocolsSettingsValidation,
):
    """Own the structural contracts declared by its model source."""


__all__: list[str] = [
    "FlextLdifProtocolsSettings",
]
