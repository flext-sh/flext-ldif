"""Extracted facade class for settings.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._models._settings import (
    FlextLdifModelsSettingsAcl,
    FlextLdifModelsSettingsCriteria,
    FlextLdifModelsSettingsMigrate,
    FlextLdifModelsSettingsMisc,
    FlextLdifModelsSettingsNormalization,
    FlextLdifModelsSettingsProcessing,
    FlextLdifModelsSettingsRules,
    FlextLdifModelsSettingsValidation,
)


class FlextLdifModelsSettings(
    FlextLdifModelsSettingsAcl,
    FlextLdifModelsSettingsCriteria,
    FlextLdifModelsSettingsMigrate,
    FlextLdifModelsSettingsMisc,
    FlextLdifModelsSettingsNormalization,
    FlextLdifModelsSettingsProcessing,
    FlextLdifModelsSettingsRules,
    FlextLdifModelsSettingsValidation,
):
    """Facade for settings."""


__all__: list[str] = ["FlextLdifModelsSettings"]
