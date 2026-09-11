"""Configuration models for LDIF processing.

This module exposes the consolidated ``FlextLdifModelsSettings`` namespace.
Each concern lives in a focused mix-in module under ``_models/_settings_*.py``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from ._settings_acl import FlextLdifModelsSettingsAcl
from ._settings_criteria import FlextLdifModelsSettingsCriteria
from ._settings_migrate import FlextLdifModelsSettingsMigrate
from ._settings_misc import FlextLdifModelsSettingsMisc
from ._settings_normalization import FlextLdifModelsSettingsNormalization
from ._settings_processing import FlextLdifModelsSettingsProcessing
from ._settings_rules import FlextLdifModelsSettingsRules
from ._settings_validation import FlextLdifModelsSettingsValidation


class FlextLdifModelsSettings(
    FlextLdifModelsSettingsAcl,
    FlextLdifModelsSettingsNormalization,
    FlextLdifModelsSettingsProcessing,
    FlextLdifModelsSettingsCriteria,
    FlextLdifModelsSettingsRules,
    FlextLdifModelsSettingsMigrate,
    FlextLdifModelsSettingsValidation,
    FlextLdifModelsSettingsMisc,
):
    """Configuration models for LDIF processing."""


__all__: list[str] = ["FlextLdifModelsSettings"]
