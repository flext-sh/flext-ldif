"""Configuration models for LDIF processing.

This module exposes the consolidated ``FlextLdifModelsSettings`` namespace.
Each concern lives in a focused mix-in module under ``_models/_settings_*.py``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif._models import (
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
    FlextLdifModelsSettingsNormalization,
    FlextLdifModelsSettingsProcessing,
    FlextLdifModelsSettingsCriteria,
    FlextLdifModelsSettingsRules,
    FlextLdifModelsSettingsMigrate,
    FlextLdifModelsSettingsValidation,
    FlextLdifModelsSettingsMisc,
):
    """Configuration models for LDIF processing.

    Plain namespace holder: the nested configuration models under each mixin
    are the Pydantic owners. The holder itself is never instantiated, so it
    must not carry ``FlextSettings`` (whose ``SettingsConfigDict``
    ``model_config`` is incompatible with the models facade's ``ConfigDict``
    when composed into the ``Ldif`` namespace MRO).
    """


__all__: list[str] = ["FlextLdifModelsSettings"]
