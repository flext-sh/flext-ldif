"""Configuration models for LDIF processing.

This module exposes the consolidated ``FlextLdifModelsSettings`` namespace.
Each concern lives in a focused mix-in module under ``_models/_settings_*.py``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Self

from flext_core import FlextSettings

from ._settings_acl import FlextLdifModelsSettingsAcl
from ._settings_criteria import FlextLdifModelsSettingsCriteria
from ._settings_migrate import FlextLdifModelsSettingsMigrate
from ._settings_misc import FlextLdifModelsSettingsMisc
from ._settings_normalization import FlextLdifModelsSettingsNormalization
from ._settings_processing import FlextLdifModelsSettingsProcessing
from ._settings_rules import FlextLdifModelsSettingsRules
from ._settings_validation import FlextLdifModelsSettingsValidation


class FlextLdifModelsSettings(
    FlextSettings,
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

    MRO carries ``FlextSettings`` FIRST (ENFORCE-042); the class is a namespace
    holder, never instantiated — nested namespaces resolve via the MRO.
    """

    # ENFORCE-042 namespace-holder contract: ``FlextSettings`` contributes
    # namespacing only — instance machinery stays plain object semantics so the
    # settings singleton/validation machinery cannot leak into instantiated
    # facade composites (e.g. the ``u`` logging facade).
    def __new__(cls, *args: object, **kwargs: object) -> Self:
        return object.__new__(cls)

    def __init__(self, *args: object, **kwargs: object) -> None:
        _ = self, args, kwargs

    def __setattr__(self, name: str, value: object) -> None:
        object.__setattr__(self, name, value)

    __eq__ = object.__eq__

    __hash__ = object.__hash__


__all__: list[str] = ["FlextLdifModelsSettings"]
