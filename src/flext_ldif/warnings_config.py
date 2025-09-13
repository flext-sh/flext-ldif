"""FLEXT LDIF - Warning configuration and suppression.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import warnings

from flext_core import FlextTypes


def configure_warnings() -> None:
    """Configure warning filters for clean CLI output."""
    # Suppress Pydantic V2 warnings for clean CLI
    warnings.filterwarnings(
        "ignore", category=UserWarning, module="pydantic._internal._config"
    )
    warnings.filterwarnings(
        "ignore", category=DeprecationWarning, module="pydantic._internal._config"
    )
    warnings.filterwarnings(
        "ignore",
        message=".*validate_all.*renamed.*validate_default.*",
        category=UserWarning,
    )
    warnings.filterwarnings(
        "ignore",
        message=".*class-based.*config.*deprecated.*",
        category=DeprecationWarning,
    )


__all__: FlextTypes.Core.StringList = [
    "configure_warnings",
]
