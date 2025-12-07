"""Internal module for FlextLdifModels nested classes.

This module contains extracted nested classes from FlextLdifModels to improve
maintainability while preserving 100% API compatibility.

All classes are re-exported through FlextLdifModels in models.py - users should
NEVER import from this module directly.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# Import all model modules
# All type references use direct imports or protocols - no forward references
# No model_rebuild() needed - models work without rebuilding
from flext_ldif._models import config, domain  # noqa: F401

__all__: list[str] = []
