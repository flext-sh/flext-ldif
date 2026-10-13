"""Base classes for flext-ldif models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_ldif/_models/base
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif._models._base_parts import FlextLdifModelsBasesParts, FlextLdifShared


class FlextLdifModelsBases(FlextLdifModelsBasesParts):
    """Facade namespace for all FLEXT-LDIF base model classes."""


__all__: list[str] = ["FlextLdifModelsBases", "FlextLdifShared"]
