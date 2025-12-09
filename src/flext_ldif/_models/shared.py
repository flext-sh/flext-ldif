"""Shared base classes for flext-ldif models.

This module provides base classes that are shared between different model modules
to avoid circular imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core._models.base import FlextModelsBase
from pydantic import ConfigDict


class FlextLdifModelsBase(FlextModelsBase.ArbitraryTypesModel):
    """Base class for all FLEXT-LDIF models (events, configs, processing results).

    Extends FlextModelsBase.ArbitraryTypesModel to provide a consistent base
    for LDIF-specific models, ensuring:
    - Proper Pydantic v2 configuration inheritance
    - Consistency with flext-core architecture
    - Type safety without using BaseModel directly
    - Support for advanced Pydantic v2 features

    Usage:
        class MyLdifModel(FlextLdifModelsBase):
            '''My LDIF domain model.'''
            field1: str
            field2: int = Field(default=0)

    """

    model_config = ConfigDict(
        strict=True,
        validate_assignment=True,
        extra="forbid",
        validate_default=True,
        use_enum_values=True,
        str_strip_whitespace=True,
    )


__all__ = ["FlextLdifModelsBase"]
