"""FlextLdif DI Container using flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any

# 🚨 ARCHITECTURAL COMPLIANCE: Using flext-core root namespace imports
from flext_core import (
    FlextAggregateRoot,
    FlextCoreSettings,
    FlextEntity,
    FlextResult,
    FlextValidator,
    FlextValueObject,
)


def flext_ldif_get_service_result() -> type[FlextResult[Any]]:
    """Get FlextResult class from flext-core."""
    return FlextResult


def flext_ldif_get_domain_entity() -> type[FlextEntity]:
    """Get FlextEntity class from flext-core."""
    return FlextEntity


def flext_ldif_get_domain_value_object() -> type[FlextValueObject]:
    """Get FlextValueObject class from flext-core."""
    return FlextValueObject


def flext_ldif_get_specification_pattern() -> type[FlextValidator[Any]]:
    """Get FlextValidator class from flext-core."""
    return FlextValidator


def flext_ldif_get_base_config() -> type[FlextCoreSettings]:
    """Get FlextCoreSettings class from flext-core."""
    return FlextCoreSettings


def flext_ldif_get_domain_aggregate_root() -> type[FlextAggregateRoot]:
    """Get FlextAggregateRoot class from flext-core."""
    return FlextAggregateRoot


__all__ = [
    "flext_ldif_get_base_config",
    "flext_ldif_get_domain_aggregate_root",
    "flext_ldif_get_domain_entity",
    "flext_ldif_get_domain_value_object",
    "flext_ldif_get_service_result",
    "flext_ldif_get_specification_pattern",
]
