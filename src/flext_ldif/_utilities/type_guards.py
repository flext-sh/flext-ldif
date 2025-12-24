"""LDIF Type Guards - Type narrowing for Model instances.

Type guard functions for safe type narrowing without circular imports.
Uses duck typing to identify Model instances.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TypeGuard

from flext import FlextUtilities


class FlextLdifUtilitiesTypeGuards(FlextUtilities):
    """Type guards for LDIF Model identification.

    Provides safe type narrowing for SchemaAttribute and SchemaObjectClass
    Models without requiring direct imports (avoiding circular dependencies).

    All methods use duck typing (hasattr checks) to identify Model instances.
    """

    @staticmethod
    def is_schema_attribute(obj: object) -> TypeGuard[object]:
        """Check if object is a SchemaAttribute Model instance.

        Uses duck typing to avoid circular imports:
        - Must have: oid, name, syntax attributes (Schema signatures)
        - For runtime type narrowing in isinstance-like checks

        Args:
            obj: Object to check

        Returns:
            True if object has SchemaAttribute structure

        """
        return hasattr(obj, "oid") and hasattr(obj, "name") and hasattr(obj, "syntax")

    @staticmethod
    def is_schema_object_class(obj: object) -> TypeGuard[object]:
        """Check if object is a SchemaObjectClass Model instance.

        Uses duck typing to avoid circular imports:
        - Must have: oid, name, sup attributes (ObjectClass signatures)
        - For runtime type narrowing in isinstance-like checks

        Args:
            obj: Object to check

        Returns:
            True if object has SchemaObjectClass structure

        """
        return hasattr(obj, "oid") and hasattr(obj, "name") and hasattr(obj, "sup")
