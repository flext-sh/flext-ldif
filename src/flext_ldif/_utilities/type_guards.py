"""LDIF Type Guards - Type narrowing for Model instances.

Type guard functions for safe type narrowing without circular imports.
Uses duck typing to identify Model instances.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence as ABCSequence
from typing import TypeGuard

from flext_core.typings import t
from flext_core.utilities import FlextUtilities


class FlextLdifUtilitiesTypeGuards(FlextUtilities):
    """Type guards for LDIF Model identification.

    Provides safe type narrowing for SchemaAttribute and SchemaObjectClass
    Models without requiring direct imports (avoiding circular dependencies).

    All methods use duck typing (hasattr checks) to identify Model instances.
    """

    @staticmethod
    def is_entry_sequence(
        obj: t.GeneralValueType,
    ) -> TypeGuard[ABCSequence[t.GeneralValueType]]:
        """Check if object is a Sequence of Entry instances.

        Uses duck typing to identify Entry sequences:
        - Must be a Sequence (list, tuple, etc.)
        - Must not be string, bytes, or dict
        - All items must have dn and attributes (Entry structure)

        Args:
            obj: Object to check

        Returns:
            True if object is a Sequence of Entry-like objects

        """
        if not isinstance(obj, ABCSequence) or isinstance(obj, (str, bytes, dict)):
            return False
        # Check if all items are Entry-like (have dn and attributes)
        return all(hasattr(item, "dn") and hasattr(item, "attributes") for item in obj)
