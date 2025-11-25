"""LDIF Validation Utilities - Pure Validation Functions.

Stateless validation functions for Entry model validators.
NO hard-coded server logic - only RFC compliance and format validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# No imports needed - all methods were removed


class FlextLdifUtilitiesValidation:
    """Pure validation functions for Entry model validators.

    Architecture:
    - Stateless pure functions (no side effects)
    - Return (bool, violations) tuples
    - ZERO server-specific logic (only RFC validation)
    - Used by Entry.validate_server_specific_rules()

    Purpose: Enable dynamic validation via DI-injected rules.
    """

    # All methods were unused and have been removed
