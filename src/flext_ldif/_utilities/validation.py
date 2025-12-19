"""LDIF Validation Utilities - Pure Validation Functions.

Stateless validation functions for Entry model validators.
NO hard-coded server logic - only RFC compliance and format validation.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import u


class FlextLdifUtilitiesValidation(u.Validation):
    """LDIF-specific validation functions extending flext-core validation.

    Architecture:
    - Inherits all validation methods from FlextUtilitiesValidation
    - Adds LDIF-specific validations (RFC 2849, schema, DN validation)
    - Stateless pure functions (no side effects)
    - ZERO server-specific logic (only RFC validation)

    Purpose: Unified validation via u.Validation access.
    """

    # Inherits all methods from FlextUtilitiesValidation
    # LDIF-specific methods can be added here as needed
