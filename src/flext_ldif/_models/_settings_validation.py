"""LDIF settings mix-in: validation.

from flext_ldif import m
from flext_ldif import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Annotated

from flext_core import FlextUtilities as u, m


class FlextLdifModelsSettingsValidation:
    """LDIF settings mix-in: validation."""

    class ServerValidationRules(m.Value):
        """Server-specific validation rules for LDIF entries."""

        requires_binary_option: Annotated[
            bool,
            u.Field(
                description="Whether server requires ;binary option for non-ASCII values"
            ),
        ] = False
        requires_naming_attr: Annotated[
            bool,
            u.Field(description="Whether server requires naming attribute in entry"),
        ] = False
        requires_objectclass: Annotated[
            bool, u.Field(description="Whether server requires objectClass attribute")
        ] = True
