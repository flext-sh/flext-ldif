"""Exceptions facade for flext_ldif.

Re-exports the canonical FLEXT exception namespace so that ``from flext_ldif import e``
works consistently with other FLEXT packages.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core.exceptions import FlextExceptions as FlextLdifExceptions

e = FlextLdifExceptions

__all__: list[str] = ["FlextLdifExceptions", "e"]
