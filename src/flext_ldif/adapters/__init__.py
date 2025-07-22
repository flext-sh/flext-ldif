"""Adapters for FLEXT LDIF - Implements core domain interfaces.

This module provides concrete implementations of flext-core interfaces
using FLEXT LDIF infrastructure.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.adapters.ldif_adapter import FlextLDIFProcessorAdapter

__all__ = [
    "FlextLDIFProcessorAdapter",
]
