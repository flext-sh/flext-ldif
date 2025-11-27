"""Entry Manipulation Services - Compatibility Alias.

This module provides compatibility alias for EntryManipulationServices.
All functionality has been consolidated into FlextLdifEntries.

For new code, use FlextLdifEntries directly:
    from flext_ldif.services.entries import FlextLdifEntries

For backward compatibility, EntryManipulationServices is available as an alias.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.services.entries import FlextLdifEntries

# Compatibility alias - all methods are available via FlextLdifEntries
EntryManipulationServices = FlextLdifEntries

__all__ = ["EntryManipulationServices"]
