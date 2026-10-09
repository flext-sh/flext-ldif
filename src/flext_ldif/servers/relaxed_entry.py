"""Relaxed entry server for lenient LDIF processing.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_ldif.servers._rfc.entry import FlextLdifServersRfcEntry
from flext_ldif.servers.relaxed_entry_parse import (
    FlextLdifServersRelaxedEntryParseMixin,
)
from flext_ldif.servers.relaxed_entry_write import (
    FlextLdifServersRelaxedEntryWriteMixin,
)


class FlextLdifServersRelaxedEntry(
    FlextLdifServersRelaxedEntryWriteMixin,
    FlextLdifServersRelaxedEntryParseMixin,
    FlextLdifServersRfcEntry,
):
    """Relaxed entry server for lenient LDIF processing.

    Behavior is composed from focused mixins: the lenient parse side
    (``relaxed_entry_parse``) and the write side plus predicate hooks
    (``relaxed_entry_write``).
    """


__all__: list[str] = ["FlextLdifServersRelaxedEntry"]
