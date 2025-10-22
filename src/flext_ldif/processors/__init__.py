"""Batch and Parallel Processors for FLEXT-LDIF.

This package provides batch and parallel processing capabilities for LDIF entries
using FlextProcessors infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.processors.ldif_processor import (
    FlextLdifBatchProcessor,
    FlextLdifParallelProcessor,
)

__all__ = [
    "FlextLdifBatchProcessor",
    "FlextLdifParallelProcessor",
]
