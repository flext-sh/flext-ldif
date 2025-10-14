"""Batch and Parallel Processors for FLEXT-LDIF.

This package provides batch and parallel processing capabilities for LDIF entries
using FlextCore.Processors infrastructure.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_ldif.processors.ldif_processor import (
    LdifBatchProcessor,
    LdifParallelProcessor,
)

__all__ = [
    "LdifBatchProcessor",
    "LdifParallelProcessor",
]
