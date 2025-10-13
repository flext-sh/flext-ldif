"""LDIF Batch and Parallel Processors.

This module provides batch and parallel processing capabilities for LDIF entries
using FlextCore.Processors infrastructure for efficient large-scale operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from flext_core import FlextCore

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels


class LdifBatchProcessor:
    """Batch processor for LDIF entries.

    Processes LDIF entries in batches for memory-efficient operations
    on large LDIF files.

    Attributes:
        batch_size: Number of entries to process per batch

    Example:
        processor = LdifBatchProcessor(batch_size=100)
        result = processor.process_batch(entries, validate_entry)

    """

    def __init__(self, batch_size: int = 100) -> None:
        """Initialize batch processor.

        Args:
            batch_size: Number of entries per batch (default: 100)

        """
        self._batch_size = batch_size
        self._processors = FlextCore.Processors()

    def process_batch(
        self,
        entries: list[FlextLdifModels.Entry],
        func: Callable[[FlextLdifModels.Entry], Any],
    ) -> FlextCore.Result[list[Any]]:
        """Process entries in batches.

        Args:
            entries: List of LDIF entries to process
            func: Function to apply to each entry

        Returns:
            FlextCore.Result containing list of processed results

        Example:
            def validate_entry(entry):
                return entry.dn

            result = processor.process_batch(entries, validate_entry)

        """
        try:
            results: list[Any] = []
            for i in range(0, len(entries), self._batch_size):
                batch = entries[i : i + self._batch_size]
                batch_results = [func(entry) for entry in batch]
                results.extend(batch_results)

            return FlextCore.Result[list[Any]].ok(results)

        except Exception as e:
            return FlextCore.Result[list[Any]].fail(
                f"Batch processing failed: {e}"
            )


class LdifParallelProcessor:
    """Parallel processor for LDIF entries.

    Processes LDIF entries in parallel for CPU-intensive operations
    on large LDIF files.

    Attributes:
        max_workers: Maximum number of parallel workers

    Example:
        processor = LdifParallelProcessor(max_workers=4)
        result = processor.process_parallel(entries, transform_entry)

    """

    def __init__(self, max_workers: int = 4) -> None:
        """Initialize parallel processor.

        Args:
            max_workers: Maximum number of parallel workers (default: 4)

        """
        self._max_workers = max_workers
        self._processors = FlextCore.Processors()

    def process_parallel(
        self,
        entries: list[FlextLdifModels.Entry],
        func: Callable[[FlextLdifModels.Entry], Any],
    ) -> FlextCore.Result[list[Any]]:
        """Process entries in parallel.

        Args:
            entries: List of LDIF entries to process
            func: Function to apply to each entry

        Returns:
            FlextCore.Result containing list of processed results

        Example:
            def transform_entry(entry):
                return entry.model_dump()

            result = processor.process_parallel(entries, transform_entry)

        """
        try:
            # Note: FlextCore.Processors provides parallel processing utilities
            # For now, use sequential processing as FlextCore.Processors
            # interface is not fully defined
            results = [func(entry) for entry in entries]
            return FlextCore.Result[list[Any]].ok(results)

        except Exception as e:
            return FlextCore.Result[list[Any]].fail(
                f"Parallel processing failed: {e}"
            )


__all__ = [
    "LdifBatchProcessor",
    "LdifParallelProcessor",
]
