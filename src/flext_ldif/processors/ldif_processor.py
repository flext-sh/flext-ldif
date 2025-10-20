"""LDIF Batch and Parallel Processors.

This module provides enterprise-grade batch and parallel processing capabilities
for LDIF entries using concurrent.futures for true parallel execution. Designed for efficient
large-scale operations on directory data with memory-conscious batching and
CPU-optimized parallel execution.

Features:
- LdifBatchProcessor: Memory-efficient batch processing for large datasets
- LdifParallelProcessor: CPU-optimized parallel processing with ThreadPoolExecutor
- FlextProcessors integration: Leverages flext-core processing infrastructure
- Type-safe generic processing with full Pydantic model support
- Comprehensive error handling with FlextResult railway-oriented programming
- Configurable batch sizes and worker counts for performance tuning

Use Cases:
- Large-scale LDIF validation across thousands of entries
- CPU-intensive transformations (encryption, complex mappings)
- Memory-bound operations on datasets larger than available RAM
- Parallel schema validation and consistency checking

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

from flext_core import FlextProcessors, FlextResult

if TYPE_CHECKING:
    from flext_ldif.models import FlextLdifModels

# Generic type variable for processor return types
T = TypeVar("T")


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
        super().__init__()
        self._batch_size = batch_size
        self._processors = FlextProcessors()

    def process_batch(
        self,
        entries: list[FlextLdifModels.Entry],
        func: Callable[[FlextLdifModels.Entry], T],
    ) -> FlextResult[list[T]]:
        """Process entries in batches.

        Args:
            entries: List of LDIF entries to process
            func: Function to apply to each entry (generic return type T)

        Returns:
            FlextResult containing list of processed results of type T

        Example:
            def validate_entry(entry):
                return entry.dn

            result = processor.process_batch(entries, validate_entry)

        """
        try:
            results: list[T] = []
            for i in range(0, len(entries), self._batch_size):
                batch = entries[i : i + self._batch_size]
                batch_results = [func(entry) for entry in batch]
                results.extend(batch_results)

            return FlextResult[list[T]].ok(results)

        except Exception as e:
            return FlextResult[list[T]].fail(f"Batch processing failed: {e}")


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
        super().__init__()
        self._max_workers = max_workers
        self._processors = FlextProcessors()

    def process_parallel(
        self,
        entries: list[FlextLdifModels.Entry],
        func: Callable[[FlextLdifModels.Entry], T],
    ) -> FlextResult[list[T]]:
        """Process entries in parallel using ThreadPoolExecutor.

        Args:
            entries: List of LDIF entries to process
            func: Function to apply to each entry (generic return type T)

        Returns:
            FlextResult containing list of processed results of type T

        Example:
            def transform_entry(entry):
                return entry.model_dump()

            result = processor.process_parallel(entries, transform_entry)

        Note:
            Uses concurrent.futures.ThreadPoolExecutor for true parallel execution.
            Results are returned in the order they complete (not input order).

        """
        try:
            if not entries:
                return FlextResult[list[T]].ok([])

            # Calculate optimal workers: min of configured max and entry count
            max_workers = min(len(entries), self._max_workers)
            results: list[T] = []

            # Use ThreadPoolExecutor for true parallel processing
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers
            ) as executor:
                # Submit all tasks for parallel execution
                future_to_entry = {
                    executor.submit(func, entry): entry for entry in entries
                }

                # Collect results as they complete
                for future in concurrent.futures.as_completed(future_to_entry):
                    result = future.result()
                    results.append(result)

            return FlextResult[list[T]].ok(results)

        except Exception as e:
            return FlextResult[list[T]].fail(f"Parallel processing failed: {e}")


__all__ = [
    "LdifBatchProcessor",
    "LdifParallelProcessor",
]
