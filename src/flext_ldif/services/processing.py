"""Processing Service - Batch and Parallel Entry Processing.

Provides batch (sequential) and parallel (concurrent) processing of LDIF entries
using ThreadPoolExecutor for concurrent operations with configurable worker pools.

Scope: Entry batch processing, parallel processing with ThreadPoolExecutor,
transform and validate operations, custom processor function support.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import override

from flext_core import r

# Use models facade instead of direct _models imports (architecture layering)
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifProcessing(
    FlextLdifServiceBase[list[m.Ldif.ProcessingResult]],
):
    """Service for batch and parallel entry processing.

    Business Rule: Processing service provides batch (sequential) and parallel
    (concurrent) processing modes for LDIF entries. Batch mode processes entries
    sequentially in configurable batch sizes. Parallel mode uses ThreadPoolExecutor
    for concurrent processing with configurable worker pools. Both modes support
    transform and validate operations via processor function names.

    Implication: Flexible processing enables efficient handling of large entry sets.
    Batch mode provides predictable memory usage, while parallel mode maximizes CPU
    utilization for I/O-bound operations. ThreadPoolExecutor ensures thread-safe
    concurrent processing with proper resource management.

    Provides methods for:
    - Processing entries in batches (sequential)
    - Processing entries in parallel (concurrent)
    - Transform and validate operations
    - Custom processor function support

    Example:
        processing_service = FlextLdifProcessing()

        # Batch processing (sequential)
        result = processing_service.process("transform", entries, batch_size=100)

        # Parallel processing (concurrent)
        result = processing_service.process(
            "validate",
            entries,
            parallel=True,
            max_workers=8
        )

    """

    @override
    def execute(
        self,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Execute method required by FlextService abstract base class.

        Business Rule: Processing service does not support generic execute() operation.
        All processing must use the process() method with explicit processor name and
        configuration. This ensures type safety and clear operation semantics.

        Implication: Callers must use process() method with processor_name parameter.
        Generic execute() returns fail result to prevent incorrect usage.

        Returns:
            FlextResult with not implemented error

        """
        return r[list[m.Ldif.ProcessingResult]].fail(
            "FlextLdifProcessing does not support generic execute(). Use specific methods instead.",
        )

    def process(
        self,
        processor_name: str,
        entries: list[m.Ldif.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Unified processing method supporting batch and parallel modes.

        Business Rule: Processing method routes to batch or parallel execution based on
        parallel flag. Batch mode processes entries sequentially in configurable batch
        sizes for predictable memory usage. Parallel mode uses ThreadPoolExecutor with
        configurable worker pools for concurrent processing. Processor function is
        resolved by name from registry.

        Implication: Flexible processing enables efficient handling of large entry sets.
        Batch mode provides predictable memory usage, while parallel mode maximizes CPU
        utilization for I/O-bound operations. ThreadPoolExecutor ensures thread-safe
        concurrent processing with proper resource management.

        Consolidates process_batch() and process_parallel() into a single flexible
        method with an optional parallel execution mode.

        Args:
            processor_name: Name of processor function ("transform", "validate", etc.)
            entries: List of entries to process
            parallel: If True, use parallel processing; if False, use batch. Default: False
            batch_size: Number of entries per batch (only used when parallel=False). Default: 100
            max_workers: Number of worker threads (only used when parallel=True). Default: 4

        Returns:
            FlextResult containing processed results

        Example:
            # Batch processing (sequential)
            result = processing_service.process("transform", entries)

            # Batch processing with custom batch size
            result = processing_service.process("transform", entries, batch_size=200)

            # Parallel processing
            result = processing_service.process("transform", entries, parallel=True)

            # Parallel processing with custom worker count
            result = processing_service.process("validate", entries, parallel=True, max_workers=8)

        Note:
            Supported processors: "transform" (converts to dict), "validate" (validates entries).
            Uses batch processing for sequential operations.
            Uses ThreadPoolExecutor for parallel processing.

        """
        processor_result = self._get_processor_function(processor_name)
        if processor_result.is_failure:
            return r[list[m.Ldif.ProcessingResult]].fail(
                processor_result.error or "Processor function not found",
            )
        processor_func = processor_result.value

        if parallel:
            return self._execute_parallel_processing(
                entries,
                processor_func,
                max_workers,
            )
        return self._execute_batch_processing(entries, processor_func, batch_size)

    def _get_processor_function(
        self,
        processor_name: str,
    ) -> r[Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult]]:
        """Get processor function by name.

        Args:
            processor_name: Name of processor ("transform" or "validate")

        Returns:
            FlextResult with processor function or error

        """
        processor_map: dict[
            str,
            Callable[[], Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult]],
        ] = {
            "transform": self._create_transform_processor,
            "validate": self._create_validate_processor,
        }
        if processor_name in processor_map:
            return r[Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult]].ok(
                processor_map[processor_name](),
            )
        supported = "'transform', 'validate'"
        return r[Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult]].fail(
            f"Unknown processor: '{processor_name}'. Supported: {supported}",
        )

    @staticmethod
    def _execute_parallel_processing(
        entries: list[m.Ldif.Entry],
        processor_func: Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult],
        max_workers: int,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Execute parallel processing using ThreadPoolExecutor.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            max_workers: Maximum number of worker threads

        Returns:
            FlextResult with list of processed results

        """
        max_workers_actual = min(len(entries), max_workers)
        with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
            future_to_entry = {
                executor.submit(processor_func, entry): entry for entry in entries
            }
            results = [future.result() for future in as_completed(future_to_entry)]
        return r[list[m.Ldif.ProcessingResult]].ok(results)

    @staticmethod
    def _execute_batch_processing(
        entries: list[m.Ldif.Entry],
        processor_func: Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult],
        _batch_size: int,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Execute batch processing sequentially.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            _batch_size: Number of entries per batch (reserved for future chunking, not yet implemented)

        Returns:
            FlextResult with list of processed results

        """
        # Use u.process for batch processing with error handling
        # FlextLdifUtilities may not have process() method with on_error, delegate to core
        batch_result = u.Collection.process(
            entries,
            processor_func,
            on_error="collect",
        )
        if batch_result.is_failure:
            return r[list[m.Ldif.ProcessingResult]].fail(
                batch_result.error or "Batch processing failed",
            )
        # u.process returns list[R] | dict[str, R] depending on input
        # Type narrowing: batch_result.value is list[m.Ldif.ProcessingResult] | dict[str, m.Ldif.ProcessingResult]
        batch_value = batch_result.value
        if isinstance(batch_value, list):
            results: list[m.Ldif.ProcessingResult] = batch_value
            return r[list[m.Ldif.ProcessingResult]].ok(results)
        # If dict, convert to list
        if isinstance(batch_value, dict):
            results = list(batch_value.values())
            return r[list[m.Ldif.ProcessingResult]].ok(results)
        # Fallback: empty list
        return r[list[m.Ldif.ProcessingResult]].ok([])

    @staticmethod
    def _create_transform_processor() -> Callable[
        [m.Ldif.Entry],
        m.Ldif.ProcessingResult,
    ]:
        """Create transform processor function.

        Returns:
            Processor function that transforms Entry to m.Ldif.ProcessingResult

        """

        def _transform_func(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.ProcessingResult:
            # Transform Entry to m.Ldif.ProcessingResult with all metadata preserved
            if entry.dn is None:
                msg = "Entry DN cannot be None"
                raise ValueError(msg)
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            if entry.attributes is None:
                msg = "Entry attributes cannot be None"
                raise ValueError(msg)
            # entry.attributes is Attributes, not dict
            # Use .attributes property to get dict[str, list[str]]
            # Attributes has .attributes property that returns dict[str, list[str]]
            attrs_dict = entry.attributes.attributes
            return m.Ldif.ProcessingResult(
                dn=dn_str,
                attributes=attrs_dict,
            )

        return _transform_func

    @staticmethod
    def _create_validate_processor() -> Callable[
        [m.Ldif.Entry],
        m.Ldif.ProcessingResult,
    ]:
        """Create validate processor function.

        Returns:
            Processor function that validates Entry and returns m.Ldif.ProcessingResult

        """

        def _validate_func(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.ProcessingResult:
            # Basic validation: entry has DN and attributes - required fields must be present
            # Return complete entry data for validation results
            if entry.dn is None:
                msg = "Entry DN cannot be None"
                raise ValueError(msg)
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            if entry.attributes is None:
                msg = "Entry attributes cannot be None"
                raise ValueError(msg)
            # entry.attributes is Attributes, not dict
            # Use .attributes property to get dict[str, list[str]]
            # Attributes has .attributes property that returns dict[str, list[str]]
            attrs_dict = entry.attributes.attributes
            return m.Ldif.ProcessingResult(
                dn=dn_str,
                attributes=attrs_dict,
            )

        return _validate_func


__all__ = ["FlextLdifProcessing"]
