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

from flext_core import FlextResult

from flext_ldif._models.processing import ProcessingResult
from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels


class FlextLdifProcessing(
    FlextLdifServiceBase[list[ProcessingResult]],
):
    """Service for batch and parallel entry processing.

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
    ) -> FlextResult[list[ProcessingResult]]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (process)
        rather than a generic execute operation.

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult[list[ProcessingResult]].fail(
            "FlextLdifProcessing does not support generic execute(). Use specific methods instead.",
        )

    def process(
        self,
        processor_name: str,
        entries: list[FlextLdifModels.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> FlextResult[list[ProcessingResult]]:
        """Unified processing method supporting batch and parallel modes.

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
            return FlextResult[list[ProcessingResult]].fail(
                processor_result.error or "Processor function not found",
            )
        processor_func = processor_result.unwrap()

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
    ) -> FlextResult[Callable[[FlextLdifModels.Entry], ProcessingResult]]:
        """Get processor function by name.

        Args:
            processor_name: Name of processor ("transform" or "validate")

        Returns:
            FlextResult with processor function or error

        """
        processor_map: dict[
            str, Callable[[], Callable[[FlextLdifModels.Entry], ProcessingResult]]
        ] = {
            FlextLdifConstants.ProcessorTypes.TRANSFORM: self._create_transform_processor,
            FlextLdifConstants.ProcessorTypes.VALIDATE: self._create_validate_processor,
        }
        if processor_name in processor_map:
            return FlextResult[Callable[[FlextLdifModels.Entry], ProcessingResult]].ok(
                processor_map[processor_name]()
            )
        supported = "'transform', 'validate'"
        return FlextResult[Callable[[FlextLdifModels.Entry], ProcessingResult]].fail(
            f"Unknown processor: '{processor_name}'. Supported: {supported}",
        )

    @staticmethod
    def _execute_parallel_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], ProcessingResult],
        max_workers: int,
    ) -> FlextResult[list[ProcessingResult]]:
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
        return FlextResult[list[ProcessingResult]].ok(results)

    @staticmethod
    def _execute_batch_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], ProcessingResult],
        batch_size: int,
    ) -> FlextResult[list[ProcessingResult]]:
        """Execute batch processing sequentially.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            batch_size: Number of entries per batch

        Returns:
            FlextResult with list of processed results

        """
        results = []
        for i in range(0, len(entries), batch_size):
            batch = entries[i : i + batch_size]
            batch_results = [processor_func(entry) for entry in batch]
            results.extend(batch_results)
        return FlextResult[list[ProcessingResult]].ok(results)

    @staticmethod
    def _create_transform_processor() -> Callable[
        [FlextLdifModels.Entry],
        ProcessingResult,
    ]:
        """Create transform processor function.

        Returns:
            Processor function that transforms Entry to ProcessingResult

        """

        def _transform_func(entry: FlextLdifModels.Entry) -> ProcessingResult:
            # Transform Entry to ProcessingResult with all metadata preserved
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            attrs_dict = dict(entry.attributes) if not isinstance(entry.attributes, dict) else entry.attributes
            return ProcessingResult(
                dn=dn_str,
                attributes=attrs_dict,
            )

        return _transform_func

    @staticmethod
    def _create_validate_processor() -> Callable[
        [FlextLdifModels.Entry],
        ProcessingResult,
    ]:
        """Create validate processor function.

        Returns:
            Processor function that validates Entry and returns ProcessingResult

        """

        def _validate_func(entry: FlextLdifModels.Entry) -> ProcessingResult:
            # Basic validation: entry has DN and attributes - required fields must be present
            # Return complete entry data for validation results
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            attrs_dict = dict(entry.attributes) if not isinstance(entry.attributes, dict) else entry.attributes
            return ProcessingResult(
                dn=dn_str,
                attributes=attrs_dict,
            )

        return _validate_func


__all__ = ["FlextLdifProcessing"]
