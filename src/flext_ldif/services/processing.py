"""FLEXT-LDIF Processing Service - Batch and parallel entry processing.

This service handles batch and parallel processing of LDIF entries using
ThreadPoolExecutor for concurrent operations.

Extracted from FlextLdif facade to follow Single Responsibility Principle.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from flext_core import FlextResult, FlextService

from flext_ldif.constants import FlextLdifConstants
from flext_ldif.models import FlextLdifModels
from flext_ldif.typings import FlextLdifTypes


class FlextLdifProcessing(FlextService[FlextLdifTypes.Models.ServiceResponseTypes]):
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

    def execute(
        self,
        **_kwargs: object,
    ) -> FlextResult[FlextLdifTypes.Models.ServiceResponseTypes]:
        """Execute method required by FlextService abstract base class.

        This service provides specific methods (process)
        rather than a generic execute operation.

        Args:
            **_kwargs: Ignored parameters for FlextService protocol compatibility

        Returns:
            FlextResult with not implemented error

        """
        return FlextResult.fail(
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
    ) -> FlextResult[list[dict[str, object]]]:
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
        try:
            # Get processor function
            processor_result = self._get_processor_function(processor_name)
            if processor_result.is_failure:
                return FlextResult[list[dict[str, object]]].fail(
                    processor_result.error or "Processor function not found",
                )
            processor_func = processor_result.unwrap()

            # Execute processing based on mode
            if parallel:
                return self._execute_parallel_processing(
                    entries,
                    processor_func,
                    max_workers,
                )
            return self._execute_batch_processing(entries, processor_func, batch_size)

        except (ValueError, TypeError, AttributeError) as e:
            mode = "Parallel" if parallel else "Batch"
            return FlextResult[list[dict[str, object]]].fail(
                f"{mode} processing failed: {e}",
            )

    def _get_processor_function(
        self,
        processor_name: str,
    ) -> FlextResult[Callable[[FlextLdifModels.Entry], dict[str, object]]]:
        """Get processor function by name.

        Args:
            processor_name: Name of processor ("transform" or "validate")

        Returns:
            FlextResult with processor function or error

        """
        if processor_name == FlextLdifConstants.ProcessorTypes.TRANSFORM:
            return FlextResult.ok(self._create_transform_processor())
        if processor_name == FlextLdifConstants.ProcessorTypes.VALIDATE:
            return FlextResult.ok(self._create_validate_processor())
        supported = "'transform', 'validate'"
        return FlextResult.fail(
            f"Unknown processor: '{processor_name}'. Supported: {supported}",
        )

    @staticmethod
    def _execute_parallel_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]],
        max_workers: int,
    ) -> FlextResult[list[dict[str, object]]]:
        """Execute parallel processing using ThreadPoolExecutor.

        Args:
            entries: List of entries to process
            processor_func: Processor function to apply
            max_workers: Maximum number of worker threads

        Returns:
            FlextResult with list of processed results

        """
        try:
            max_workers_actual = min(len(entries), max_workers)
            with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                future_to_entry = {
                    executor.submit(processor_func, entry): entry for entry in entries
                }
                results = [future.result() for future in as_completed(future_to_entry)]
            return FlextResult[list[dict[str, object]]].ok(results)
        except (ValueError, TypeError, AttributeError) as e:
            return FlextResult[list[dict[str, object]]].fail(
                f"Parallel processing failed: {e}",
            )

    @staticmethod
    def _execute_batch_processing(
        entries: list[FlextLdifModels.Entry],
        processor_func: Callable[[FlextLdifModels.Entry], dict[str, object]],
        batch_size: int,
    ) -> FlextResult[list[dict[str, object]]]:
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
        return FlextResult[list[dict[str, object]]].ok(results)

    @staticmethod
    def _create_transform_processor() -> Callable[
        [FlextLdifModels.Entry],
        dict[str, object],
    ]:
        """Create transform processor function.

        Returns:
            Processor function that transforms Entry to dict

        """

        def _transform_func(entry: FlextLdifModels.Entry) -> dict[str, object]:
            # Build dict directly from Entry fields without model_dump()
            result: dict[str, object] = {
                "dn": entry.dn.value,
                "attributes": entry.attributes.attributes,
            }
            if entry.metadata:
                result["metadata"] = entry.metadata
            if entry.metadata.processing_stats:
                result["statistics"] = entry.metadata.processing_stats
            return result

        return _transform_func

    @staticmethod
    def _create_validate_processor() -> Callable[
        [FlextLdifModels.Entry],
        dict[str, object],
    ]:
        """Create validate processor function.

        Returns:
            Processor function that validates Entry

        """

        def _validate_func(entry: FlextLdifModels.Entry) -> dict[str, object]:
            # Basic validation: entry has DN and attributes - fast fail if None
            # dn and attributes are required, cannot be None
            dn_value = entry.dn.value
            attrs_dict = entry.attributes.attributes
            return {
                "dn": dn_value,
                "valid": bool(dn_value and attrs_dict),
                "attribute_count": len(attrs_dict),
            }

        return _validate_func


__all__ = ["FlextLdifProcessing"]
