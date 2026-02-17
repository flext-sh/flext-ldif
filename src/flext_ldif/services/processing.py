"""Processing Service - Batch and Parallel Entry Processing."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import override

from flext_core import r

from flext_ldif.base import FlextLdifServiceBase
from flext_ldif.models import m
from flext_ldif.utilities import u


class FlextLdifProcessing(
    FlextLdifServiceBase[list[m.Ldif.ProcessingResult]],
):
    """Service for batch and parallel entry processing."""

    @override
    def execute(
        self,
    ) -> r[list[m.Ldif.ProcessingResult]]:
        """Execute method required by FlextService abstract base class."""
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
        """Unified processing method supporting batch and parallel modes."""
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
        """Get processor function by name."""
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
        """Execute parallel processing using ThreadPoolExecutor."""
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
        """Execute batch processing sequentially."""
        batch_result = u.Collection.process(
            entries,
            processor_func,
            on_error="collect",
        )
        if batch_result.is_failure:
            return r[list[m.Ldif.ProcessingResult]].fail(
                batch_result.error or "Batch processing failed",
            )

        batch_value = batch_result.value
        if isinstance(batch_value, list):
            results: list[m.Ldif.ProcessingResult] = [
                item
                for item in batch_value
                if isinstance(item, m.Ldif.ProcessingResult)
            ]
            return r[list[m.Ldif.ProcessingResult]].ok(results)

        return r[list[m.Ldif.ProcessingResult]].ok([])

    @staticmethod
    def _create_transform_processor() -> Callable[
        [m.Ldif.Entry],
        m.Ldif.ProcessingResult,
    ]:
        """Create transform processor function."""

        def _transform_func(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.ProcessingResult:

            if entry.dn is None:
                msg = "Entry DN cannot be None"
                raise ValueError(msg)
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            if entry.attributes is None:
                msg = "Entry attributes cannot be None"
                raise ValueError(msg)

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
        """Create validate processor function."""

        def _validate_func(
            entry: m.Ldif.Entry,
        ) -> m.Ldif.ProcessingResult:

            if entry.dn is None:
                msg = "Entry DN cannot be None"
                raise ValueError(msg)
            dn_str = entry.dn.value if hasattr(entry.dn, "value") else str(entry.dn)
            if entry.attributes is None:
                msg = "Entry attributes cannot be None"
                raise ValueError(msg)

            attrs_dict = entry.attributes.attributes
            return m.Ldif.ProcessingResult(
                dn=dn_str,
                attributes=attrs_dict,
            )

        return _validate_func


__all__ = ["FlextLdifProcessing"]
