"""Processing Service - Batch and Parallel Entry Processing."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, MutableSequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import override

from flext_ldif import FlextLdifServiceBase, m, r, u


class FlextLdifProcessing(
    FlextLdifServiceBase[MutableSequence[m.Ldif.ProcessingResult]],
):
    """Service for batch and parallel entry processing."""

    @staticmethod
    def _create_entry_processor() -> Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult]:
        def _entry_processor(entry: m.Ldif.Entry) -> m.Ldif.ProcessingResult:
            if entry.dn is None:
                msg = "Entry DN cannot be None"
                raise ValueError(msg)
            dn_str = (
                entry.dn.value
                if getattr(entry.dn, "value", None) is not None
                else str(entry.dn)
            )
            if entry.attributes is None:
                msg = "Entry attributes cannot be None"
                raise ValueError(msg)
            attrs_dict = entry.attributes.attributes
            return m.Ldif.ProcessingResult(dn=dn_str, attributes=attrs_dict)

        return _entry_processor

    @staticmethod
    def _create_transform_processor() -> Callable[
        [m.Ldif.Entry],
        m.Ldif.ProcessingResult,
    ]:
        """Create transform processor function."""
        return FlextLdifProcessing._create_entry_processor()

    @staticmethod
    def _create_validate_processor() -> Callable[
        [m.Ldif.Entry],
        m.Ldif.ProcessingResult,
    ]:
        """Create validate processor function."""
        return FlextLdifProcessing._create_entry_processor()

    @staticmethod
    def _execute_batch_processing(
        entries: MutableSequence[m.Ldif.Entry],
        processor_func: Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult],
        _batch_size: int,
    ) -> r[MutableSequence[m.Ldif.ProcessingResult]]:
        """Execute batch processing sequentially."""
        return u.process(entries, processor_func, on_error="collect").fold(
            on_failure=lambda e: r[MutableSequence[m.Ldif.ProcessingResult]].fail(
                e or "Batch processing failed",
            ),
            on_success=lambda v: r[MutableSequence[m.Ldif.ProcessingResult]].ok([*v]),
        )

    @staticmethod
    def _execute_parallel_processing(
        entries: MutableSequence[m.Ldif.Entry],
        processor_func: Callable[[m.Ldif.Entry], m.Ldif.ProcessingResult],
        max_workers: int,
    ) -> r[MutableSequence[m.Ldif.ProcessingResult]]:
        """Execute parallel processing using ThreadPoolExecutor."""
        max_workers_actual = min(len(entries), max_workers)
        with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
            future_to_entry = {
                executor.submit(processor_func, entry): entry for entry in entries
            }
            results = [future.result() for future in as_completed(future_to_entry)]
        return r[MutableSequence[m.Ldif.ProcessingResult]].ok(results)

    @override
    def execute(self) -> r[MutableSequence[m.Ldif.ProcessingResult]]:
        """Execute method required by s abstract base class."""
        return r[MutableSequence[m.Ldif.ProcessingResult]].fail(
            "FlextLdifProcessing does not support generic execute(). Use specific methods instead.",
        )

    def process_entries(
        self,
        processor_name: str,
        entries: MutableSequence[m.Ldif.Entry],
        *,
        parallel: bool = False,
        batch_size: int = 100,
        max_workers: int = 4,
    ) -> r[MutableSequence[m.Ldif.ProcessingResult]]:
        """Unified processing method supporting batch and parallel modes."""
        processor_result = self._get_processor_function(processor_name)
        if processor_result.is_failure:
            return r[MutableSequence[m.Ldif.ProcessingResult]].fail(
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
        processor_map: MutableMapping[
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


__all__ = ["FlextLdifProcessing"]
