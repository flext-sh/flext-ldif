"""Processing Service - Batch and Parallel Entry Processing."""

from __future__ import annotations

from collections.abc import MutableSequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import override

from flext_ldif import m, r, s, u


class FlextLdifProcessing(
    s[MutableSequence[m.Ldif.ProcessingResult]],
):
    """Service for batch and parallel entry processing."""

    _SUPPORTED_PROCESSORS: frozenset[str] = frozenset({"transform", "validate"})

    @staticmethod
    def _process_entry(entry: m.Ldif.Entry) -> m.Ldif.ProcessingResult:
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
        return m.Ldif.ProcessingResult.model_validate({
            "dn": dn_str,
            "attributes": attrs_dict,
        })

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
        if processor_name not in self._SUPPORTED_PROCESSORS:
            supported = "'transform', 'validate'"
            return r[MutableSequence[m.Ldif.ProcessingResult]].fail(
                f"Unknown processor: '{processor_name}'. Supported: {supported}",
            )
        if parallel:
            max_workers_actual = min(len(entries), max_workers)
            with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                futures = [
                    executor.submit(self._process_entry, entry) for entry in entries
                ]
                results = [future.result() for future in as_completed(futures)]
            return r[MutableSequence[m.Ldif.ProcessingResult]].ok(results)
        _ = batch_size
        return (
            r[MutableSequence[m.Ldif.ProcessingResult]]
            .from_result(
                u.process(entries, self._process_entry, on_error="collect"),
            )
            .map_error(
                lambda error: error or "Batch processing failed",
            )
            .map(list)
        )


__all__: list[str] = ["FlextLdifProcessing"]
