"""Processing Service - Batch and Parallel Entry Processing."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from flext_ldif import m, p, r, s, t, u


class FlextLdifProcessing(s):
    """Service for batch and parallel entry processing."""

    @staticmethod
    def _process_entry(entry: p.Ldif.Entry) -> p.Ldif.ProcessingResult:
        if entry.dn is None:
            msg = "Entry DN cannot be None"
            raise ValueError(msg)
        dn_str = str(entry.dn)
        if entry.attributes is None:
            msg = "Entry attributes cannot be None"
            raise ValueError(msg)
        attrs_dict = entry.attributes.attributes
        validated: p.Ldif.ProcessingResult = m.Ldif.ProcessingResult.model_validate({
            "dn": dn_str,
            "attributes": attrs_dict,
        })
        return validated

    def process_entries(
        self,
        entries: t.MutableSequenceOf[p.Ldif.Entry],
        options: p.Ldif.ProcessEntriesOptions | None = None,
        **kwargs: t.JsonValue,
    ) -> p.Result[t.MutableSequenceOf[p.Ldif.ProcessingResult]]:
        """Unified processing method supporting batch and parallel modes."""
        payload: t.MutableJsonMapping = (
            options.model_dump(mode="python") if options is not None else {}
        )
        payload.update(kwargs)
        validated_options = m.Ldif.ProcessEntriesOptions.model_validate(payload)
        if validated_options.parallel:
            max_workers_actual = min(len(entries), validated_options.max_workers)
            with ThreadPoolExecutor(max_workers=max_workers_actual) as executor:
                futures = [
                    executor.submit(self._process_entry, entry) for entry in entries
                ]
                results = [future.result() for future in as_completed(futures)]
            return r[t.MutableSequenceOf[p.Ldif.ProcessingResult]].ok(results)
        _ = validated_options.batch_size
        return (
            r[t.MutableSequenceOf[p.Ldif.ProcessingResult]]
            .from_result(
                u.process(entries, self._process_entry, on_error="collect"),
            )
            .map_error(
                lambda error: error or "Batch processing failed",
            )
            .map(list)
        )


__all__: list[str] = ["FlextLdifProcessing"]
