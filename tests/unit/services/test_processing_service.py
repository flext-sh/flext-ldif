"""Behavioral tests for public LDIF processing service APIs."""

from __future__ import annotations

from typing import Literal

import pytest
from flext_tests import tm

from tests import c, m, p, t
from tests.utilities import TestsFlextLdifUtilities as u


class TestsFlextLdifProcessingService:
    """Cover batch/parallel processing through the public facade only."""

    @staticmethod
    def _entry(dn: str) -> m.Ldif.Entry:
        return u.Tests.create_real_entry(
            dn=dn,
            attributes=c.Tests.PROCESSING_ATTRS,
            server_type=c.Tests.RFC,
        )

    @pytest.mark.parametrize(
        ("processor_name", "parallel", "batch_size", "max_workers"),
        list(c.Tests.PROCESSING_OPTIONS_CASES.values()),
        ids=list(c.Tests.PROCESSING_OPTIONS_CASES.keys()),
    )
    def test_process_entries_returns_results_for_configured_modes(
        self,
        api: p.Ldif.LdifClient,
        processor_name: Literal["transform", "validate"],
        parallel: bool,
        batch_size: int,
        max_workers: int,
    ) -> None:
        entries = [self._entry(dn) for dn in c.Tests.PROCESSING_VALID_DNS]
        options = m.Ldif.ProcessEntriesOptions(
            processor_name=processor_name,
            parallel=parallel,
            batch_size=batch_size,
            max_workers=max_workers,
        )

        result = api.process_entries(entries, options=options)
        processed: t.MutableSequenceOf[m.Ldif.ProcessingResult] = (
            u.Tests.assert_success(result)
        )
        tm.that(len(processed), eq=len(entries))
        processed_dns = {item.dn for item in processed}
        tm.that(processed_dns == set(c.Tests.PROCESSING_VALID_DNS), eq=True)

    def test_process_entries_supports_kwargs_option_payload(
        self, api: p.Ldif.LdifClient
    ) -> None:
        entries = [self._entry(c.Tests.PROCESSING_VALID_DNS[0])]

        result = api.process_entries(
            entries,
            processor_name="transform",
            parallel=False,
            batch_size=1,
            max_workers=1,
        )
        processed: t.MutableSequenceOf[m.Ldif.ProcessingResult] = (
            u.Tests.assert_success(result)
        )
        tm.that(len(processed), eq=1)
        tm.that(processed[0].dn, eq=c.Tests.PROCESSING_VALID_DNS[0])

    def test_process_entries_batch_returns_failure_for_none_attributes(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        invalid_entry = m.Ldif.Entry(
            dn=c.Tests.PROCESSING_VALID_DNS[0],
            attributes=None,
        )

        result = api.process_entries(
            [invalid_entry],
            processor_name="transform",
            parallel=False,
            batch_size=1,
            max_workers=1,
        )
        tm.that(result.failure, eq=True)

    def test_process_entries_parallel_raises_for_none_dn(
        self,
        api: p.Ldif.LdifClient,
    ) -> None:
        invalid_entry = m.Ldif.Entry(
            dn=None,
            attributes=m.Ldif.Attributes(attributes={"cn": ["x"]}),
        )

        with pytest.raises(ValueError, match="Entry DN cannot be None"):
            _ = api.process_entries(
                [invalid_entry],
                processor_name="validate",
                parallel=True,
                batch_size=1,
                max_workers=1,
            )
